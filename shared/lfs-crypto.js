/*
 * LFS crypto core — shared by the server, the CLI and the browser.
 *
 *   - Ed25519 signatures (tweetnacl) over a domain-separated, canonical-JSON message
 *   - SHA-256 (js-sha256, incremental so large files can be hashed in chunks)
 *   - Identity files: secret key encrypted with PBKDF2-HMAC-SHA256 + XSalsa20-Poly1305
 *
 * Pure JS on purpose: WebCrypto is unavailable on plain-HTTP LAN origins (non-secure
 * context), and this must work at http://192.168.x.x too.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('tweetnacl'), require('js-sha256').sha256);
  } else {
    root.LFS = factory(root.nacl, root.sha256);
  }
})(typeof self !== 'undefined' ? self : this, function (nacl, sha256) {
  'use strict';

  const DOMAIN = 'LFS-v1';
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // ---------- encoding ----------
  function toB64(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    }
    return btoa(s);
  }
  function fromB64(str) {
    const s = atob(str);
    const u8 = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
    return u8;
  }
  function toHex(u8) {
    let h = '';
    for (let i = 0; i < u8.length; i++) h += u8[i].toString(16).padStart(2, '0');
    return h;
  }
  function randomHex(n) {
    return toHex(nacl.randomBytes(n));
  }

  // Deterministic JSON: object keys sorted recursively, undefined dropped.
  function canonical(v) {
    if (v === null || typeof v !== 'object') {
      if (typeof v === 'number' && !Number.isFinite(v)) throw new Error('non-finite number');
      return JSON.stringify(v);
    }
    if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
    return '{' + Object.keys(v).filter((k) => v[k] !== undefined).sort()
      .map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  }

  // ---------- signatures ----------
  // The purpose string is part of the signed bytes, so a signature made for one
  // action ("grant", "download", ...) can never be replayed as another.
  function message(purpose, obj) {
    return enc.encode(DOMAIN + '\n' + purpose + '\n' + canonical(obj));
  }
  function sign(secretKey, purpose, obj) {
    return toB64(nacl.sign.detached(message(purpose, obj), secretKey));
  }
  function verify(publicKeyB64, purpose, obj, sigB64) {
    try {
      const pk = fromB64(publicKeyB64);
      const sig = fromB64(sigB64);
      if (pk.length !== 32 || sig.length !== 64) return false;
      return nacl.sign.detached.verify(message(purpose, obj), sig, pk);
    } catch (_) {
      return false;
    }
  }
  function generateKeyPair() {
    const kp = nacl.sign.keyPair();
    return { publicKey: toB64(kp.publicKey), secretKey: kp.secretKey };
  }
  function keyPairFromSecret(secretKey) {
    const kp = nacl.sign.keyPair.fromSecretKey(secretKey);
    return { publicKey: toB64(kp.publicKey), secretKey: kp.secretKey };
  }

  // Human-comparable fingerprint of a public key: SHA-256, first 16 bytes, grouped.
  function fingerprint(publicKeyB64) {
    const h = sha256(fromB64(publicKeyB64)).slice(0, 32).toUpperCase();
    return h.match(/.{4}/g).join(':');
  }
  function hashObject(obj) {
    return sha256(enc.encode(canonical(obj)));
  }

  // ---------- share codes ----------
  // 16 chars of Crockford base32 (80 bits) shown as XXXX-XXXX-XXXX-XXXX.
  const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  function newCode() {
    const bytes = nacl.randomBytes(10);
    let bits = 0, value = 0, out = '';
    for (let i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) {
        out += B32[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    return out.match(/.{4}/g).join('-');
  }
  function normalizeCode(s) {
    const c = String(s || '').toUpperCase().replace(/[^0-9A-Z]/g, '')
      .replace(/O/g, '0').replace(/[IL]/g, '1');
    if (c.length !== 16 || /[^0-9A-HJKMNP-TV-Z]/.test(c)) return null;
    return c.match(/.{4}/g).join('-');
  }

  // ---------- passphrase-protected identity ----------
  function pbkdf2(password, salt, iterations) {
    // One 32-byte block of PBKDF2-HMAC-SHA256 (RFC 8018).
    const block = new Uint8Array(salt.length + 4);
    block.set(salt);
    block.set([0, 0, 0, 1], salt.length);
    let u = new Uint8Array(sha256.hmac.arrayBuffer(password, block));
    const t = u.slice();
    for (let i = 1; i < iterations; i++) {
      u = new Uint8Array(sha256.hmac.arrayBuffer(password, u));
      for (let j = 0; j < 32; j++) t[j] ^= u[j];
    }
    return t;
  }
  const KDF_ITER = 60000;
  function encryptSecret(secretKey, passphrase) {
    const salt = nacl.randomBytes(16);
    const nonce = nacl.randomBytes(24);
    const key = pbkdf2(enc.encode(passphrase), salt, KDF_ITER);
    return {
      kdf: 'pbkdf2-sha256', iter: KDF_ITER, salt: toB64(salt), nonce: toB64(nonce),
      box: toB64(nacl.secretbox(secretKey, nonce, key)),
    };
  }
  function decryptSecret(blob, passphrase) {
    if (!blob || blob.kdf !== 'pbkdf2-sha256') throw new Error('Unsupported key format');
    const key = pbkdf2(enc.encode(passphrase), fromB64(blob.salt), blob.iter);
    const sk = nacl.secretbox.open(fromB64(blob.box), fromB64(blob.nonce), key);
    if (!sk) throw new Error('Wrong passphrase');
    return sk;
  }
  function createIdentityFile(username, passphrase) {
    const kp = generateKeyPair();
    return {
      file: {
        type: 'lfs-identity', v: 1, username, publicKey: kp.publicKey,
        createdAt: new Date().toISOString(),
        secretKey: encryptSecret(kp.secretKey, passphrase),
      },
      secretKey: kp.secretKey,
    };
  }
  function unlockIdentityFile(file, passphrase) {
    if (!file || file.type !== 'lfs-identity') throw new Error('Not an LFS identity file');
    const sk = decryptSecret(file.secretKey, passphrase);
    if (keyPairFromSecret(sk).publicKey !== file.publicKey) throw new Error('Identity file is corrupted');
    return sk;
  }

  return {
    DOMAIN, enc, dec, toB64, fromB64, toHex, randomHex, canonical, message,
    sign, verify, generateKeyPair, keyPairFromSecret, fingerprint, hashObject,
    newCode, normalizeCode, sha256, pbkdf2, encryptSecret, decryptSecret,
    createIdentityFile, unlockIdentityFile, nacl,
  };
});

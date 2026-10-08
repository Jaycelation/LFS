#!/usr/bin/env node
'use strict';
/*
 * LFS command-line client. Profile (identity + pinned server + session) lives in
 * ~/.lfs, or in the directory given by LFS_HOME / --home.
 * The passphrase is read from LFS_PASSPHRASE or prompted.
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');
const https = require('https');
const readline = require('readline');
const LFS = require('../shared/lfs-crypto');

// ---------- args ----------
const argv = process.argv.slice(2);
const opts = {};
const pos = [];
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a.startsWith('--')) {
    const k = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) opts[k] = true;
    else { opts[k] = next; i++; }
  } else if (a === '-o') {
    opts.out = argv[++i];
  } else pos.push(a);
}

const HOME = path.resolve(opts.home || process.env.LFS_HOME || path.join(os.homedir(), '.lfs'));
const ID_FILE = path.join(HOME, 'identity.json');
const PROFILE_FILE = path.join(HOME, 'profile.json');

const readJson = (p, def) => (fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : def);
const writeJson = (p, v) => {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(v, null, 2), { mode: 0o600 });
};
let profile = readJson(PROFILE_FILE, {});
const saveProfile = () => writeJson(PROFILE_FILE, profile);

function die(msg) {
  console.error('✖ ' + msg);
  process.exit(1);
}
const ok = (msg) => console.log('✔ ' + msg);

function fmtBytes(n) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + ' ' + u[i];
}

// ---------- passphrase / identity ----------
function prompt(question, hidden) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (hidden) {
      rl._writeToOutput = (s) => {
        if (s.includes(question)) rl.output.write(s);
      };
    }
    rl.question(question, (ans) => {
      rl.close();
      if (hidden) process.stdout.write('\n');
      resolve(ans);
    });
  });
}
async function passphrase(confirm) {
  if (process.env.LFS_PASSPHRASE) return process.env.LFS_PASSPHRASE;
  const p = await prompt('Passphrase: ', true);
  if (confirm && (await prompt('Repeat passphrase: ', true)) !== p) die('Passphrases do not match');
  return p;
}
function identity() {
  const id = readJson(ID_FILE, null);
  if (!id) die(`No identity. Run: lfs init <username>  (profile dir: ${HOME})`);
  return id;
}
let cachedSk = null;
async function secretKey() {
  if (cachedSk) return cachedSk;
  try {
    cachedSk = LFS.unlockIdentityFile(identity(), await passphrase(false));
  } catch (e) {
    die(e.message);
  }
  return cachedSk;
}
const fresh = () => ({ nonce: LFS.randomHex(16), ts: Date.now() });

// ---------- HTTP ----------
function serverUrl() {
  if (!profile.server) die('No server set. Run: lfs server <url>');
  return profile.server;
}
function transport(url) {
  return url.protocol === 'https:' ? https : http;
}
function rawRequest(method, urlPath, { headers = {}, body, stream, onResponse } = {}) {
  const url = new URL(urlPath, serverUrl());
  return new Promise((resolve, reject) => {
    const req = transport(url).request(url, {
      method, headers,
      rejectUnauthorized: !profile.tlsInsecure,
    }, (res) => {
      if (onResponse && res.statusCode === 200) return onResponse(res, resolve, reject);
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch (_) { /* not JSON */ }
        if (res.statusCode >= 400) {
          return reject(new Error(json?.message || json?.error || `HTTP ${res.statusCode}: ${text.slice(0, 200)}`));
        }
        resolve(json);
      });
    });
    req.on('error', reject);
    if (stream) stream.pipe(req);
    else req.end(body);
  });
}
async function api(method, urlPath, payload, { authed = true } = {}) {
  const headers = { Accept: 'application/json' };
  if (authed) {
    if (!profile.token || profile.tokenExpires < Date.now()) die('Not logged in. Run: lfs login');
    headers.Authorization = 'Bearer ' + profile.token;
  }
  let body;
  if (payload !== undefined) {
    body = JSON.stringify(payload);
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = Buffer.byteLength(body);
  }
  try {
    return await rawRequest(method, urlPath, { headers, body });
  } catch (e) {
    die(e.message);
  }
}

// ---------- commands ----------
const commands = {};

commands.init = async () => {
  const username = (pos[1] || '').toLowerCase();
  if (!/^[a-z0-9_.-]{3,32}$/.test(username)) die('Usage: lfs init <username>  (3-32 chars a-z 0-9 _ . -)');
  if (fs.existsSync(ID_FILE) && !opts.force) die(`Identity already exists at ${ID_FILE} (use --force to overwrite)`);
  const { file } = LFS.createIdentityFile(username, await passphrase(true));
  writeJson(ID_FILE, file);
  ok(`Identity "${username}" created → ${ID_FILE}`);
  console.log('  Public key fingerprint: ' + LFS.fingerprint(file.publicKey));
  console.log('  Back this file up — losing it means losing this identity.');
};

commands.import = async () => {
  const src = pos[1] || die('Usage: lfs import <identity.json>');
  const file = readJson(path.resolve(src), null);
  LFS.unlockIdentityFile(file, await passphrase(false));
  writeJson(ID_FILE, file);
  ok(`Imported identity "${file.username}"`);
};

commands.server = async () => {
  const url = pos[1] || die('Usage: lfs server <http(s)://host:port> [--insecure-tls]');
  profile = { server: new URL(url).origin, tlsInsecure: !!opts['insecure-tls'] };
  const info = await api('GET', '/api/info', undefined, { authed: false });
  if (opts.fingerprint && opts.fingerprint.toUpperCase() !== info.fingerprint) {
    die(`Server fingerprint mismatch!\n  expected ${opts.fingerprint}\n  got      ${info.fingerprint}`);
  }
  profile.serverPublicKey = info.serverPublicKey;
  saveProfile();
  ok(`Server "${info.name}" (${info.networkMode}) pinned`);
  console.log('  Fingerprint: ' + info.fingerprint + (opts.fingerprint ? '  (matches)' : '  ← verify this with the server console'));
};

commands.register = async () => {
  const id = identity();
  const sk = await secretKey();
  const obj = { username: id.username, publicKey: id.publicKey, server: profile.serverPublicKey };
  if (!profile.serverPublicKey) die('Run lfs server <url> first');
  const r = await api('POST', '/api/register', { ...obj, signature: LFS.sign(sk, 'register', obj) }, { authed: false });
  ok(`Registered "${r.user.username}" as ${r.user.role} (${r.user.status})`);
};

commands.login = async () => {
  const id = identity();
  const sk = await secretKey();
  const clientNonce = LFS.randomHex(32);
  const c = await api('POST', '/api/auth/challenge', { username: id.username, clientNonce }, { authed: false });
  // 2-way: the server must prove it holds the pinned key by signing our nonce.
  if (!opts['one-way']) {
    if (c.serverPublicKey !== profile.serverPublicKey) die('Server key changed since it was pinned — possible MITM!');
    const sObj = { challengeId: c.challengeId, username: id.username, clientNonce, serverNonce: c.serverNonce };
    if (!LFS.verify(profile.serverPublicKey, 'auth-server', sObj, c.serverSignature)) {
      die('Server signature invalid — possible MITM!');
    }
  }
  const obj = {
    challengeId: c.challengeId, username: id.username, clientNonce,
    serverNonce: c.serverNonce, server: profile.serverPublicKey,
  };
  const r = await api('POST', '/api/auth/verify', { challengeId: c.challengeId, signature: LFS.sign(sk, 'auth-client', obj) }, { authed: false });
  profile.token = r.token;
  profile.tokenExpires = r.expiresAt;
  profile.username = id.username;
  saveProfile();
  ok(`Logged in as ${r.user.username} (${r.user.role}) — ${opts['one-way'] ? '1-way' : '2-way (mutual)'} auth`);
};

commands.logout = async () => {
  await api('POST', '/api/auth/logout', {});
  delete profile.token;
  saveProfile();
  ok('Logged out');
};

commands.whoami = async () => {
  const r = await api('GET', '/api/me');
  console.log(`${r.user.username}  role=${r.user.role}  fp=${r.user.fingerprint}`);
};

commands.users = async () => {
  const r = await api('GET', '/api/users');
  for (const u of r.users) console.log(`${u.username.padEnd(20)} ${u.role.padEnd(6)} ${u.status.padEnd(9)} ${u.fingerprint}`);
};

commands.ls = async () => {
  const r = await api('GET', '/api/files');
  if (!r.files.length) return console.log('(no files)');
  for (const f of r.files) {
    const access = !f.protected ? 'public' : f.canDownloadDirectly ? 'member' : f.myGrants.some((g) => g.status === 'active') ? 'key' : '-';
    console.log(`${f.id}  ${fmtBytes(f.size).padStart(9)}  ${f.owner.padEnd(12)} policy ${f.policy.threshold}-of-${f.policy.approvers.length}  access:${access.padEnd(6)} ${f.name}`);
  }
};

function hashFile(p) {
  return new Promise((resolve, reject) => {
    const h = LFS.sha256.create();
    fs.createReadStream(p).on('data', (c) => h.update(c)).on('end', () => resolve(h.hex())).on('error', reject);
  });
}

commands.upload = async () => {
  const file = pos[1] || die('Usage: lfs upload <path> [--key CODE] [--approvers a,b] [--threshold N] [--hidden]');
  const st = fs.statSync(file);
  const sk = await secretKey();
  process.stdout.write('Hashing… ');
  const sha256 = await hashFile(file);
  console.log(sha256);
  const meta = {
    name: path.basename(file), size: st.size, sha256, mime: 'application/octet-stream',
    grantId: opts.key ? LFS.normalizeCode(opts.key) : null,
    approvers: opts.approvers ? String(opts.approvers).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean) : [],
    threshold: Number(opts.threshold || 1), visibility: opts.hidden ? 'hidden' : 'listed',
    protected: !opts.public,
    uploader: profile.username, ...fresh(),
  };
  const headers = {
    Authorization: 'Bearer ' + profile.token,
    'Content-Type': 'application/octet-stream',
    'Content-Length': st.size,
    'X-LFS-Meta': Buffer.from(JSON.stringify(meta)).toString('base64'),
    'X-LFS-Signature': LFS.sign(sk, 'upload', meta),
  };
  try {
    const r = await rawRequest('PUT', '/api/files', { headers, stream: fs.createReadStream(file) });
    ok(`Uploaded ${r.file.name} → id ${r.file.id}`);
    if (r.file.publicUrl) console.log(`  Public link: ${new URL(r.file.publicUrl, serverUrl()).href}`);
  } catch (e) {
    die(e.message);
  }
};

commands.download = async () => {
  const fileId = pos[1] || die('Usage: lfs download <fileId> [--key CODE] [-o path]');
  const sk = await secretKey();
  const { file: f } = await api('GET', '/api/files/' + fileId);
  let grantId = opts.key ? LFS.normalizeCode(opts.key) : null;
  if (!grantId && !f.canDownloadDirectly) grantId = f.myGrants[0]?.id || null;
  const req = { fileId, grantId, username: profile.username, ...fresh() };
  const t = await api('POST', `/api/files/${fileId}/download-token`, { ...req, signature: LFS.sign(sk, 'download', req) });
  const out = path.resolve(opts.out || f.name);
  const h = LFS.sha256.create();
  try {
    await rawRequest('GET', t.url, {
      onResponse: (res, resolve, reject) => {
        const ws = fs.createWriteStream(out);
        res.on('data', (c) => h.update(c));
        res.pipe(ws);
        ws.on('finish', resolve);
        ws.on('error', reject);
      },
    });
  } catch (e) {
    die(e.message);
  }
  const digest = h.hex();
  const sigOk = LFS.verify(f.ownerPublicKey, 'upload', f.uploadMeta, f.uploadSignature)
    && f.uploadMeta.sha256 === digest;
  if (digest !== f.sha256 || !sigOk) {
    fs.rmSync(out, { force: true });
    die('Integrity check FAILED — file discarded');
  }
  ok(`Saved ${out}`);
  console.log(`  SHA-256 ${digest} — matches the signature of uploader "${f.owner}"`);
};

commands.access = async () => {
  const [, fileId, mode] = pos;
  if (!fileId || !['public', 'protected'].includes(mode)) die('Usage: lfs access <fileId> public|protected');
  const sk = await secretKey();
  const obj = { fileId, protected: mode === 'protected', by: profile.username, ...fresh() };
  const r = await api('POST', `/api/files/${fileId}/access`,
    { protected: obj.protected, nonce: obj.nonce, ts: obj.ts, signature: LFS.sign(sk, 'file-access', obj) });
  ok(`${r.file.name} is now ${mode}`);
  if (r.file.publicUrl) console.log(`  Public link: ${new URL(r.file.publicUrl, serverUrl()).href}`);
};

commands.rm = async () => {
  const fileId = pos[1] || die('Usage: lfs rm <fileId>');
  const sk = await secretKey();
  const obj = { fileId, by: profile.username, ...fresh() };
  await api('POST', `/api/files/${fileId}/delete`, { nonce: obj.nonce, ts: obj.ts, signature: LFS.sign(sk, 'file-delete', obj) });
  ok('Deleted');
};

commands.grant = async () => {
  const action = pos[1];
  if (!['download', 'upload'].includes(action)) {
    die('Usage:\n  lfs grant download <fileId> --to <user|*> [--uses N] [--hours H] [--note text]\n  lfs grant upload --to <user> [--uses N] [--max-mb M] [--hours H]');
  }
  const sk = await secretKey();
  let fileId = null, fileSha256 = null;
  if (action === 'download') {
    fileId = pos[2] || die('Missing fileId');
    fileSha256 = (await api('GET', '/api/files/' + fileId)).file.sha256;
  }
  const payload = {
    id: LFS.newCode(), action, fileId, fileSha256,
    grantee: String(opts.to || die('--to <user|*> is required')).toLowerCase(),
    maxUses: Number(opts.uses || 1),
    maxBytes: action === 'upload' ? Math.round(Number(opts['max-mb'] || 100) * 1024 * 1024) : null,
    expiresAt: Date.now() + Number(opts.hours || 24) * 3600_000,
    issuedBy: profile.username, issuedAt: Date.now(), nonce: LFS.randomHex(16),
  };
  if (typeof opts.note === 'string') payload.note = opts.note;
  const r = await api('POST', '/api/grants', { payload, signature: LFS.sign(sk, 'grant', payload) });
  ok(`${action === 'upload' ? 'Upload' : 'Download'} Key created`);
  console.log(`\n    ${r.grant.id}\n`);
  console.log(`  Signatures: ${r.grant.approvers.filter((a) => a.signature).length}/${r.grant.threshold}   status: ${r.grant.status}`);
  console.log(`  Send this code to ${payload.grantee === '*' ? 'the recipient' : payload.grantee}; they run: lfs accept ${r.grant.id}`);
};

function verifyGrantSignatures(g) {
  const res = g.approvers.map((a) => ({
    ...a, valid: a.signature ? LFS.verify(a.publicKey, 'grant', g.payload, a.signature) : null,
  }));
  let accValid = null;
  if (g.acceptance) {
    accValid = LFS.verify(g.acceptance.publicKey, 'grant-accept',
      { grantId: g.id, payloadHash: LFS.hashObject(g.payload), grantee: g.acceptance.username }, g.acceptance.signature);
  }
  return { approvers: res, accValid };
}

function printGrant(g) {
  const p = g.payload;
  const v = verifyGrantSignatures(g);
  console.log(`Key ${g.id}  [${g.status}]`);
  console.log(`  action    ${p.action}${g.file ? `  file "${g.file.name}" (${g.file.id})` : `  ≤ ${fmtBytes(p.maxBytes)} per file`}`);
  console.log(`  grantee   ${g.grantee}    uses left ${g.usesLeft}/${p.maxUses}    expires ${new Date(p.expiresAt).toLocaleString()}`);
  if (p.note) console.log(`  note      ${p.note}`);
  console.log(`  approvals ${v.approvers.filter((a) => a.valid).length}/${g.threshold} required:`);
  for (const a of v.approvers) {
    console.log(`    ${a.valid === null ? '·' : a.valid ? '✔' : '✖ INVALID'} ${a.username}`);
  }
  console.log(`  recipient ${g.acceptance ? `${v.accValid ? '✔' : '✖ INVALID'} signed by ${g.acceptance.username}` : '· not signed yet'}`);
}

commands.key = async () => {
  const code = LFS.normalizeCode(pos[1]) || die('Usage: lfs key <CODE>');
  printGrant((await api('GET', '/api/grants/' + code)).grant);
};

commands.keys = async () => {
  const r = await api('GET', '/api/grants');
  if (!r.grants.length) return console.log('(no keys)');
  for (const g of r.grants) {
    const sigs = g.approvers.filter((a) => a.signature).length;
    console.log(`${g.id}  ${g.payload.action.padEnd(8)} ${(g.file?.name || '-').slice(0, 24).padEnd(24)} → ${g.grantee.padEnd(12)} ${sigs}/${g.threshold}  ${g.status}`);
  }
};

commands.approve = async () => {
  const code = LFS.normalizeCode(pos[1]) || die('Usage: lfs approve <CODE>');
  const sk = await secretKey();
  const { grant: g } = await api('GET', '/api/grants/' + code);
  printGrant(g);
  const r = await api('POST', `/api/grants/${code}/approve`, { signature: LFS.sign(sk, 'grant', g.payload) });
  ok(`Co-signed. Status: ${r.grant.status}`);
};

commands.accept = async () => {
  const code = LFS.normalizeCode(pos[1]) || die('Usage: lfs accept <CODE>');
  const sk = await secretKey();
  const { grant: g } = await api('GET', '/api/grants/' + code);
  const v = verifyGrantSignatures(g);
  if (v.approvers.some((a) => a.valid === false)) die('Key carries an invalid approver signature — refusing');
  printGrant(g);
  const obj = { grantId: g.id, payloadHash: LFS.hashObject(g.payload), grantee: profile.username };
  const r = await api('POST', `/api/grants/${code}/accept`, { signature: LFS.sign(sk, 'grant-accept', obj) });
  ok(`Signed as recipient. Status: ${r.grant.status}`);
  if (r.grant.status === 'active' && g.file) console.log(`  Download with: lfs download ${g.file.id}`);
};

commands.revoke = async () => {
  const code = LFS.normalizeCode(pos[1]) || die('Usage: lfs revoke <CODE>');
  const sk = await secretKey();
  const obj = { grantId: code, by: profile.username, ...fresh() };
  await api('POST', `/api/grants/${code}/revoke`, { nonce: obj.nonce, ts: obj.ts, signature: LFS.sign(sk, 'grant-revoke', obj) });
  ok('Revoked');
};

commands.admin = async () => {
  const [, target, field, value] = pos;
  if (!target || !['status', 'role'].includes(field)) die('Usage: lfs admin <user> status active|disabled  |  lfs admin <user> role admin|user');
  const sk = await secretKey();
  const obj = { username: target, [field]: value, by: profile.username, ...fresh() };
  const r = await api('POST', '/api/admin/users/' + target, { [field]: value, nonce: obj.nonce, ts: obj.ts, signature: LFS.sign(sk, 'admin-user', obj) });
  ok(`${r.user.username}: role=${r.user.role} status=${r.user.status}`);
};

commands.audit = async () => {
  const r = await api('GET', '/api/admin/audit?limit=' + (opts.limit || 50));
  for (const e of r.events) {
    console.log(`${new Date(e.ts).toLocaleString()}  ${String(e.actor).padEnd(12)} ${e.action.padEnd(20)} ${e.detail ? JSON.stringify(e.detail) : ''}  ${e.ip || ''}`);
  }
};

commands.help = async () => {
  console.log(`LFS client — profile: ${HOME}

  Identity & auth
    lfs init <username>                 create an Ed25519 identity (passphrase-protected)
    lfs import <identity.json>          import an identity exported from the web UI
    lfs server <url> [--fingerprint FP] [--insecure-tls]   pin a server
    lfs register | login [--one-way] | logout | whoami | users

  Files
    lfs ls
    lfs upload <path> [--key CODE] [--approvers a,b] [--threshold N] [--hidden] [--public]
    lfs access <fileId> public|protected   download auth on/off (owner)
    lfs download <fileId> [--key CODE] [-o path]
    lfs rm <fileId>

  Keys (grants)
    lfs grant download <fileId> --to <user|*> [--uses N] [--hours H] [--note text]
    lfs grant upload --to <user> [--uses N] [--max-mb M] [--hours H]       (admin)
    lfs key <CODE> | keys | approve <CODE> | accept <CODE> | revoke <CODE>

  Admin
    lfs admin <user> status active|disabled | role admin|user
    lfs audit [--limit N]

  Set LFS_PASSPHRASE to skip the passphrase prompt; LFS_HOME / --home for another profile.`);
};

(commands[pos[0]] || commands.help)().catch((e) => die(e.stack || e.message));

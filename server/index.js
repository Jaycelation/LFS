'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');
const https = require('https');
const express = require('express');
const LFS = require('../shared/lfs-crypto');
const { config, ROOT } = require('./config');
const { Store } = require('./store');

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const store = new Store(config);
const db = store; // db.users / db.files / db.grants

// Server identity: lets clients authenticate the server (2-way / mutual auth).
const serverKeyPath = path.join(config.keysDir, 'server.key');
let serverKey;
if (fs.existsSync(serverKeyPath)) {
  serverKey = LFS.keyPairFromSecret(LFS.fromB64(fs.readFileSync(serverKeyPath, 'utf8').trim()));
} else {
  serverKey = LFS.generateKeyPair();
  fs.writeFileSync(serverKeyPath, LFS.toB64(serverKey.secretKey) + '\n', { mode: 0o600 });
}
const SERVER_FP = LFS.fingerprint(serverKey.publicKey);

const sessions = new Map();        // token -> { username, expires }
const challenges = new Map();      // challengeId -> { username, clientNonce, serverNonce, expires }
const usedNonces = new Map();      // nonce -> expires (replay protection)
const downloadTokens = new Map();  // token -> { fileId, username, expires }
const rateBuckets = new Map();     // key -> { count, reset }

const FRESH_MS = 5 * 60 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const m of [sessions, challenges, downloadTokens]) {
    for (const [k, v] of m) if (v.expires < now) m.delete(k);
  }
  for (const [k, exp] of usedNonces) if (exp < now) usedNonces.delete(k);
  for (const [k, b] of rateBuckets) if (b.reset < now) rateBuckets.delete(k);
}, 60 * 1000).unref();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
class HttpError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}
const fail = (status, code, message) => { throw new HttpError(status, code, message); };
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function clientIp(req) {
  const ip = config.trustProxy ? req.ip : req.socket.remoteAddress;
  return String(ip || '').replace(/^::ffff:/, '');
}

function isPrivateIp(ip) {
  if (ip === '::1' || ip === '127.0.0.1' || ip.startsWith('127.')) return true;
  const m = ip.match(/^(\d+)\.(\d+)\.\d+\.\d+$/);
  if (m) {
    const a = +m[1], b = +m[2];
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
      || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127); // CGNAT / Tailscale
  }
  const l = ip.toLowerCase();
  return l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80');
}

function rateLimit(key, limit, windowMs) {
  const now = Date.now();
  let b = rateBuckets.get(key);
  if (!b || b.reset < now) rateBuckets.set(key, (b = { count: 0, reset: now + windowMs }));
  if (++b.count > limit) fail(429, 'rate_limited', 'Too many requests, slow down');
}

// Every signed action carries {nonce, ts}: must be recent and never seen before.
function checkFresh(nonce, ts) {
  if (typeof nonce !== 'string' || !/^[0-9a-f]{32,64}$/.test(nonce)) fail(400, 'bad_nonce');
  if (typeof ts !== 'number' || Math.abs(Date.now() - ts) > FRESH_MS) {
    fail(400, 'stale_request', 'Timestamp too old/new — check the device clock');
  }
  if (usedNonces.has(nonce)) fail(409, 'replay', 'This signed request was already used');
  usedNonces.set(nonce, Date.now() + 2 * FRESH_MS);
}

function requireSig(publicKey, purpose, obj, sig) {
  if (typeof sig !== 'string' || !LFS.verify(publicKey, purpose, obj, sig)) {
    fail(401, 'bad_signature', `Signature check failed (${purpose})`);
  }
}

const USERNAME_RE = /^[a-z0-9_.-]{3,32}$/;
const activeUser = (name) => {
  const u = db.users[name];
  return u && u.status === 'active' ? u : null;
};
const admins = () => Object.values(db.users).filter((u) => u.role === 'admin' && u.status === 'active');

function grantStatus(g) {
  if (g.revoked) return 'revoked';
  if (g.payload.expiresAt < Date.now()) return 'expired';
  if (g.usesLeft <= 0) return 'exhausted';
  if (g.payload.action === 'download' && !db.files[g.payload.fileId]) return 'revoked';
  if (Object.keys(g.approvals).length < g.threshold) return 'awaiting_approvals';
  if (!g.acceptance) return 'awaiting_acceptance';
  return 'active';
}

// Download auth is optional per file: protected (default) needs a key, public does not.
const isProtected = (f) => f.protected !== false;
const publicUrl = (f) => `/f/${f.id}/${encodeURIComponent(f.name)}`;

function canSeeFile(f, username) {
  if (f.visibility === 'listed') return true;
  if (f.owner === username || f.policy.approvers.includes(username)) return true;
  if (db.users[username]?.role === 'admin') return true;
  return Object.values(db.grants).some((g) => g.payload.fileId === f.id && g.grantee === username);
}

function userView(u) {
  return {
    username: u.username, publicKey: u.publicKey, fingerprint: LFS.fingerprint(u.publicKey),
    role: u.role, status: u.status, createdAt: u.createdAt,
  };
}

function fileView(f, viewer) {
  const isOwner = f.owner === viewer;
  const isApprover = f.policy.approvers.includes(viewer);
  return {
    id: f.id, name: f.name, size: f.size, mime: f.mime, sha256: f.sha256, owner: f.owner,
    uploadedAt: f.uploadedAt, visibility: f.visibility, policy: f.policy,
    protected: isProtected(f), publicUrl: isProtected(f) ? null : publicUrl(f),
    // Lets any client re-verify who uploaded exactly these bytes.
    uploadMeta: f.uploadMeta, uploadSignature: f.uploadSignature,
    ownerPublicKey: f.ownerPublicKey,
    canDownloadDirectly: isOwner || isApprover || !isProtected(f),
    canShare: isApprover,
    // Keys addressed to the viewer for this file, active ones first.
    myGrants: Object.values(db.grants)
      .filter((g) => g.payload.fileId === f.id && g.grantee === viewer)
      .map((g) => ({ id: g.id, status: grantStatus(g), usesLeft: g.usesLeft, expiresAt: g.payload.expiresAt }))
      .sort((a, b) => (b.status === 'active') - (a.status === 'active') || b.expiresAt - a.expiresAt),
  };
}

function grantView(g, viewer) {
  const f = g.payload.fileId ? db.files[g.payload.fileId] : null;
  const status = grantStatus(g);
  const isApprover = g.approvers.includes(viewer);
  const isGrantee = g.grantee === viewer || (g.grantee === '*' && !g.acceptance);
  return {
    id: g.id, payload: g.payload, payloadHash: LFS.hashObject(g.payload), status,
    threshold: g.threshold, usesLeft: g.usesLeft, createdAt: g.createdAt,
    grantee: g.grantee, revoked: g.revoked || null,
    approvers: g.approvers.map((name) => ({
      username: name, publicKey: db.users[name]?.publicKey, signature: g.approvals[name] || null,
    })),
    acceptance: g.acceptance
      ? { ...g.acceptance, publicKey: db.users[g.acceptance.username]?.publicKey }
      : null,
    file: f ? { id: f.id, name: f.name, size: f.size, sha256: f.sha256, owner: f.owner } : null,
    me: {
      isApprover, isGrantee,
      canApprove: isApprover && !g.approvals[viewer] && !['revoked', 'expired', 'exhausted'].includes(status),
      canAccept: isGrantee && !g.acceptance && !['revoked', 'expired', 'exhausted'].includes(status),
      canRevoke: (isApprover || g.grantee === viewer) && !g.revoked,
    },
  };
}

function cleanFileName(name) {
  const n = String(name || '').normalize('NFC')
    .replace(/[\u0000-\u001f\u007f<>:"/\\|?*]/g, '_').replace(/^[\s.]+|[\s.]+$/g, '').slice(0, 200);
  // Windows reserved device names
  return (/^(con|prn|aux|nul|com\d|lpt\d)(\.|$)/i.test(n) ? '_' + n : n) || 'file';
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
const app = express();
app.disable('x-powered-by');
if (config.trustProxy) app.set('trust proxy', true);

// Network mode guard.
app.use((req, res, next) => {
  if (config.networkMode === 'internal') {
    // A forwarding header means the request crossed a proxy/tunnel, i.e. it may
    // come from outside even though the socket peer is local.
    const proxied = req.headers['x-forwarded-for'] || req.headers.forwarded || req.headers['cf-connecting-ip'];
    if ((proxied && !config.trustProxy) || !isPrivateIp(clientIp(req))) {
      return res.status(403).json({ error: 'internal_only', message: 'This server only accepts LAN clients' });
    }
  }
  next();
});

app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  });
  next();
});

app.use(express.json({ limit: '64kb' }));

const send = (rel) => (req, res) => res.sendFile(path.join(ROOT, rel));
app.get('/vendor/nacl-fast.min.js', send('node_modules/tweetnacl/nacl-fast.min.js'));
app.get('/vendor/sha256.min.js', send('node_modules/js-sha256/build/sha256.min.js'));
app.get('/shared/lfs-crypto.js', send('shared/lfs-crypto.js'));
app.use(express.static(path.join(ROOT, 'public'), { index: 'index.html' }));

function auth(req, res, next) {
  const m = /^Bearer ([0-9a-f]{64})$/.exec(req.get('authorization') || '');
  const s = m && sessions.get(m[1]);
  if (!s || s.expires < Date.now()) return next(new HttpError(401, 'unauthenticated', 'Please log in'));
  const u = activeUser(s.username);
  if (!u) return next(new HttpError(403, 'account_inactive'));
  req.user = u;
  req.token = m[1];
  next();
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return next(new HttpError(403, 'admin_only'));
  next();
}

// ----- info -----------------------------------------------------------------
app.get('/api/info', (req, res) => {
  res.json({
    name: config.serverName, version: 1,
    serverPublicKey: serverKey.publicKey, fingerprint: SERVER_FP,
    networkMode: config.networkMode, openRegistration: config.openRegistration,
    defaultProtected: config.defaultProtected,
    hasAdmin: admins().length > 0, maxUploadBytes: config.maxUploadBytes,
    uploadKeyThreshold: config.uploadKeyThreshold, maxGrantDays: config.maxGrantDays,
    time: Date.now(),
  });
});

// ----- registration ---------------------------------------------------------
app.post('/api/register', wrap(async (req, res) => {
  rateLimit('reg:' + clientIp(req), 10, 60_000);
  const { username, publicKey, signature } = req.body || {};
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) {
    fail(400, 'bad_username', 'Username: 3-32 chars, a-z 0-9 _ . -');
  }
  if (typeof publicKey !== 'string' || LFS.fromB64(publicKey).length !== 32) fail(400, 'bad_public_key');
  if (db.users[username]) fail(409, 'username_taken', 'Username already registered');
  if (Object.values(db.users).some((u) => u.publicKey === publicKey)) fail(409, 'key_taken', 'Key already registered');
  // Proof of possession, bound to this server.
  requireSig(publicKey, 'register', { username, publicKey, server: serverKey.publicKey }, signature);

  const first = Object.keys(db.users).length === 0;
  const u = {
    username, publicKey, role: first ? 'admin' : 'user',
    status: first || config.openRegistration ? 'active' : 'pending',
    createdAt: Date.now(),
  };
  db.users[username] = u;
  store.saveUsers();
  store.audit(username, 'register', { role: u.role, status: u.status }, clientIp(req));
  res.json({ user: userView(u) });
}));

// ----- challenge–response login (1-way, or 2-way when the client checks serverSignature)
app.post('/api/auth/challenge', wrap(async (req, res) => {
  rateLimit('auth:' + clientIp(req), 30, 60_000);
  const { username, clientNonce } = req.body || {};
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) fail(400, 'bad_username');
  if (typeof clientNonce !== 'string' || !/^[0-9a-f]{32,64}$/.test(clientNonce)) fail(400, 'bad_nonce');
  const challengeId = LFS.randomHex(16);
  const serverNonce = LFS.randomHex(32);
  challenges.set(challengeId, { username, clientNonce, serverNonce, expires: Date.now() + 60_000 });
  // Server proves its identity by signing the client's fresh nonce.
  const serverSignature = LFS.sign(serverKey.secretKey, 'auth-server',
    { challengeId, username, clientNonce, serverNonce });
  res.json({ challengeId, serverNonce, serverPublicKey: serverKey.publicKey, serverSignature });
}));

app.post('/api/auth/verify', wrap(async (req, res) => {
  rateLimit('auth:' + clientIp(req), 30, 60_000);
  const { challengeId, signature } = req.body || {};
  const c = challenges.get(challengeId);
  challenges.delete(challengeId); // single use, success or not
  if (!c || c.expires < Date.now()) fail(401, 'challenge_expired', 'Challenge expired, try again');
  const u = db.users[c.username];
  const obj = {
    challengeId, username: c.username, clientNonce: c.clientNonce,
    serverNonce: c.serverNonce, server: serverKey.publicKey,
  };
  if (!u || !LFS.verify(u.publicKey, 'auth-client', obj, signature)) {
    store.audit(c.username, 'login_failed', null, clientIp(req));
    fail(401, 'bad_signature', 'Authentication failed');
  }
  if (u.status === 'pending') fail(403, 'account_pending', 'Account awaiting admin approval');
  if (u.status !== 'active') fail(403, 'account_disabled', 'Account disabled');
  const token = LFS.randomHex(32);
  const expires = Date.now() + config.sessionTtlMs;
  sessions.set(token, { username: u.username, expires });
  store.audit(u.username, 'login', null, clientIp(req));
  res.json({ token, expiresAt: expires, user: userView(u) });
}));

app.post('/api/auth/logout', auth, (req, res) => {
  sessions.delete(req.token);
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => res.json({ user: userView(req.user) }));

app.get('/api/users', auth, (req, res) => {
  const list = Object.values(db.users)
    .filter((u) => u.status === 'active' || req.user.role === 'admin')
    .map(userView);
  res.json({ users: list });
});

// ----- files ---------------------------------------------------------------
app.get('/api/files', auth, (req, res) => {
  const files = Object.values(db.files)
    .filter((f) => canSeeFile(f, req.user.username))
    .sort((a, b) => b.uploadedAt - a.uploadedAt)
    .map((f) => fileView(f, req.user.username));
  res.json({ files });
});

app.get('/api/files/:id', auth, (req, res) => {
  const f = db.files[req.params.id];
  if (!f || !canSeeFile(f, req.user.username)) fail(404, 'not_found');
  res.json({ file: fileView(f, req.user.username) });
});

// Upload (*): raw body stream. Metadata + uploader signature travel in headers.
app.put('/api/files', auth, wrap(async (req, res) => {
  const user = req.user;
  let meta;
  try {
    meta = JSON.parse(Buffer.from(req.get('x-lfs-meta') || '', 'base64').toString('utf8'));
  } catch (_) {
    fail(400, 'bad_meta');
  }
  const signature = req.get('x-lfs-signature');
  const {
    name, size, sha256, mime, grantId, approvers, threshold, visibility, nonce, ts, uploader,
    protected: needsKey = true,
  } = meta || {};
  if (typeof needsKey !== 'boolean') fail(400, 'bad_meta', 'protected');
  if (uploader !== user.username) fail(400, 'bad_meta', 'uploader mismatch');
  if (typeof name !== 'string' || !name) fail(400, 'bad_meta', 'name');
  if (!Number.isSafeInteger(size) || size < 0) fail(400, 'bad_meta', 'size');
  if (typeof sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(sha256)) fail(400, 'bad_meta', 'sha256');
  if (!['listed', 'hidden'].includes(visibility)) fail(400, 'bad_meta', 'visibility');
  requireSig(user.publicKey, 'upload', meta, signature);
  checkFresh(nonce, ts);
  if (size > config.maxUploadBytes) fail(413, 'too_large', 'File exceeds server limit');
  const len = req.get('content-length');
  if (len !== undefined && Number(len) !== size) fail(400, 'size_mismatch');

  // Who may approve future downloads of this file (M-of-N). Owner is always in.
  const set = new Set([user.username, ...(Array.isArray(approvers) ? approvers : [])]);
  for (const a of set) if (!activeUser(a)) fail(400, 'bad_approver', `Unknown user: ${a}`);
  const policy = { approvers: [...set], threshold: Number(threshold) || 1 };
  if (!Number.isInteger(policy.threshold) || policy.threshold < 1 || policy.threshold > set.size) {
    fail(400, 'bad_threshold', `Threshold must be 1..${set.size}`);
  }

  // Authorization: admins sign their own uploads; everyone else needs an active Upload Key.
  let grant = null;
  if (user.role !== 'admin') {
    grant = grantId && db.grants[grantId];
    if (!grant || grant.payload.action !== 'upload' || grant.grantee !== user.username) {
      fail(403, 'upload_key_required', 'An active Upload Key is required');
    }
    if (grantStatus(grant) !== 'active') fail(403, 'grant_not_active', `Upload Key is ${grantStatus(grant)}`);
    if (size > grant.payload.maxBytes) fail(413, 'too_large', 'File exceeds the Upload Key size limit');
    grant.usesLeft--; // reserve; refunded on failure
  }

  const id = LFS.randomHex(12);
  const tmp = store.tmpPath(id);
  const hasher = LFS.sha256.create();
  let received = 0;
  const out = fs.createWriteStream(tmp, { flags: 'wx' });

  const cleanup = () => {
    out.destroy();
    fs.rm(tmp, { force: true }, () => {});
    if (grant) grant.usesLeft++;
  };

  await new Promise((resolve, reject) => {
    let done = false;
    const abort = (err) => {
      if (done) return;
      done = true;
      cleanup();
      reject(err);
    };
    req.on('data', (chunk) => {
      received += chunk.length;
      if (received > size) {
        req.pause();
        return abort(new HttpError(400, 'size_mismatch', 'More bytes than declared'));
      }
      hasher.update(chunk);
      if (!out.write(chunk)) {
        req.pause();
        out.once('drain', () => req.resume());
      }
    });
    req.on('aborted', () => abort(new HttpError(400, 'aborted')));
    req.on('error', abort);
    out.on('error', abort);
    req.on('end', () => {
      if (done) return;
      out.end(() => {
        if (done) return;
        if (received !== size) return abort(new HttpError(400, 'size_mismatch'));
        if (hasher.hex() !== sha256) {
          return abort(new HttpError(400, 'hash_mismatch', 'Content does not match the signed SHA-256'));
        }
        done = true;
        resolve();
      });
    });
  });

  const f = {
    id, name: cleanFileName(name), size, sha256,
    mime: typeof mime === 'string' && /^[\w.+-]+\/[\w.+-]+$/.test(mime) ? mime : 'application/octet-stream',
    owner: user.username, uploadedAt: Date.now(), visibility, policy, protected: needsKey,
    ownerPublicKey: user.publicKey,
    uploadMeta: meta, uploadSignature: signature, viaGrant: grant ? grant.id : null,
  };
  store.addFile(f, tmp);
  store.audit(user.username, 'upload', { fileId: id, name: f.name, size, grant: f.viaGrant }, clientIp(req));
  res.json({ file: fileView(f, user.username) });
}));

app.post('/api/files/:id/delete', auth, wrap(async (req, res) => {
  const f = db.files[req.params.id];
  if (!f) fail(404, 'not_found');
  if (f.owner !== req.user.username && req.user.role !== 'admin') fail(403, 'forbidden');
  const { nonce, ts, signature } = req.body || {};
  requireSig(req.user.publicKey, 'file-delete', { fileId: f.id, by: req.user.username, nonce, ts }, signature);
  checkFresh(nonce, ts);
  store.removeFile(f);
  store.audit(req.user.username, 'delete', { fileId: f.id, name: f.name }, clientIp(req));
  res.json({ ok: true });
}));

// Download (*): the downloader signs a fresh request; owner/approvers are allowed
// directly, anyone else needs an active Download Key. Returns a 60 s one-time link.
app.post('/api/files/:id/download-token', auth, wrap(async (req, res) => {
  const f = db.files[req.params.id];
  if (!f || !canSeeFile(f, req.user.username)) fail(404, 'not_found');
  const { grantId = null, nonce, ts, signature } = req.body || {};
  const username = req.user.username;
  requireSig(req.user.publicKey, 'download', { fileId: f.id, grantId, username, nonce, ts }, signature);
  checkFresh(nonce, ts);

  let via = isProtected(f) ? 'policy-member' : 'public';
  if (isProtected(f) && !(f.owner === username || f.policy.approvers.includes(username))) {
    const g = grantId && db.grants[grantId];
    if (!g || g.payload.action !== 'download' || g.payload.fileId !== f.id || g.grantee !== username) {
      fail(403, 'download_key_required', 'A Download Key for this file is required');
    }
    const st = grantStatus(g);
    if (st !== 'active') fail(403, 'grant_not_active', `Download Key is ${st}`);
    g.usesLeft--;
    via = g.id;
  }
  const token = LFS.randomHex(32);
  downloadTokens.set(token, { fileId: f.id, username, expires: Date.now() + 60_000 });
  store.audit(username, 'download_authorized', { fileId: f.id, name: f.name, via }, clientIp(req));
  res.json({ token, url: '/dl/' + token, expiresIn: 60 });
}));

// Owner switches a file between "public" and "key required".
app.post('/api/files/:id/access', auth, wrap(async (req, res) => {
  const f = db.files[req.params.id];
  if (!f) fail(404, 'not_found');
  if (f.owner !== req.user.username) fail(403, 'forbidden', 'Only the owner can change access');
  const { protected: needsKey, nonce, ts, signature } = req.body || {};
  if (typeof needsKey !== 'boolean') fail(400, 'bad_request');
  requireSig(req.user.publicKey, 'file-access',
    { fileId: f.id, protected: needsKey, by: req.user.username, nonce, ts }, signature);
  checkFresh(nonce, ts);
  f.protected = needsKey;
  store.saveMeta(f);
  store.audit(req.user.username, 'file_access', { fileId: f.id, protected: needsKey }, clientIp(req));
  res.json({ file: fileView(f, req.user.username) });
}));

// Public files: no login, like a plain "python -m http.server" share.
app.get('/api/public/files', (req, res) => {
  const files = Object.values(db.files)
    .filter((f) => !isProtected(f) && f.visibility === 'listed')
    .sort((a, b) => b.uploadedAt - a.uploadedAt)
    .map((f) => ({
      id: f.id, name: f.name, size: f.size, sha256: f.sha256, owner: f.owner, uploadedAt: f.uploadedAt,
      url: publicUrl(f), ownerPublicKey: f.ownerPublicKey, uploadMeta: f.uploadMeta, uploadSignature: f.uploadSignature,
    }));
  res.json({ files });
});

app.get('/f/:id/:name?', (req, res) => {
  const f = db.files[req.params.id];
  if (!f || isProtected(f)) return res.status(404).type('text').send('Not found.');
  store.audit('(public)', 'public_download', { fileId: f.id, name: f.name }, clientIp(req));
  sendStoredFile(res, f);
});

app.get('/dl/:token', (req, res) => {
  const t = downloadTokens.get(req.params.token);
  downloadTokens.delete(req.params.token);
  const f = t && t.expires >= Date.now() && db.files[t.fileId];
  if (!f) return res.status(410).type('text').send('Download link expired or already used.');
  sendStoredFile(res, f);
});

function sendStoredFile(res, f) {
  const encoded = encodeURIComponent(f.name).replace(/['()*]/g, (c) => '%' + c.charCodeAt(0).toString(16));
  res.set({
    'Content-Type': f.mime,
    'Content-Length': String(f.size),
    'Content-Disposition': `attachment; filename="${f.name.replace(/[^\x20-\x7e]/g, '_').replace(/"/g, '')}"; filename*=UTF-8''${encoded}`,
    'X-LFS-SHA256': f.sha256,
    'Cache-Control': 'no-store',
  });
  fs.createReadStream(store.pathOf(f)).pipe(res);
}

// ----- grants (Upload / Download Keys) -------------------------------------
const GRANT_KEYS = ['id', 'action', 'fileId', 'fileSha256', 'grantee', 'maxUses', 'maxBytes',
  'expiresAt', 'issuedBy', 'issuedAt', 'nonce', 'note'];

app.post('/api/grants', auth, wrap(async (req, res) => {
  const { payload: p, signature } = req.body || {};
  const me = req.user.username;
  if (!p || typeof p !== 'object') fail(400, 'bad_payload');
  for (const k of Object.keys(p)) if (!GRANT_KEYS.includes(k)) fail(400, 'bad_payload', `Unknown field ${k}`);
  if (LFS.normalizeCode(p.id) !== p.id) fail(400, 'bad_payload', 'id');
  if (db.grants[p.id]) fail(409, 'duplicate', 'Key id already exists');
  if (p.issuedBy !== me) fail(400, 'bad_payload', 'issuedBy');
  if (!Number.isInteger(p.maxUses) || p.maxUses < 1 || p.maxUses > 1000) fail(400, 'bad_payload', 'maxUses 1..1000');
  const maxExp = Date.now() + config.maxGrantDays * 86400_000;
  if (!Number.isSafeInteger(p.expiresAt) || p.expiresAt <= Date.now() || p.expiresAt > maxExp) {
    fail(400, 'bad_payload', `expiresAt must be within ${config.maxGrantDays} days`);
  }
  if (typeof p.issuedAt !== 'number' || Math.abs(Date.now() - p.issuedAt) > FRESH_MS) fail(400, 'stale_request');
  if (p.note !== undefined && (typeof p.note !== 'string' || p.note.length > 200)) fail(400, 'bad_payload', 'note');
  if (p.grantee !== '*' && !activeUser(p.grantee)) fail(400, 'bad_grantee', `Unknown user: ${p.grantee}`);

  let approvers, threshold;
  if (p.action === 'download') {
    const f = db.files[p.fileId];
    if (!f) fail(404, 'not_found', 'File not found');
    if (p.fileSha256 !== f.sha256) fail(400, 'bad_payload', 'fileSha256 does not match the file');
    if (p.maxBytes !== null) fail(400, 'bad_payload', 'maxBytes must be null');
    if (!f.policy.approvers.includes(me)) fail(403, 'not_approver', 'Only the file\'s approvers can issue Download Keys');
    approvers = f.policy.approvers.filter((a) => db.users[a]);
    threshold = f.policy.threshold;
  } else if (p.action === 'upload') {
    if (req.user.role !== 'admin') fail(403, 'admin_only', 'Only admins can issue Upload Keys');
    if (p.fileId !== null || p.fileSha256 !== null) fail(400, 'bad_payload', 'fileId must be null');
    if (!Number.isSafeInteger(p.maxBytes) || p.maxBytes < 1 || p.maxBytes > config.maxUploadBytes) {
      fail(400, 'bad_payload', 'maxBytes');
    }
    approvers = admins().map((u) => u.username);
    threshold = Math.min(Math.max(1, config.uploadKeyThreshold), approvers.length);
  } else {
    fail(400, 'bad_payload', 'action');
  }

  requireSig(req.user.publicKey, 'grant', p, signature);
  const g = {
    id: p.id, payload: p, approvers, threshold,
    approvals: { [me]: signature }, acceptance: null,
    grantee: p.grantee, usesLeft: p.maxUses, createdAt: Date.now(), revoked: null,
  };
  db.grants[g.id] = g;
  store.audit(me, 'grant_create', { grantId: g.id, action: p.action, fileId: p.fileId, grantee: p.grantee }, clientIp(req));
  res.json({ grant: grantView(g, me) });
}));

app.get('/api/grants', auth, (req, res) => {
  const me = req.user.username;
  const list = Object.values(db.grants)
    .filter((g) => g.approvers.includes(me) || g.grantee === me || g.payload.issuedBy === me)
    .sort((a, b) => b.createdAt - a.createdAt)
    .map((g) => grantView(g, me));
  res.json({ grants: list });
});

function loadGrant(req) {
  const id = LFS.normalizeCode(req.params.id);
  const g = id && db.grants[id];
  if (!g) fail(404, 'not_found', 'Unknown key');
  const me = req.user.username;
  // Knowing the code of an open ("anyone with the code") key is enough to view it.
  const visible = g.approvers.includes(me) || g.grantee === me || (g.grantee === '*' && !g.acceptance);
  if (!visible) fail(404, 'not_found', 'Unknown key');
  return g;
}

app.get('/api/grants/:id', auth, wrap(async (req, res) => {
  rateLimit('code:' + req.user.username, 60, 60_000);
  res.json({ grant: grantView(loadGrant(req), req.user.username) });
}));

// Co-sign by another approver (N-party / M-of-N).
app.post('/api/grants/:id/approve', auth, wrap(async (req, res) => {
  const g = loadGrant(req);
  const me = req.user.username;
  const v = grantView(g, me);
  if (!v.me.canApprove) fail(403, 'cannot_approve', 'You are not a pending approver of this key');
  requireSig(req.user.publicKey, 'grant', g.payload, req.body?.signature);
  g.approvals[me] = req.body.signature;
  store.audit(me, 'grant_approve', { grantId: g.id }, clientIp(req));
  res.json({ grant: grantView(g, me) });
}));

// Recipient signs the key (step "B ký") — binds it to B's identity.
app.post('/api/grants/:id/accept', auth, wrap(async (req, res) => {
  const g = loadGrant(req);
  const me = req.user.username;
  const v = grantView(g, me);
  if (!v.me.canAccept) fail(403, 'cannot_accept', 'This key is not addressed to you');
  const obj = { grantId: g.id, payloadHash: LFS.hashObject(g.payload), grantee: me };
  requireSig(req.user.publicKey, 'grant-accept', obj, req.body?.signature);
  g.grantee = me;
  g.acceptance = { username: me, signature: req.body.signature, at: Date.now() };
  store.audit(me, 'grant_accept', { grantId: g.id }, clientIp(req));
  res.json({ grant: grantView(g, me) });
}));

app.post('/api/grants/:id/revoke', auth, wrap(async (req, res) => {
  const g = loadGrant(req);
  const me = req.user.username;
  if (!grantView(g, me).me.canRevoke) fail(403, 'cannot_revoke');
  const { nonce, ts, signature } = req.body || {};
  requireSig(req.user.publicKey, 'grant-revoke', { grantId: g.id, by: me, nonce, ts }, signature);
  checkFresh(nonce, ts);
  g.revoked = { by: me, at: Date.now() };
  store.audit(me, 'grant_revoke', { grantId: g.id }, clientIp(req));
  res.json({ grant: grantView(g, me) });
}));

// ----- admin ---------------------------------------------------------------
app.post('/api/admin/users/:username', auth, adminOnly, wrap(async (req, res) => {
  const target = db.users[req.params.username];
  if (!target) fail(404, 'not_found');
  const { status, role, nonce, ts, signature } = req.body || {};
  if (status !== undefined && !['active', 'disabled'].includes(status)) fail(400, 'bad_status');
  if (role !== undefined && !['admin', 'user'].includes(role)) fail(400, 'bad_role');
  requireSig(req.user.publicKey, 'admin-user',
    { username: target.username, status, role, by: req.user.username, nonce, ts }, signature);
  checkFresh(nonce, ts);
  const losingAdmin = target.role === 'admin' && (role === 'user' || status === 'disabled');
  if (losingAdmin && admins().length <= 1) fail(400, 'last_admin', 'Cannot remove the last admin');
  if (status) target.status = status;
  if (role) target.role = role;
  store.saveUsers();
  if (target.status !== 'active') {
    for (const [k, s] of sessions) if (s.username === target.username) sessions.delete(k);
  }
  store.audit(req.user.username, 'admin_user', { target: target.username, status, role }, clientIp(req));
  res.json({ user: userView(target) });
}));

app.get('/api/admin/audit', auth, adminOnly, (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 200, 2000);
  res.json({ events: store.auditLog.slice(-limit).reverse() });
});

// ----- errors --------------------------------------------------------------
app.use('/api', (req, res) => res.status(404).json({ error: 'not_found' }));
app.use((err, req, res, next) => {
  if (err instanceof HttpError) {
    return res.status(err.status).json({ error: err.code, message: err.message });
  }
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'bad_json' });
  console.error(err);
  res.status(500).json({ error: 'internal', message: 'Internal server error' });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
function start() {
  const useTls = fs.existsSync(config.tlsCert) && fs.existsSync(config.tlsKey);
  const server = useTls
    ? https.createServer({ cert: fs.readFileSync(config.tlsCert), key: fs.readFileSync(config.tlsKey) }, app)
    : http.createServer(app);
  server.requestTimeout = 0; // large uploads
  server.listen(config.port, config.host, () => {
    const proto = useTls ? 'https' : 'http';
    const addrs = ['localhost'];
    for (const list of Object.values(os.networkInterfaces())) {
      for (const a of list || []) if (a.family === 'IPv4' && !a.internal) addrs.push(a.address);
    }
    console.log(`\n  ${config.serverName}  —  mode: ${config.networkMode.toUpperCase()}${useTls ? '' : '  (no TLS: run "npm run cert" for HTTPS)'}`);
    for (const a of addrs) console.log(`  → ${proto}://${a}:${config.port}`);
    console.log(`\n  Server key fingerprint (compare on clients for 2-way auth):\n    ${SERVER_FP}\n`);
  });
  return server;
}

if (require.main === module) start();
module.exports = { app, start, store };

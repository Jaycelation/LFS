'use strict';
// No database. Only plain files on disk:
//
//   keys/server.key        server Ed25519 identity (for 2-way auth)
//   keys/authorized_keys   one user per line, SSH-style:  username role status publicKey
//   storage/<name>         the shared files themselves, original names
//   storage/.lfs/<id>.json signature sidecar per file (hash, owner key, policy, signature)
//
// Keys (grants), sessions and the audit log live in memory only.
const fs = require('fs');
const path = require('path');

function writeAtomic(file, text) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, text, { mode: 0o600 });
  // OneDrive / antivirus can briefly lock the target on Windows: retry a few times.
  for (let i = 0; ; i++) {
    try {
      return fs.renameSync(tmp, file);
    } catch (e) {
      if (i >= 5) throw e;
      const until = Date.now() + 50;
      while (Date.now() < until);
    }
  }
}

class Store {
  constructor({ storageDir, keysDir }) {
    this.storageDir = storageDir;
    this.metaDir = path.join(storageDir, '.lfs');
    this.tmpDir = path.join(this.metaDir, 'tmp');
    this.keysDir = keysDir;
    this.usersFile = path.join(keysDir, 'authorized_keys');
    for (const d of [storageDir, this.metaDir, this.tmpDir, keysDir]) fs.mkdirSync(d, { recursive: true });
    for (const f of fs.readdirSync(this.tmpDir)) fs.rmSync(path.join(this.tmpDir, f), { force: true });

    this.users = this.loadUsers();
    this.files = this.loadFiles();
    this.grants = {};
    this.auditLog = [];
  }

  // ----- users: authorized_keys -----
  loadUsers() {
    const users = {};
    if (!fs.existsSync(this.usersFile)) return users;
    for (const line of fs.readFileSync(this.usersFile, 'utf8').split(/\r?\n/)) {
      const l = line.trim();
      if (!l || l.startsWith('#')) continue;
      const [username, role, status, publicKey, createdAt] = l.split(/\s+/);
      if (username && publicKey) {
        users[username] = { username, role, status, publicKey, createdAt: Number(createdAt) || 0 };
      }
    }
    return users;
  }

  saveUsers() {
    const lines = ['# LFS authorized keys — username role(admin|user) status(active|pending|disabled) ed25519-public-key created'];
    for (const u of Object.values(this.users)) {
      lines.push([u.username, u.role, u.status, u.publicKey, u.createdAt].join(' '));
    }
    writeAtomic(this.usersFile, lines.join('\n') + '\n');
  }

  // ----- files: storage/ + sidecars -----
  loadFiles() {
    const files = {};
    for (const f of fs.readdirSync(this.metaDir)) {
      if (!f.endsWith('.json')) continue;
      try {
        const meta = JSON.parse(fs.readFileSync(path.join(this.metaDir, f), 'utf8'));
        if (fs.existsSync(this.pathOf(meta))) files[meta.id] = meta;
      } catch (_) { /* ignore broken sidecar */ }
    }
    return files;
  }

  pathOf(meta) {
    return path.join(this.storageDir, meta.storedAs);
  }

  tmpPath(id) {
    return path.join(this.tmpDir, id + '.part');
  }

  // Keep the original name; add " (2)", " (3)"… on collision.
  freeName(name) {
    const ext = path.extname(name);
    const base = name.slice(0, name.length - ext.length);
    let candidate = name;
    for (let i = 2; fs.existsSync(path.join(this.storageDir, candidate)); i++) candidate = `${base} (${i})${ext}`;
    return candidate;
  }

  addFile(meta, tmpFile) {
    meta.storedAs = this.freeName(meta.name);
    fs.renameSync(tmpFile, this.pathOf(meta));
    this.saveMeta(meta);
    this.files[meta.id] = meta;
  }

  saveMeta(meta) {
    writeAtomic(path.join(this.metaDir, meta.id + '.json'), JSON.stringify(meta, null, 2));
  }

  removeFile(meta) {
    delete this.files[meta.id];
    fs.rmSync(this.pathOf(meta), { force: true });
    fs.rmSync(path.join(this.metaDir, meta.id + '.json'), { force: true });
  }

  audit(actor, action, detail, ip) {
    const e = { ts: Date.now(), actor, action, detail, ip };
    this.auditLog.push(e);
    if (this.auditLog.length > 2000) this.auditLog.shift();
    console.log(`[${new Date(e.ts).toISOString()}] ${actor} ${action} ${detail ? JSON.stringify(detail) : ''} ${ip || ''}`);
  }
}

module.exports = { Store, writeAtomic };

'use strict';
// End-to-end test: boots a throwaway server and drives the full flow through the CLI
// with three identities (alice = admin, bob, carol). Run: npm test
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');
const LFS = require('../shared/lfs-crypto');

const ROOT = path.resolve(__dirname, '..');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'lfs-e2e-'));
const PORT = 18000 + Math.floor(Math.random() * 1000);
const BASE = `http://127.0.0.1:${PORT}`;
let passed = 0;

function cli(who, ...args) {
  return execFileSync(process.execPath, [path.join(ROOT, 'cli/lfs.js'), ...args], {
    env: { ...process.env, LFS_HOME: path.join(TMP, who), LFS_PASSPHRASE: 'pw-' + who },
    cwd: path.join(TMP, who), encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
  });
}
function cliFails(who, pattern, ...args) {
  try {
    cli(who, ...args);
  } catch (e) {
    assert.match(e.stderr, pattern, `expected ${pattern} but got: ${e.stderr}`);
    return;
  }
  assert.fail(`expected failure: ${args.join(' ')}`);
}
function step(name, fn) {
  fn();
  passed++;
  console.log('  ✔ ' + name);
}
const codeOf = (out) => out.match(/[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}/)[0];
const profile = (who) => JSON.parse(fs.readFileSync(path.join(TMP, who, 'profile.json'), 'utf8'));
const identity = (who) => JSON.parse(fs.readFileSync(path.join(TMP, who, 'identity.json'), 'utf8'));

async function startServer() {
  const server = spawn(process.execPath, [path.join(ROOT, 'server/index.js')], {
    env: {
      ...process.env, PORT, HOST: '127.0.0.1', LFS_CONFIG: path.join(TMP, 'none.json'),
      STORAGE_DIR: path.join(TMP, 'storage'), KEYS_DIR: path.join(TMP, 'keys'),
    },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  await new Promise((resolve) => server.stdout.on('data', (d) => d.toString().includes('fingerprint') && resolve()));
  return server;
}

async function main() {
  let server = await startServer();

  try {
    for (const who of ['alice', 'bob', 'carol']) fs.mkdirSync(path.join(TMP, who));
    const secret = 'top secret report ' + LFS.randomHex(2000);
    fs.writeFileSync(path.join(TMP, 'alice', 'report.txt'), secret);
    fs.writeFileSync(path.join(TMP, 'bob', 'bob-notes.txt'), 'notes from bob');

    step('identities created, server pinned, registered (first user = admin)', () => {
      for (const who of ['alice', 'bob', 'carol']) {
        cli(who, 'init', who);
        cli(who, 'server', BASE);
        assert.match(cli(who, 'register'), who === 'alice' ? /as admin/ : /as user/);
      }
    });

    step('2-way login (client verifies server signature)', () => {
      for (const who of ['alice', 'bob', 'carol']) assert.match(cli(who, 'login'), /2-way/);
    });

    step('login rejected when the pinned server key does not match (MITM simulation)', () => {
      const p = profile('carol');
      const fake = LFS.generateKeyPair().publicKey;
      fs.writeFileSync(path.join(TMP, 'carol', 'profile.json'), JSON.stringify({ ...p, serverPublicKey: fake }));
      cliFails('carol', /possible MITM/, 'login');
      fs.writeFileSync(path.join(TMP, 'carol', 'profile.json'), JSON.stringify(p));
    });

    let fileId;
    step('admin uploads with a 2-of-2 policy (alice + carol)', () => {
      const out = cli('alice', 'upload', 'report.txt', '--approvers', 'carol', '--threshold', '2');
      fileId = out.match(/id ([0-9a-f]{24})/)[1];
      assert.match(cli('bob', 'ls'), /policy 2-of-2/);
    });

    step('download without a key is refused', () => {
      cliFails('bob', /Download Key for this file is required/, 'download', fileId);
    });

    let code;
    step('A generates a Download Key for B → 1/2 signatures', () => {
      const out = cli('alice', 'grant', 'download', fileId, '--to', 'bob', '--uses', '1');
      code = codeOf(out);
      assert.match(out, /Signatures: 1\/2/);
    });

    step('B signs the key, but it is not active until the 2nd approver co-signs', () => {
      assert.match(cli('bob', 'accept', code), /awaiting_approvals/);
      cliFails('bob', /is awaiting_approvals/, 'download', fileId);
    });

    step('a non-recipient cannot even see the key', () => {
      fs.mkdirSync(path.join(TMP, 'dave'));
      cli('dave', 'init', 'dave');
      cli('dave', 'server', BASE);
      cli('dave', 'register');
      cli('dave', 'login');
      cliFails('dave', /Unknown key/, 'key', code);
    });

    step('C co-signs (M-of-N reached) → B downloads, hash + uploader signature verified', () => {
      assert.match(cli('carol', 'approve', code), /Status: active/);
      assert.match(cli('bob', 'download', fileId), /matches the signature of uploader "alice"/);
      assert.strictEqual(fs.readFileSync(path.join(TMP, 'bob', 'report.txt'), 'utf8'), secret);
    });

    step('key with 1 use is exhausted after one download', () => {
      cliFails('bob', /is exhausted/, 'download', fileId, '--key', code);
    });

    step('upload by a normal user needs an Upload Key', () => {
      cliFails('bob', /Upload Key is required/, 'upload', 'bob-notes.txt');
      const ucode = codeOf(cli('alice', 'grant', 'upload', '--to', 'bob', '--uses', '1', '--max-mb', '1'));
      cliFails('bob', /awaiting_acceptance/, 'upload', 'bob-notes.txt', '--key', ucode);
      cli('bob', 'accept', ucode);
      assert.match(cli('bob', 'upload', 'bob-notes.txt', '--key', ucode), /Uploaded bob-notes.txt/);
      cliFails('bob', /exhausted/, 'upload', 'bob-notes.txt', '--key', ucode);
    });

    step('open key ("anyone with the code") binds to the first signer', () => {
      const bobFile = cli('bob', 'ls').split('\n').find((l) => l.includes('bob-notes.txt')).slice(0, 24);
      const ocode = codeOf(cli('bob', 'grant', 'download', bobFile, '--to', '*', '--uses', '3'));
      cli('carol', 'accept', ocode);
      cliFails('dave', /Unknown key/, 'accept', ocode);
      assert.match(cli('carol', 'download', bobFile), /Saved/);
    });

    step('revoked key stops working', () => {
      const rcode = codeOf(cli('alice', 'grant', 'download', fileId, '--to', 'dave', '--uses', '5'));
      cli('carol', 'approve', rcode);
      cli('dave', 'accept', rcode);
      cli('alice', 'revoke', rcode);
      cliFails('dave', /is revoked/, 'download', fileId);
    });

    // ---- protocol-level attacks, straight against the API ----
    const bob = profile('bob');
    const bobSk = LFS.unlockIdentityFile(identity('bob'), 'pw-bob');
    const post = (url, body, token = bob.token) => fetch(BASE + url, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
      body: JSON.stringify(body),
    });

    await stepAsync('replayed signed request is rejected', async () => {
      const req = { fileId, grantId: null, username: 'bob', nonce: LFS.randomHex(16), ts: Date.now() };
      const body = { ...req, signature: LFS.sign(bobSk, 'download', req) };
      const r1 = await post(`/api/files/${fileId}/download-token`, body);
      assert.strictEqual(r1.status, 403); // bob has no active key — but the nonce is burned
      const r2 = await post(`/api/files/${fileId}/download-token`, body);
      assert.strictEqual(r2.status, 409);
    });

    await stepAsync('signature from a different user is rejected', async () => {
      const carolSk = LFS.unlockIdentityFile(identity('carol'), 'pw-carol');
      const req = { fileId, grantId: null, username: 'bob', nonce: LFS.randomHex(16), ts: Date.now() };
      const r = await post(`/api/files/${fileId}/download-token`, { ...req, signature: LFS.sign(carolSk, 'download', req) });
      assert.strictEqual(r.status, 401);
    });

    await stepAsync('upload whose bytes differ from the signed SHA-256 is rejected', async () => {
      const alice = profile('alice');
      const sk = LFS.unlockIdentityFile(identity('alice'), 'pw-alice');
      const body = Buffer.from('tampered!');
      const meta = {
        name: 'x.txt', size: body.length, sha256: LFS.sha256('original!'), mime: 'text/plain', grantId: null,
        approvers: [], threshold: 1, visibility: 'listed', uploader: 'alice', nonce: LFS.randomHex(16), ts: Date.now(),
      };
      const r = await fetch(BASE + '/api/files', {
        method: 'PUT', body,
        headers: {
          Authorization: 'Bearer ' + alice.token, 'Content-Type': 'application/octet-stream',
          'X-LFS-Meta': Buffer.from(JSON.stringify(meta)).toString('base64'),
          'X-LFS-Signature': LFS.sign(sk, 'upload', meta),
        },
      });
      assert.strictEqual(r.status, 400);
      assert.strictEqual((await r.json()).error, 'hash_mismatch');
      assert.ok(!fs.readdirSync(path.join(TMP, 'storage', '.lfs', 'tmp')).length);
    });

    await stepAsync('download link is single-use', async () => {
      const sk = LFS.unlockIdentityFile(identity('alice'), 'pw-alice');
      const alice = profile('alice');
      const req = { fileId, grantId: null, username: 'alice', nonce: LFS.randomHex(16), ts: Date.now() };
      const r = await post(`/api/files/${fileId}/download-token`, { ...req, signature: LFS.sign(sk, 'download', req) }, alice.token);
      const { url } = await r.json();
      assert.strictEqual((await fetch(BASE + url)).status, 200);
      assert.strictEqual((await fetch(BASE + url)).status, 410);
    });

    await stepAsync('internal mode refuses proxied requests', async () => {
      const r = await fetch(BASE + '/api/info', { headers: { 'X-Forwarded-For': '8.8.8.8' } });
      assert.strictEqual(r.status, 403);
    });

    step('audit log records the flow', () => {
      const out = cli('alice', 'audit', '--limit', '100');
      for (const a of ['grant_create', 'grant_approve', 'grant_accept', 'download_authorized', 'grant_revoke']) assert.match(out, new RegExp(a));
    });

    await stepAsync('download auth is optional: public files need no login', async () => {
      fs.writeFileSync(path.join(TMP, 'alice', 'readme.txt'), 'hello LAN');
      const out = cli('alice', 'upload', 'readme.txt', '--public');
      const pubId = out.match(/id ([0-9a-f]{24})/)[1];
      const link = out.match(/Public link: (\S+)/)[1];
      const list = await (await fetch(BASE + '/api/public/files')).json();
      assert.deepStrictEqual(list.files.map((f) => f.name), ['readme.txt']); // protected files not listed
      assert.strictEqual(await (await fetch(link)).text(), 'hello LAN');
      assert.strictEqual((await fetch(`${BASE}/f/${fileId}`)).status, 404); // protected file
      assert.match(cli('dave', 'download', pubId, '-o', 'pub.txt'), /Saved/); // no key needed
      cli('alice', 'access', pubId, 'protected');
      assert.strictEqual((await fetch(link)).status, 404);
      cliFails('dave', /Download Key for this file is required/, 'download', pubId);
      cliFails('bob', /Only the owner/, 'access', pubId, 'public');
    });

    step('no database: plain files on disk (original names + authorized_keys)', () => {
      assert.ok(fs.existsSync(path.join(TMP, 'storage', 'report.txt')));
      assert.ok(fs.existsSync(path.join(TMP, 'storage', 'bob-notes.txt')));
      assert.match(fs.readFileSync(path.join(TMP, 'keys', 'authorized_keys'), 'utf8'), /^alice admin active /m);
    });

    server.kill();
    server = await startServer();
    step('after restart: users + files remain, sessions and keys are gone', () => {
      cliFails('alice', /Please log in/, 'ls');
      cli('alice', 'login');
      cli('bob', 'login');
      assert.match(cli('alice', 'ls'), /report\.txt/);
      assert.match(cli('bob', 'keys'), /no keys/);
      assert.match(cli('alice', 'download', fileId, '-o', 'copy.txt'), /matches the signature/);
    });

    console.log(`\n  ${passed} passed`);
  } finally {
    server.kill();
    fs.rmSync(TMP, { recursive: true, force: true });
  }
}

async function stepAsync(name, fn) {
  await fn();
  passed++;
  console.log('  ✔ ' + name);
}

main().catch((e) => {
  console.error('\n  ✖ ' + (e.stack || e.message));
  process.exitCode = 1;
});

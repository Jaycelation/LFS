'use strict';
// Generates a self-signed TLS certificate for this machine (localhost + every LAN IP)
// into certs/. The server picks it up automatically and switches to HTTPS.
// Browsers will warn about it; that is fine — server identity is verified separately
// by the Ed25519 fingerprint (2-way auth), not by the certificate.
const fs = require('fs');
const os = require('os');
const path = require('path');
const selfsigned = require('selfsigned');

const dir = path.join(__dirname, '..', 'certs');
fs.mkdirSync(dir, { recursive: true });

const ips = ['127.0.0.1'];
for (const list of Object.values(os.networkInterfaces())) {
  for (const a of list || []) if (a.family === 'IPv4' && !a.internal) ips.push(a.address);
}
const altNames = [
  { type: 2, value: 'localhost' },
  { type: 2, value: os.hostname() },
  ...ips.map((ip) => ({ type: 7, ip })),
];
const pems = selfsigned.generate([{ name: 'commonName', value: os.hostname() }], {
  keySize: 2048, days: 825, algorithm: 'sha256',
  extensions: [{ name: 'subjectAltName', altNames }],
});
fs.writeFileSync(path.join(dir, 'cert.pem'), pems.cert);
fs.writeFileSync(path.join(dir, 'key.pem'), pems.private, { mode: 0o600 });
console.log(`Certificate written to ${dir}\n  valid for: localhost, ${os.hostname()}, ${ips.join(', ')}`);
console.log('Restart the server — it will now serve HTTPS.');

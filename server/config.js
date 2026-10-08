'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

// Precedence: environment variable > config.json > default.
let file = {};
const cfgPath = process.env.LFS_CONFIG || path.join(ROOT, 'config.json');
if (fs.existsSync(cfgPath)) file = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));

function pick(envName, key, def, cast = (v) => v) {
  if (process.env[envName] !== undefined) return cast(process.env[envName]);
  if (file[key] !== undefined) return file[key];
  return def;
}
const bool = (v) => /^(1|true|yes|on)$/i.test(String(v));

// Quick start like "python -m http.server":  node server [PORT] [FOLDER]
const [argPort, argDir] = process.argv.slice(2).filter((a) => !a.startsWith('-'));

const config = {
  host: pick('HOST', 'host', '0.0.0.0'),
  port: argPort && /^d+$/.test(argPort) ? Number(argPort) : pick('PORT', 'port', 8080, Number),
  serverName: pick('LFS_NAME', 'serverName', 'Local File Share'),
  // internal: only private/loopback client IPs are served. external: anyone.
  networkMode: pick('NETWORK_MODE', 'networkMode', 'internal'),
  // Set when running behind a reverse proxy / tunnel you control (cloudflared, nginx...).
  trustProxy: pick('TRUST_PROXY', 'trustProxy', false, bool),
  // Shared files (original names) + their signature sidecars in storage/.lfs/
  storageDir: argDir ? path.resolve(argDir) : path.resolve(ROOT, pick('STORAGE_DIR', 'storageDir', 'storage')),
  // server.key + authorized_keys
  keysDir: path.resolve(ROOT, pick('KEYS_DIR', 'keysDir', 'keys')),
  // false: new accounts stay "pending" until an admin activates them.
  openRegistration: pick('OPEN_REGISTRATION', 'openRegistration', true, bool),
  // Default state of the "require a key to download" checkbox (per-file, optional).
  defaultProtected: pick('DOWNLOAD_AUTH', 'downloadAuthDefault', true, bool),
  maxUploadBytes: pick('MAX_UPLOAD_MB', 'maxUploadMB', 4096, Number) * 1024 * 1024,
  // How many admin signatures an Upload Key needs (capped at the number of admins).
  uploadKeyThreshold: pick('UPLOAD_KEY_THRESHOLD', 'uploadKeyThreshold', 1, Number),
  sessionTtlMs: pick('SESSION_TTL_MIN', 'sessionTtlMinutes', 480, Number) * 60 * 1000,
  maxGrantDays: pick('MAX_GRANT_DAYS', 'maxGrantDays', 30, Number),
  tlsCert: pick('TLS_CERT', 'tlsCert', path.join(ROOT, 'certs', 'cert.pem')),
  tlsKey: pick('TLS_KEY', 'tlsKey', path.join(ROOT, 'certs', 'key.pem')),
};

if (!['internal', 'external'].includes(config.networkMode)) {
  throw new Error(`networkMode must be "internal" or "external", got "${config.networkMode}"`);
}

module.exports = { config, ROOT };

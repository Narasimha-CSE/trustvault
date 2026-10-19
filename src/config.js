'use strict';
/**
 * Configuration. Everything security-relevant is explicit here.
 *
 * TV_SECRET is the single root secret (>= 32 chars). Sub-keys are derived with
 * HKDF so the file-encryption key and the audit-HMAC key are independent.
 * It lives in the environment, NOT in the database or the data directory, so a
 * stolen copy of the data directory alone cannot decrypt files or forge audit rows.
 */
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const ROOT = path.resolve(__dirname, '..');

function deriveKey(secret, info) {
  return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(secret, 'utf8'), Buffer.from('trustvault-v1'), Buffer.from(info), 32));
}

function loadConfig(overrides = {}) {
  const env = process.env;
  const production = (overrides.production ?? env.NODE_ENV === 'production') === true;
  const dataDir = path.resolve(overrides.dataDir || env.TV_DATA_DIR || path.join(ROOT, 'data'));
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });

  let secret = overrides.secret || env.TV_SECRET;
  if (!secret) {
    if (production) {
      throw new Error('TV_SECRET is required in production (>= 32 random characters). Run `node scripts/setup.js` to generate one.');
    }
    // Development convenience only: persist a generated secret next to the data (0600).
    const devKeyFile = path.join(dataDir, 'dev-secret');
    if (fs.existsSync(devKeyFile)) secret = fs.readFileSync(devKeyFile, 'utf8').trim();
    else {
      secret = crypto.randomBytes(48).toString('base64url');
      fs.writeFileSync(devKeyFile, secret, { mode: 0o600 });
    }
  }
  if (secret.length < 32) throw new Error('TV_SECRET must be at least 32 characters.');

  const cfg = {
    production,
    port: Number(overrides.port ?? env.PORT ?? 3000),
    host: overrides.host || env.HOST || (production ? '0.0.0.0' : '127.0.0.1'),
    dataDir,
    dbPath: overrides.dbPath || path.join(dataDir, 'trustvault.db'),
    filesDir: path.join(dataDir, 'files'),
    auditHeadFile: path.join(dataDir, 'audit.head'),
    fileKey: deriveKey(secret, 'file-key-encryption'),
    auditKey: deriveKey(secret, 'audit-hmac'),
    // Cookies are Secure whenever we are behind TLS (production). Dev over http://localhost is the only exception.
    secureCookies: overrides.secureCookies ?? (production && env.TV_INSECURE_COOKIES !== '1'),
    trustProxy: overrides.trustProxy ?? env.TV_TRUST_PROXY === '1',
    maxUploadBytes: Number(overrides.maxUploadBytes ?? env.TV_MAX_UPLOAD_BYTES ?? 10 * 1024 * 1024),
    sessionIdleMs: Number(overrides.sessionIdleMs ?? 30 * 60 * 1000),
    sessionAbsoluteMs: Number(overrides.sessionAbsoluteMs ?? 8 * 60 * 60 * 1000),
    trashRetentionDays: Number(overrides.trashRetentionDays ?? env.TV_TRASH_DAYS ?? 30),
    externalMaxGrantDays: Number(overrides.externalMaxGrantDays ?? 30),
    maxGrantDays: Number(overrides.maxGrantDays ?? 365),
    loginMaxFailures: Number(overrides.loginMaxFailures ?? 5),
    loginIpMaxFailures: Number(overrides.loginIpMaxFailures ?? 30),
    loginWindowMs: Number(overrides.loginWindowMs ?? 15 * 60 * 1000),
    passwordMinLength: 10,
    scryptCost: Number(overrides.scryptCost ?? 32768),
    // Injectable clock so tests can prove expiry without sleeping.
    now: overrides.now || (() => Date.now()),
    maintenanceIntervalMs: overrides.maintenanceIntervalMs ?? 60 * 60 * 1000,
  };
  return cfg;
}

module.exports = { loadConfig, ROOT };

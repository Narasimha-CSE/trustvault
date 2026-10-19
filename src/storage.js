'use strict';
/**
 * Encrypted file store. Files live outside any served directory under random names,
 * as AES-256-GCM ciphertext. The storage key is random and carries no user input,
 * so there is no path an attacker can influence (no traversal), and nothing in this
 * directory is ever reachable over HTTP except through an authorised download.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { encryptBlob, decryptBlob } = require('./crypto');

function createStorage(cfg) {
  fs.mkdirSync(cfg.filesDir, { recursive: true, mode: 0o700 });

  const pathFor = (key) => {
    if (!/^[0-9a-f]{32}$/.test(key)) throw new Error('bad storage key'); // defence in depth
    return path.join(cfg.filesDir, key);
  };

  return {
    /** Encrypts and writes. Returns { storageKey, wrappedKey }. */
    put(versionId, plaintext) {
      const storageKey = crypto.randomBytes(16).toString('hex');
      const { blob, wrappedKey } = encryptBlob(plaintext, versionId, cfg.fileKey);
      fs.writeFileSync(pathFor(storageKey), blob, { mode: 0o600, flag: 'wx' });
      return { storageKey, wrappedKey };
    },
    /** Reads and decrypts; throws if the ciphertext was modified or swapped between records. */
    get(versionId, storageKey, wrappedKey) {
      const blob = fs.readFileSync(pathFor(storageKey));
      return decryptBlob(blob, Buffer.from(wrappedKey), versionId, cfg.fileKey);
    },
    remove(storageKey) {
      try { fs.unlinkSync(pathFor(storageKey)); } catch { /* already gone */ }
    },
    pathFor,
  };
}

module.exports = { createStorage };

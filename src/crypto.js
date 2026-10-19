'use strict';
/**
 * Cryptographic helpers: password hashing, tokens, and authenticated encryption
 * of stored files. Only Node's built-in crypto is used.
 */
const crypto = require('node:crypto');

// ---------- passwords (scrypt, per-user salt, constant-time compare) ----------

function scrypt(password, salt, N, r, p) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password.normalize('NFKC'), salt, 64, { N, r, p, maxmem: 256 * N * r }, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

async function hashPassword(password, N = 32768) {
  const salt = crypto.randomBytes(16);
  const r = 8, p = 1;
  const key = await scrypt(password, salt, N, r, p);
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${key.toString('base64')}`;
}

async function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, N, r, p, saltB64, keyB64] = parts;
  const expected = Buffer.from(keyB64, 'base64');
  const actual = await scrypt(password, Buffer.from(saltB64, 'base64'), Number(N), Number(r), Number(p));
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

// Used when the account does not exist so response time does not reveal which emails are registered.
let dummyHashPromise = null;
async function dummyVerify(password, N) {
  dummyHashPromise ||= hashPassword('not-a-real-password', N);
  await verifyPassword(password, await dummyHashPromise);
  return false;
}

function generateTempPassword() {
  // 16 chars from an unambiguous alphabet, ~90 bits.
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  let out = '';
  const bytes = crypto.randomBytes(18);
  for (let i = 0; i < 16; i++) out += alphabet[bytes[i] % alphabet.length];
  return out;
}

// ---------- tokens / hashing ----------

const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
const sha256Hex = (data) => crypto.createHash('sha256').update(data).digest('hex');

function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

// ---------- file encryption (envelope: per-file data key wrapped by the master key) ----------
// On disk:   iv(12) | ciphertext | tag(16)             AAD = version id
// In DB:     wrapped_key = iv(12) | enc(dataKey) | tag  AAD = version id
// Binding the AAD to the version id means swapping two ciphertext files on disk makes decryption FAIL.

function encryptBlob(plaintext, versionId, masterKey) {
  const dataKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from(versionId);
  const c = crypto.createCipheriv('aes-256-gcm', dataKey, iv);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  const blob = Buffer.concat([iv, ct, c.getAuthTag()]);

  const wiv = crypto.randomBytes(12);
  const w = crypto.createCipheriv('aes-256-gcm', masterKey, wiv);
  w.setAAD(aad);
  const wrapped = Buffer.concat([wiv, w.update(dataKey), w.final(), w.getAuthTag()]);
  dataKey.fill(0);
  return { blob, wrappedKey: wrapped };
}

function decryptBlob(blob, wrappedKey, versionId, masterKey) {
  const aad = Buffer.from(versionId);
  const wiv = wrappedKey.subarray(0, 12);
  const wtag = wrappedKey.subarray(wrappedKey.length - 16);
  const wct = wrappedKey.subarray(12, wrappedKey.length - 16);
  const u = crypto.createDecipheriv('aes-256-gcm', masterKey, wiv);
  u.setAAD(aad);
  u.setAuthTag(wtag);
  const dataKey = Buffer.concat([u.update(wct), u.final()]);

  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(blob.length - 16);
  const ct = blob.subarray(12, blob.length - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', dataKey, iv);
  d.setAAD(aad);
  d.setAuthTag(tag);
  const pt = Buffer.concat([d.update(ct), d.final()]); // throws if tampered/swapped
  dataKey.fill(0);
  return pt;
}

module.exports = {
  hashPassword, verifyPassword, dummyVerify, generateTempPassword,
  randomToken, sha256Hex, safeEqual, encryptBlob, decryptBlob,
};

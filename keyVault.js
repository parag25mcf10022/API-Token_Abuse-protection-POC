/**
 * Encrypts API keys at rest so their owner can view them again after
 * re-entering their password (POST /auth/reveal-key).
 *
 * - Lookup still uses the SHA-256 hash; this encrypted copy is only for display.
 * - AES-256-GCM with a random IV per key; the user id is bound in as
 *   additional authenticated data, so a ciphertext copied onto another user's
 *   record won't decrypt.
 * - The encryption key never lives in MongoDB: it comes from
 *   KEY_ENCRYPTION_KEY (64 hex chars) or a generated file at
 *   .secrets/key-encryption.key (mode 600, git-ignored). A database leak alone
 *   therefore doesn't expose keys.
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEY_FILE = path.join(__dirname, '.secrets', 'key-encryption.key');
let masterKey;

function loadKey() {
  if (masterKey) return masterKey;
  const fromEnv = process.env.KEY_ENCRYPTION_KEY;
  if (fromEnv) {
    if (!/^[0-9a-f]{64}$/i.test(fromEnv)) {
      throw new Error('KEY_ENCRYPTION_KEY must be 64 hex characters (32 bytes).');
    }
    masterKey = Buffer.from(fromEnv, 'hex');
    return masterKey;
  }
  try {
    masterKey = Buffer.from(fs.readFileSync(KEY_FILE, 'utf8').trim(), 'hex');
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    fs.mkdirSync(path.dirname(KEY_FILE), { recursive: true, mode: 0o700 });
    masterKey = crypto.randomBytes(32);
    fs.writeFileSync(KEY_FILE, masterKey.toString('hex'), { mode: 0o600, flag: 'wx' });
  }
  if (masterKey.length !== 32) throw new Error(`Invalid key in ${KEY_FILE}.`);
  return masterKey;
}

/** Encrypt an API key for a user → { iv, tag, data } (base64). */
function encrypt(plaintext, userId) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', loadKey(), iv);
  cipher.setAAD(Buffer.from(`user:${userId}`));
  const data = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    data: data.toString('base64'),
  };
}

/** Decrypt; returns null if missing or tampered with. */
function decrypt(box, userId) {
  if (!box || !box.iv || !box.tag || !box.data) return null;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', loadKey(), Buffer.from(box.iv, 'base64'));
    decipher.setAAD(Buffer.from(`user:${userId}`));
    decipher.setAuthTag(Buffer.from(box.tag, 'base64'));
    return Buffer.concat([
      decipher.update(Buffer.from(box.data, 'base64')),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    return null;
  }
}

module.exports = { encrypt, decrypt, loadKey };

/**
 * MongoDB-backed data layer for the AAP demo.
 *
 * Database: "AAP" (open it in MongoDB Compass to inspect collections).
 *   • users    — one document per account (email, password hash, api key, flags)
 *   • counters — auto-increment source for the numeric `id` field
 *   • sessions — created by connect-mongo (see server.js); the queryable
 *                session store that makes account-binding possible
 *
 * Connect with Compass at: mongodb://localhost:27017  →  database "AAP".
 */

const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const MONGO_URL = process.env.MONGO_URL || 'mongodb://localhost:27017';
const DB_NAME = process.env.MONGO_DB || 'AAP';

let client;
let db;
let users;
let counters;

/** Connect once and cache the handles. Safe to call repeatedly. */
async function connect() {
  if (db) return db;
  client = new MongoClient(MONGO_URL);
  await client.connect();
  db = client.db(DB_NAME);
  users = db.collection('users');
  counters = db.collection('counters');
  await users.createIndex({ email: 1 }, { unique: true });
  await users.createIndex({ id: 1 }, { unique: true });
  await migratePlaintextKeys();
  await users.createIndex({ apiKeyHash: 1 }, { unique: true });
  return db;
}

/**
 * One-time migration: older versions stored API keys in plaintext (`apiKey`).
 * Replace them with a hash + display prefix. Existing keys keep working.
 */
async function migratePlaintextKeys() {
  const legacy = await users.find({ apiKey: { $exists: true } }).toArray();
  if (!legacy.length) return;
  // The old unique index on `apiKey` would reject unsetting the field on more
  // than one document (missing values index as null), so drop it first.
  await users.dropIndex('apiKey_1').catch(() => {});
  for (const u of legacy) {
    await users.updateOne(
      { _id: u._id },
      {
        $set: { apiKeyHash: hashApiKey(u.apiKey), apiKeyPrefix: keyPrefix(u.apiKey) },
        $unset: { apiKey: '' },
      }
    );
  }
  console.log(`Migrated ${legacy.length} plaintext API key(s) to hashed storage.`);
}

/** The live MongoClient — connect-mongo reuses this so everything lands in "AAP". */
function getClient() {
  return client;
}

function getDbName() {
  return DB_NAME;
}

async function close() {
  if (client) await client.close();
}

/**
 * Return a persistent random secret (e.g. the session-signing key), creating
 * it on first use. Stored in the "config" collection so it survives restarts
 * without ever being hard-coded.
 */
async function getOrCreateSecret(name) {
  const doc = await db.collection('config').findOneAndUpdate(
    { _id: name },
    { $setOnInsert: { value: crypto.randomBytes(32).toString('hex') } },
    { upsert: true, returnDocument: 'after' }
  );
  return doc.value;
}

/** Hash a password with a random salt using scrypt. Format: salt:hash (hex). */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

// Hash of a random throwaway password. Login verifies against this when the
// email doesn't exist, so "unknown user" and "wrong password" take the same
// time and can't be told apart.
const DUMMY_HASH = hashPassword(crypto.randomBytes(16).toString('hex'));

/** Constant-time verify of a password against a stored salt:hash string. */
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const candidate = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(hash, 'hex');
  return candidate.length === expected.length &&
    crypto.timingSafeEqual(candidate, expected);
}

/** Generate a fresh API key (plaintext — shown to the owner once, never stored). */
function generateApiKey() {
  return 'ak_' + crypto.randomBytes(24).toString('hex');
}

/**
 * Keys are stored only as SHA-256 hashes. They're 192-bit random values, so a
 * fast hash is sufficient (no salt/slow KDF needed — they can't be guessed).
 * A DB leak therefore doesn't reveal usable keys.
 */
function hashApiKey(apiKey) {
  return crypto.createHash('sha256').update(apiKey).digest('hex');
}

/** Non-secret display prefix, e.g. "ak_1a2b3c4", so users can tell keys apart. */
function keyPrefix(apiKey) {
  return apiKey.slice(0, 10);
}

/** Atomically grab the next numeric user id. */
async function nextId() {
  const doc = await counters.findOneAndUpdate(
    { _id: 'userId' },
    { $inc: { seq: 1 } },
    { upsert: true, returnDocument: 'after' }
  );
  return doc.seq;
}

// New keys start DISABLED: an admin must approve (enable) them before use.
async function createUser(email, password, { isAdmin = false, keyEnabled = false } = {}) {
  email = email.trim().toLowerCase();
  // Deliberately vague: don't confirm whether an email is registered.
  if (await users.findOne({ email })) {
    throw new Error('Could not create an account with those details.');
  }
  const id = await nextId();
  const apiKey = generateApiKey();
  const user = {
    id,
    email,
    passwordHash: hashPassword(password),
    apiKeyHash: hashApiKey(apiKey),
    apiKeyPrefix: keyPrefix(apiKey),
    keyEnabled: !!keyEnabled, // admin toggles this on/off
    isAdmin,
    createdAt: new Date().toISOString(),
  };
  try {
    await users.insertOne(user);
  } catch (e) {
    if (e.code === 11000) {
      throw new Error('Could not create an account with those details.');
    }
    throw e;
  }
  // Plaintext key is returned to the caller once (for display) — not stored.
  return { ...user, apiKey };
}

function getUserById(id) {
  return users.findOne({ id: Number(id) });
}

function getUserByEmail(email) {
  return users.findOne({ email: String(email).trim().toLowerCase() });
}

function getUserByApiKey(apiKey) {
  return users.findOne({ apiKeyHash: hashApiKey(apiKey) });
}

/**
 * Replace a user's API key. The old key stops working immediately. Returns
 * the new plaintext key (the only time it is available). Approval state
 * (keyEnabled) is kept, so rotating can't bypass an admin's decision.
 */
async function rotateApiKey(userId) {
  const apiKey = generateApiKey();
  const r = await users.updateOne(
    { id: Number(userId) },
    { $set: { apiKeyHash: hashApiKey(apiKey), apiKeyPrefix: keyPrefix(apiKey) } }
  );
  if (!r.matchedCount) throw new Error('User not found');
  return apiKey;
}

function listUsers() {
  return users.find().sort({ id: 1 }).toArray();
}

/** Replace a user's password (new salt + hash). */
async function setPassword(userId, password) {
  await users.updateOne(
    { id: Number(userId) },
    { $set: { passwordHash: hashPassword(password) } }
  );
}

/** Admin helper: flip a user's API key on/off. Returns the new state. */
async function setKeyEnabled(userId, enabled) {
  const doc = await users.findOneAndUpdate(
    { id: Number(userId) },
    { $set: { keyEnabled: !!enabled } },
    { returnDocument: 'after' }
  );
  if (!doc) throw new Error('User not found');
  return doc.keyEnabled;
}

module.exports = {
  connect,
  close,
  getClient,
  getDbName,
  getOrCreateSecret,
  createUser,
  getUserById,
  getUserByEmail,
  getUserByApiKey,
  listUsers,
  setKeyEnabled,
  setPassword,
  verifyPassword,
  DUMMY_HASH,
  rotateApiKey,
};

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
  await users.createIndex({ apiKey: 1 }, { unique: true });
  await users.createIndex({ id: 1 }, { unique: true });
  return db;
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

/** Hash a password with a random salt using scrypt. Format: salt:hash (hex). */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

/** Constant-time verify of a password against a stored salt:hash string. */
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const candidate = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(hash, 'hex');
  return candidate.length === expected.length &&
    crypto.timingSafeEqual(candidate, expected);
}

/** Generate a fresh API key. */
function generateApiKey() {
  return 'ak_' + crypto.randomBytes(24).toString('hex');
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
  if (await users.findOne({ email })) {
    throw new Error('An account with that email already exists.');
  }
  const id = await nextId();
  const user = {
    id,
    email,
    passwordHash: hashPassword(password),
    apiKey: generateApiKey(),
    keyEnabled: !!keyEnabled, // admin toggles this on/off
    isAdmin,
    createdAt: new Date().toISOString(),
  };
  try {
    await users.insertOne(user);
  } catch (e) {
    if (e.code === 11000) {
      throw new Error('An account with that email already exists.');
    }
    throw e;
  }
  return user;
}

function getUserById(id) {
  return users.findOne({ id: Number(id) });
}

function getUserByEmail(email) {
  return users.findOne({ email: String(email).trim().toLowerCase() });
}

function getUserByApiKey(apiKey) {
  return users.findOne({ apiKey });
}

function listUsers() {
  return users.find().sort({ id: 1 }).toArray();
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
  createUser,
  getUserById,
  getUserByEmail,
  getUserByApiKey,
  listUsers,
  setKeyEnabled,
  verifyPassword,
  generateApiKey,
};

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
const { DEFAULT_USER_POLICY } = require('./policy');

const MONGO_URL = process.env.MONGO_URL || 'mongodb://localhost:27017';
const DB_NAME = process.env.MONGO_DB || 'AAP';

let client;
let db;
let users;
let counters;
let devices;
let orgs;

/** Connect once and cache the handles. Safe to call repeatedly. */
async function connect() {
  if (db) return db;
  client = new MongoClient(MONGO_URL);
  await client.connect();
  db = client.db(DB_NAME);
  users = db.collection('users');
  counters = db.collection('counters');
  devices = db.collection('devices');
  orgs = db.collection('orgs');
  await users.createIndex({ email: 1 }, { unique: true });
  await users.createIndex({ id: 1 }, { unique: true });
  await migratePlaintextKeys();
  await users.createIndex({ apiKeyHash: 1 }, { unique: true });
  await devices.createIndex({ userId: 1, deviceHash: 1 }, { unique: true });
  await devices.createIndex({ publicId: 1 }, { unique: true });
  await orgs.createIndex({ id: 1 }, { unique: true });
  await orgs.createIndex({ name: 1 }, { unique: true });
  await orgs.createIndex(
    { masterKeyHash: 1 },
    { unique: true, partialFilterExpression: { masterKeyHash: { $type: 'string' } } }
  );
  await users.createIndex({ orgId: 1 });
  await migrateMissingPolicies();
  return db;
}

/** Users created before policies existed: admins unrestricted, others default. */
async function migrateMissingPolicies() {
  await users.updateMany(
    { policy: { $exists: false }, isAdmin: true },
    { $set: { policy: { scopes: null, limits: { categoryRequestsPerDay: {} } } } }
  );
  await users.updateMany(
    { policy: { $exists: false } },
    { $set: { policy: DEFAULT_USER_POLICY } }
  );
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

/** Atomically grab the next numeric id for a sequence ("userId", "orgId"). */
async function nextId(seq = 'userId') {
  const doc = await counters.findOneAndUpdate(
    { _id: seq },
    { $inc: { seq: 1 } },
    { upsert: true, returnDocument: 'after' }
  );
  return doc.seq;
}

// New keys start DISABLED: an admin must approve (enable) them before use.
async function createUser(
  email,
  password,
  { isAdmin = false, keyEnabled = false, orgId = null, orgRole = null, policy = null } = {}
) {
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
    keyRevoked: false,
    isAdmin,
    orgId,
    orgRole, // 'admin' | 'member' | null
    policy: policy || DEFAULT_USER_POLICY,
    knownIps: [],
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
    {
      $set: {
        apiKeyHash: hashApiKey(apiKey),
        apiKeyPrefix: keyPrefix(apiKey),
        keyRevoked: false,
      },
    }
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

// --- Devices ---------------------------------------------------------------
// A key only works from devices its owner has approved. The CLI holds a random
// device token; we store only its SHA-256 hash, plus a short pairing code
// (shown in both the CLI and the dashboard) so the owner can confirm they're
// approving their own machine.

const MAX_PENDING_DEVICES = 5;

function hashDeviceToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/** Pairing code shown to the user, e.g. "4F2-A9C". The CLI computes the same. */
function deviceCode(deviceHash) {
  const c = deviceHash.slice(0, 6).toUpperCase();
  return `${c.slice(0, 3)}-${c.slice(3)}`;
}

function getDevice(userId, token) {
  return devices.findOne({ userId, deviceHash: hashDeviceToken(token) });
}

/**
 * Register an unknown device as pending. Keeps at most MAX_PENDING_DEVICES
 * pending entries per user (oldest dropped) so a stolen key can't flood the
 * owner's list.
 */
async function registerPendingDevice(userId, token, name) {
  const deviceHash = hashDeviceToken(token);
  const pending = await devices
    .find({ userId, status: 'pending' })
    .sort({ createdAt: 1 })
    .toArray();
  const excess = pending.length - (MAX_PENDING_DEVICES - 1);
  if (excess > 0) {
    await devices.deleteMany({ _id: { $in: pending.slice(0, excess).map((d) => d._id) } });
  }
  const now = new Date();
  const doc = {
    publicId: crypto.randomBytes(8).toString('hex'),
    userId,
    deviceHash,
    code: deviceCode(deviceHash),
    name,
    status: 'pending',
    createdAt: now,
    lastSeen: now,
  };
  try {
    await devices.insertOne(doc);
  } catch (e) {
    if (e.code !== 11000) throw e; // concurrent registration — fine
  }
  return doc;
}

function touchDevice(id) {
  return devices.updateOne({ _id: id }, { $set: { lastSeen: new Date() } });
}

function listDevices(userId) {
  return devices
    .find({ userId }, { projection: { _id: 0, deviceHash: 0, userId: 0 } })
    .sort({ createdAt: -1 })
    .toArray();
}

/** Approve a device — scoped to the owner, so users can't touch others'. */
async function approveDevice(userId, publicId) {
  const r = await devices.updateOne(
    { userId, publicId: String(publicId) },
    { $set: { status: 'approved', approvedAt: new Date() } }
  );
  return r.matchedCount === 1;
}

async function removeDevice(userId, publicId) {
  const r = await devices.deleteOne({ userId, publicId: String(publicId) });
  return r.deletedCount === 1;
}

/**
 * Admin response to suspicious activity: kill the key without issuing a new
 * one. The owner must log in and generate a replacement (shown only to them).
 */
async function revokeApiKey(userId) {
  const r = await users.updateOne(
    { id: Number(userId) },
    {
      $set: {
        // Unique, never-matching placeholder (hex keys can't hash to this).
        apiKeyHash: `revoked:${crypto.randomBytes(16).toString('hex')}`,
        apiKeyPrefix: null,
        keyRevoked: true,
      },
    }
  );
  return r.matchedCount === 1;
}

/**
 * Remember the IPs an account logs in from. Returns true if this IP is new
 * AND the account has logged in before (first login isn't suspicious).
 */
async function noteLoginIp(userId, ip) {
  const u = await users.findOne({ id: Number(userId) }, { projection: { knownIps: 1 } });
  const known = (u && u.knownIps) || [];
  if (known.includes(ip)) return false;
  await users.updateOne(
    { id: Number(userId) },
    { $push: { knownIps: { $each: [ip], $slice: -20 } } }
  );
  return known.length > 0;
}

function setUserPolicy(userId, policy) {
  return users.updateOne({ id: Number(userId) }, { $set: { policy } });
}

function setUserOrg(userId, orgId, orgRole) {
  return users.updateOne({ id: Number(userId) }, { $set: { orgId, orgRole } });
}

function listUsersInOrg(orgId) {
  return users.find({ orgId }).sort({ id: 1 }).toArray();
}

// --- Orgs ------------------------------------------------------------------
// An org groups members under one admin-only master key. The master key is
// for management only (see server.js /api/org/*) and is stored hashed.

async function createOrg(name) {
  const org = {
    id: await nextId('orgId'),
    name,
    masterKeyHash: null,
    masterKeyPrefix: null,
    // Org-wide pool: totals across all members. Empty = unlimited.
    policy: { scopes: null, limits: { categoryRequestsPerDay: {} } },
    // Policy given to newly added members.
    memberDefaults: DEFAULT_USER_POLICY,
    createdAt: new Date().toISOString(),
  };
  try {
    await orgs.insertOne(org);
  } catch (e) {
    if (e.code === 11000) throw new Error('An org with that name already exists.');
    throw e;
  }
  return org;
}

function getOrg(id) {
  return id == null ? null : orgs.findOne({ id: Number(id) });
}

function listOrgs() {
  return orgs.find().sort({ id: 1 }).toArray();
}

function getOrgByMasterKey(masterKey) {
  return orgs.findOne({ masterKeyHash: hashApiKey(masterKey) });
}

/** Issue a new master key (old one dies). Returns the plaintext, once. */
async function rotateOrgMasterKey(orgId) {
  const key = 'mk_' + crypto.randomBytes(24).toString('hex');
  const r = await orgs.updateOne(
    { id: Number(orgId) },
    { $set: { masterKeyHash: hashApiKey(key), masterKeyPrefix: key.slice(0, 10) } }
  );
  if (!r.matchedCount) throw new Error('Org not found');
  return key;
}

function setOrgPolicy(orgId, field, policy) {
  return orgs.updateOne({ id: Number(orgId) }, { $set: { [field]: policy } });
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
  getDevice,
  registerPendingDevice,
  touchDevice,
  listDevices,
  approveDevice,
  removeDevice,
  verifyPassword,
  DUMMY_HASH,
  rotateApiKey,
  revokeApiKey,
  noteLoginIp,
  setUserPolicy,
  setUserOrg,
  listUsersInOrg,
  createOrg,
  getOrg,
  listOrgs,
  getOrgByMasterKey,
  rotateOrgMasterKey,
  setOrgPolicy,
};

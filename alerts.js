/**
 * Security alerts (collection "alerts") surfaced to admins, who can respond
 * by rotating the affected user's key.
 *
 * Types:
 *   new_device      — a key was used from an unknown device (now pending)
 *   new_ip_login    — successful login from an IP not seen for this account
 *   login_lockout   — too many failed logins for this account
 *   limit_exceeded  — a usage limit blocked a request
 *   key_revoked     — an admin revoked the user's key
 *   reveal_lockout  — too many wrong passwords while viewing the key
 *
 * Noisy types are de-duplicated per user per day via `dedupeKey`.
 */

'use strict';

const crypto = require('crypto');

let alerts;

async function init(db) {
  alerts = db.collection('alerts');
  await alerts.createIndex({ publicId: 1 }, { unique: true });
  await alerts.createIndex({ orgId: 1, resolvedAt: 1, createdAt: -1 });
  await alerts.createIndex({ dedupeKey: 1 }, { unique: true, sparse: true });
  // Keep a year of history.
  await alerts.createIndex({ createdAt: 1 }, { expireAfterSeconds: 365 * 24 * 3600 });
}

/**
 * Record an alert. `daily: true` collapses repeats of the same type for the
 * same user within a UTC day into one alert (with a counter).
 */
async function raise(type, user, { detail = '', ip = null, daily = false } = {}) {
  const now = new Date();
  const base = {
    type,
    userId: user.id,
    email: user.email,
    orgId: user.orgId || null,
    detail: String(detail).slice(0, 200),
    ip,
  };
  if (daily) {
    const dedupeKey = `${type}:${user.id}:${now.toISOString().slice(0, 10)}`;
    await alerts.updateOne(
      { dedupeKey },
      {
        $setOnInsert: { ...base, publicId: newId(), createdAt: now, resolvedAt: null, dedupeKey },
        $inc: { count: 1 },
        $set: { lastAt: now },
      },
      { upsert: true }
    );
    return;
  }
  await alerts.insertOne({
    ...base,
    publicId: newId(),
    createdAt: now,
    lastAt: now,
    count: 1,
    resolvedAt: null,
  });
}

function newId() {
  return crypto.randomBytes(8).toString('hex');
}

/** Open alerts; orgId undefined = all (super admin), otherwise that org only. */
function listOpen(orgId) {
  const q = { resolvedAt: null };
  if (orgId !== undefined) q.orgId = orgId;
  return alerts
    .find(q, { projection: { _id: 0, dedupeKey: 0 } })
    .sort({ lastAt: -1 })
    .limit(200)
    .toArray();
}

async function getByPublicId(publicId) {
  return alerts.findOne({ publicId: String(publicId) });
}

async function resolve(publicId) {
  const r = await alerts.updateOne(
    { publicId: String(publicId), resolvedAt: null },
    { $set: { resolvedAt: new Date() } }
  );
  return r.matchedCount === 1;
}

/** Resolve every open alert for a user (e.g. after their key is revoked). */
function resolveAllForUser(userId) {
  return alerts.updateMany({ userId, resolvedAt: null }, { $set: { resolvedAt: new Date() } });
}

module.exports = { init, raise, listOpen, getByPublicId, resolve, resolveAllForUser };

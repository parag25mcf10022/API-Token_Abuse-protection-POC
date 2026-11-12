/**
 * Fixed-window rate limiter backed by MongoDB (collection "ratelimits"), so
 * every app instance sharing the database enforces the same limits.
 *
 * Each window is one document { _id: "<name>|<key>", count, resetAt,
 * expiresAt }. A hit is a single atomic findOneAndUpdate (pipeline update):
 * it starts a new window when the old one has ended, otherwise increments the
 * count — so concurrent hits from any number of instances are counted
 * exactly. A TTL index removes ended windows.
 */

'use strict';

let col = null;

async function init(db) {
  col = db.collection('ratelimits');
  await col.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
}

function store() {
  if (!col) throw new Error('rateLimit.init(db) must be called before use');
  return col;
}

const isDupKey = (e) => e && e.code === 11000;

function createLimiter({ name, windowMs, max }) {
  if (!name) throw new Error('createLimiter needs a unique name');
  const id = (key) => `${name}|${key}`;
  const retry = (resetAt, now) => Math.max(1, Math.ceil((resetAt - now) / 1000));

  async function hitOnce(key) {
    const now = new Date();
    const fresh = new Date(now.getTime() + windowMs);
    // In one $set stage every expression sees the document as it was BEFORE
    // the update, so "still in window?" is evaluated once, consistently.
    const live = { $gt: ['$resetAt', now] }; // false for a new doc (missing < Date)
    return store().findOneAndUpdate(
      { _id: id(key) },
      [
        {
          $set: {
            count: { $cond: [live, { $add: ['$count', 1] }, 1] },
            resetAt: { $cond: [live, '$resetAt', fresh] },
            expiresAt: { $cond: [live, '$resetAt', fresh] },
          },
        },
      ],
      { upsert: true, returnDocument: 'after' }
    );
  }

  return {
    name,
    windowMs,
    max,
    /** Record a hit; resolves { allowed, count, retryAfterSec }. */
    async hit(key) {
      let doc;
      try {
        doc = await hitOnce(key);
      } catch (e) {
        // Two instances upserting the same new window at once: one insert
        // wins, the other retries as a plain update.
        if (!isDupKey(e)) throw e;
        doc = await hitOnce(key);
      }
      const now = Date.now();
      return { allowed: doc.count <= max, count: doc.count, retryAfterSec: retry(doc.resetAt, now) };
    },
    /** Is the key currently at/over the limit (without recording a hit)? */
    async blocked(key) {
      const now = new Date();
      const doc = await store().findOne({ _id: id(key), resetAt: { $gt: now } });
      if (!doc) return { blocked: false };
      return { blocked: doc.count >= max, retryAfterSec: retry(doc.resetAt, now) };
    },
    async reset(key) {
      await store().deleteOne({ _id: id(key) });
    },
  };
}

function tooMany(res, retryAfterSec) {
  res.set('Retry-After', String(retryAfterSec));
  return res
    .status(429)
    .json({ error: 'Too many requests. Please try again later.', retryAfter: retryAfterSec });
}

/** Express middleware: count every request under keyFn(req). */
function limit(limiter, keyFn) {
  return (req, res, next) => {
    limiter.hit(keyFn(req)).then(
      (r) => (r.allowed ? next() : tooMany(res, r.retryAfterSec)),
      next
    );
  };
}

module.exports = { init, createLimiter, limit, tooMany };

/**
 * Minimal in-memory fixed-window rate limiter (no dependencies).
 *
 * Fine for a single-process demo. For multiple instances, back this with a
 * shared store (e.g. Redis or a MongoDB TTL collection).
 */

'use strict';

function createLimiter({ windowMs, max }) {
  const hits = new Map(); // key -> { count, resetAt }

  // Drop expired windows periodically so memory stays bounded.
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.resetAt <= now) hits.delete(k);
  }, windowMs);
  sweep.unref();

  return {
    /** Record a hit; returns { allowed, retryAfterSec }. */
    hit(key) {
      const now = Date.now();
      let entry = hits.get(key);
      if (!entry || entry.resetAt <= now) {
        entry = { count: 0, resetAt: now + windowMs };
        hits.set(key, entry);
      }
      entry.count += 1;
      return {
        allowed: entry.count <= max,
        retryAfterSec: Math.ceil((entry.resetAt - now) / 1000),
      };
    },
    /** Is the key currently over the limit (without recording a hit)? */
    blocked(key) {
      const entry = hits.get(key);
      if (!entry || entry.resetAt <= Date.now()) return { blocked: false };
      return {
        blocked: entry.count >= max,
        retryAfterSec: Math.ceil((entry.resetAt - Date.now()) / 1000),
      };
    },
    reset(key) {
      hits.delete(key);
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
    const r = limiter.hit(keyFn(req));
    if (!r.allowed) return tooMany(res, r.retryAfterSec);
    next();
  };
}

module.exports = { createLimiter, limit, tooMany };

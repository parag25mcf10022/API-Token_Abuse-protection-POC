/**
 * Usage metering + limit enforcement, backed by MongoDB (collection "usage").
 *
 * Counters are kept per subject (a user "u:<id>" or an org "o:<id>") in UTC
 * buckets — minute, day, month — each document holding
 * { requests, tokens, cat: { <category>: requests } }. A TTL index drops old
 * buckets automatically.
 *
 * check() runs before the request is processed and record() after, so under
 * heavy concurrency a subject can overshoot a limit by a few in-flight
 * requests. That's acceptable for quotas; the IP limiter still caps bursts.
 */

'use strict';

const MIN_MS = 60 * 1000;
const DAY_MS = 24 * 60 * MIN_MS;

let usage;

async function init(db) {
  usage = db.collection('usage');
  await usage.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
}

function buckets(now = new Date()) {
  const iso = now.toISOString();
  return {
    minute: { id: `M:${iso.slice(0, 16)}`, ttl: 2 * 60 * MIN_MS },
    day: { id: `D:${iso.slice(0, 10)}`, ttl: 40 * DAY_MS },
    month: { id: `Mo:${iso.slice(0, 7)}`, ttl: 400 * DAY_MS },
  };
}

/** Seconds until the given bucket rolls over (for Retry-After). */
function secondsUntilReset(kind, now = new Date()) {
  const next = new Date(now);
  if (kind === 'minute') {
    next.setUTCSeconds(60, 0);
  } else if (kind === 'day') {
    next.setUTCHours(24, 0, 0, 0);
  } else {
    next.setUTCMonth(next.getUTCMonth() + 1, 1);
    next.setUTCHours(0, 0, 0, 0);
  }
  return Math.max(1, Math.ceil((next - now) / 1000));
}

const subjects = (user, org) => [
  { level: 'user', key: `u:${user.id}`, policy: user.policy },
  ...(org ? [{ level: 'org', key: `o:${org.id}`, policy: org.policy }] : []),
];

/** Current counters for one subject: { minute, day, month }. */
async function countersFor(subjectKey, now = new Date()) {
  const b = buckets(now);
  const docs = await usage
    .find({ _id: { $in: Object.values(b).map((x) => `${subjectKey}|${x.id}`) } })
    .toArray();
  const byId = Object.fromEntries(docs.map((d) => [d._id, d]));
  const get = (x) => byId[`${subjectKey}|${x.id}`] || { requests: 0, tokens: 0, cat: {} };
  return { minute: get(b.minute), day: get(b.day), month: get(b.month) };
}

/**
 * Would this request exceed any limit for the user or their org?
 * Returns { ok: true } or { ok: false, level, limit, max, retryAfterSec }.
 */
async function check(user, org, category, estTokens) {
  const now = new Date();
  for (const s of subjects(user, org)) {
    const l = (s.policy && s.policy.limits) || {};
    const c = await countersFor(s.key, now);
    const rules = [
      ['burstPerMinute', 'minute', c.minute.requests + 1],
      ['requestsPerDay', 'day', c.day.requests + 1],
      ['requestsPerMonth', 'month', c.month.requests + 1],
      ['tokensPerDay', 'day', c.day.tokens + estTokens],
      ['tokensPerMonth', 'month', c.month.tokens + estTokens],
    ];
    const catMax = l.categoryRequestsPerDay && l.categoryRequestsPerDay[category];
    if (Number.isInteger(catMax)) {
      const used = (c.day.cat && c.day.cat[category]) || 0;
      if (used + 1 > catMax) {
        return {
          ok: false,
          level: s.level,
          limit: `categoryRequestsPerDay.${category}`,
          max: catMax,
          retryAfterSec: secondsUntilReset('day', now),
        };
      }
    }
    for (const [name, kind, wouldBe] of rules) {
      if (Number.isInteger(l[name]) && wouldBe > l[name]) {
        return {
          ok: false,
          level: s.level,
          limit: name,
          max: l[name],
          retryAfterSec: secondsUntilReset(kind, now),
        };
      }
    }
  }
  return { ok: true };
}

/** Count a completed request against the user (and org) buckets. */
async function record(user, org, category, tokens) {
  const now = new Date();
  const b = buckets(now);
  const ops = [];
  for (const s of subjects(user, org)) {
    for (const x of Object.values(b)) {
      ops.push({
        updateOne: {
          filter: { _id: `${s.key}|${x.id}` },
          update: {
            $inc: { requests: 1, tokens, [`cat.${category}`]: 1 },
            $setOnInsert: { expiresAt: new Date(now.getTime() + x.ttl) },
          },
          upsert: true,
        },
      });
    }
  }
  await usage.bulkWrite(ops, { ordered: false });
}

/** Usage snapshot for display: today and this month. */
async function summary(subjectKey) {
  const c = await countersFor(subjectKey);
  const pick = (d) => ({ requests: d.requests || 0, tokens: d.tokens || 0, byCategory: d.cat || {} });
  return { today: pick(c.day), month: pick(c.month) };
}

module.exports = { init, check, record, summary };

/**
 * Usage metering + limit enforcement, backed by MongoDB (collection "usage").
 *
 * Counters are kept per subject (a user "u:<id>" or an org "o:<id>") in UTC
 * buckets — minute, day, month — each document holding
 * { requests, tokens, cat: { <category>: requests }, ctok: { <category>: tokens } }. A TTL index drops old
 * buckets automatically.
 *
 * check() runs before the request is processed and record() after, so under
 * heavy concurrency a subject can overshoot a limit by a few in-flight
 * requests. That's acceptable for quotas; the IP limiter still caps bursts.
 */

'use strict';

const { categoryCaps } = require('./policy');

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
    // This category's own daily quota (requests and tokens) — independent of
    // every other category.
    const caps = categoryCaps(l, category);
    const catReq = ((c.day.cat || {})[category] || 0) + 1;
    const catTok = ((c.day.ctok || {})[category] || 0) + estTokens;
    for (const [name, wouldBe, cap] of [
      [`${category} requests/day`, catReq, caps.requests],
      [`${category} tokens/day`, catTok, caps.tokens],
    ]) {
      if (Number.isInteger(cap) && wouldBe > cap) {
        return { ok: false, level: s.level, limit: name, max: cap, retryAfterSec: secondsUntilReset('day', now) };
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
            $inc: { requests: 1, tokens, [`cat.${category}`]: 1, [`ctok.${category}`]: tokens },
            $setOnInsert: { expiresAt: new Date(now.getTime() + x.ttl) },
          },
          upsert: true,
        },
      });
    }
  }
  await usage.bulkWrite(ops, { ordered: false });
}

// --- Quota notifications -----------------------------------------------------
const THRESHOLDS = [50, 75, 90, 99];

const LABELS = {
  requestsPerDay: ['daily requests', 'day'],
  requestsPerMonth: ['monthly requests', 'month'],
  tokensPerDay: ['daily tokens', 'day'],
  tokensPerMonth: ['monthly tokens', 'month'],
};

/**
 * After a request is recorded: which 50/75/90/99% thresholds did THIS request
 * cross? Each crossing happens exactly once per period, so notices aren't
 * repeated. Returns [{ key, scope, level, text, percent }].
 */
async function quotaNotices(user, org, category, tokens) {
  const now = new Date();
  const periodId = { day: now.toISOString().slice(0, 10), month: now.toISOString().slice(0, 7) };
  const out = [];
  for (const s of subjects(user, org)) {
    const l = (s.policy && s.policy.limits) || {};
    const c = await countersFor(s.key, now);
    const checks = [
      ['requestsPerDay', c.day.requests, 1],
      ['requestsPerMonth', c.month.requests, 1],
      ['tokensPerDay', c.day.tokens, tokens],
      ['tokensPerMonth', c.month.tokens, tokens],
    ];
    const caps = categoryCaps(l, category);
    if (Number.isInteger(caps.requests)) {
      checks.push([`category:${category}`, (c.day.cat && c.day.cat[category]) || 0, 1, caps.requests]);
    }
    if (Number.isInteger(caps.tokens)) {
      checks.push([`categoryTokens:${category}`, (c.day.ctok && c.day.ctok[category]) || 0, tokens, caps.tokens]);
    }
    for (const [name, after, inc, capOverride] of checks) {
      const cap = capOverride !== undefined ? capOverride : l[name];
      if (!Number.isInteger(cap) || cap <= 0) continue;
      const before = ((after - inc) / cap) * 100;
      const now_ = (after / cap) * 100;
      const crossed = THRESHOLDS.filter((t) => before < t && now_ >= t);
      if (!crossed.length) continue;
      const t = crossed[crossed.length - 1];
      const isCat = name.startsWith('category');
      const what = name.startsWith('categoryTokens:')
        ? `today's ${category} token quota`
        : isCat ? `today's ${category} request quota`
          : s.level === 'org' ? `its pooled ${LABELS[name][0]}` : `your account-wide ${LABELS[name][0]}`;
      const period = isCat ? periodId.day : periodId[LABELS[name][1]];
      const who = s.level === 'org' ? 'Your organization has used' : "You've used";
      const amount = after >= cap ? 'all' : `${t}%`;
      out.push({
        key: `${s.key}|${name}|${period}|${t}`,
        scope: s.level,
        level: t >= 99 ? 'critical' : t >= 90 ? 'warn' : 'info',
        percent: t,
        text: `${who} ${amount} of ${what} (${after.toLocaleString('en-US')} / ${cap.toLocaleString('en-US')}).`,
      });
    }
  }
  return out;
}

// --- Cost guide ------------------------------------------------------------------
// What a single request costs, so admins can size quotas. Measured from real
// usage (last 30 days, all users) once a category has enough samples;
// otherwise a typical estimate.
const TYPICAL_TOKENS = { general: 300, math: 40, text: 250, coding: 650, cyber: 500, design: 450, data: 500 };
const MIN_SAMPLES = 5;
let guideCache = { at: 0, value: null };

async function costGuide({ maxReplyTokens, maxMessageChars, maxHistoryChars }) {
  if (guideCache.value && Date.now() - guideCache.at < 60000) return guideCache.value;
  const since = new Date(Date.now() - 30 * DAY_MS).toISOString().slice(0, 10);
  const docs = await usage
    .find({ _id: { $regex: /^u:\d+\|D:/ }, ctok: { $exists: true } }, { projection: { _id: 1, cat: 1, ctok: 1 } })
    .toArray();
  const totals = {};
  for (const d of docs) {
    if (d._id.split('|D:')[1] < since) continue;
    for (const [cat, tok] of Object.entries(d.ctok || {})) {
      const t = (totals[cat] = totals[cat] || { requests: 0, tokens: 0 });
      t.tokens += tok;
      t.requests += (d.cat || {})[cat] || 0;
    }
  }
  const systemPrompt = 150; // approx. system prompt tokens sent with LLM requests
  const worstCase = Math.ceil(maxMessageChars / 4) + Math.ceil(maxHistoryChars / 4) + maxReplyTokens + systemPrompt;
  const categories = {};
  for (const [cat, typical] of Object.entries(TYPICAL_TOKENS)) {
    const t = totals[cat];
    const observed = t && t.requests >= MIN_SAMPLES ? Math.round(t.tokens / t.requests) : null;
    categories[cat] = {
      avgTokens: observed !== null ? observed : typical,
      source: observed !== null ? 'observed' : 'estimate',
      samples: t ? t.requests : 0,
    };
  }
  const value = {
    categories,
    localRange: [5, 60], // rules / FAQ answers
    llmRange: [250, Math.min(maxReplyTokens + 300, 1500)], // typical model answers
    worstCase,
    maxReplyTokens,
    note: 'Tokens ≈ characters ÷ 4, counted for the message, any chat history sent, and the reply.',
  };
  guideCache = { at: Date.now(), value };
  return value;
}

/** Usage snapshot for display: today and this month. */
async function summary(subjectKey) {
  const c = await countersFor(subjectKey);
  const pick = (d) => ({
    requests: d.requests || 0,
    tokens: d.tokens || 0,
    byCategory: d.cat || {},
    tokensByCategory: d.ctok || {},
  });
  return { today: pick(c.day), month: pick(c.month) };
}

module.exports = { init, check, record, summary, quotaNotices, costGuide, THRESHOLDS };

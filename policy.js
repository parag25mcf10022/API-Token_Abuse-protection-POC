/**
 * Access policies: content-category scopes + usage limits.
 *
 * A policy can be attached to a user (their key) and to an org (a pool shared
 * by all members). Both are enforced; the stricter one wins.
 *
 *   {
 *     scopes: ['math', 'text', ...] | null,   // null = no restriction at this level
 *     llm: true | false | null,               // may this key use the LLM? (cost control)
 *     limits: {
 *       burstPerMinute, requestsPerDay, requestsPerMonth,
 *       tokensPerDay, tokensPerMonth,         // ≈ characters / 4
 *       categoryRequestsPerDay: { coding: 50, ... }
 *     }                                        // missing/null = unlimited
 *   }
 *
 * Only admins can change policies (super admin for anyone, org admin for
 * their own org's members) — users can never edit their own.
 */

'use strict';

// Content categories a request can fall into (see engine.classify).
const CATEGORIES = {
  general: 'Greetings, help, time/date, questions about this service',
  math: 'Arithmetic and calculations',
  text: 'Text utilities: reverse, upper/lower, echo, count',
  coding: 'Programming, debugging, APIs, tooling',
  cyber: 'Security: vulnerabilities, hardening, threat concepts',
  design: 'UI/UX, colour, typography, layout, branding',
  data: 'Data analysis, statistics, spreadsheets, visualisation',
};
const CATEGORY_NAMES = Object.keys(CATEGORIES);

const LIMIT_FIELDS = [
  'burstPerMinute',
  'requestsPerDay',
  'requestsPerMonth',
  'tokensPerDay',
  'tokensPerMonth',
];
const MAX_LIMIT = 1e9;

// What a brand-new personal account gets until an admin changes it.
const DEFAULT_USER_POLICY = Object.freeze({
  scopes: ['general', 'math', 'text'],
  llm: true,
  limits: {
    burstPerMinute: 30,
    requestsPerDay: 500,
    requestsPerMonth: 5000,
    tokensPerDay: 50000,
    tokensPerMonth: 500000,
    categoryRequestsPerDay: {},
  },
});

/** Rough token estimate (≈4 chars per token), matching common LLM billing. */
function estimateTokens(text) {
  return Math.ceil(String(text || '').length / 4);
}

function isLimit(v) {
  return v === null || (Number.isInteger(v) && v >= 0 && v <= MAX_LIMIT);
}

/**
 * Validate an admin-supplied policy. Returns { ok, policy } with a clean copy
 * (unknown fields dropped), or { ok: false, error }.
 */
function validatePolicy(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, error: 'Policy must be an object.' };
  }
  const out = { scopes: null, llm: null, limits: { categoryRequestsPerDay: {} } };
  if (input.llm !== undefined && input.llm !== null) {
    if (typeof input.llm !== 'boolean') return { ok: false, error: 'llm must be true, false, or null.' };
    out.llm = input.llm;
  }

  if (input.scopes !== undefined && input.scopes !== null) {
    if (!Array.isArray(input.scopes) || input.scopes.some((s) => !CATEGORY_NAMES.includes(s))) {
      return { ok: false, error: `scopes must be an array of: ${CATEGORY_NAMES.join(', ')}.` };
    }
    out.scopes = [...new Set(input.scopes)];
  }

  const limits = input.limits === undefined ? {} : input.limits;
  if (!limits || typeof limits !== 'object' || Array.isArray(limits)) {
    return { ok: false, error: 'limits must be an object.' };
  }
  for (const f of LIMIT_FIELDS) {
    if (limits[f] === undefined) continue;
    if (!isLimit(limits[f])) {
      return { ok: false, error: `${f} must be a non-negative integer or null.` };
    }
    if (limits[f] !== null) out.limits[f] = limits[f];
  }
  const cat = limits.categoryRequestsPerDay;
  if (cat !== undefined && cat !== null) {
    if (typeof cat !== 'object' || Array.isArray(cat)) {
      return { ok: false, error: 'categoryRequestsPerDay must be an object.' };
    }
    for (const [k, v] of Object.entries(cat)) {
      if (!CATEGORY_NAMES.includes(k)) return { ok: false, error: `Unknown category: ${k}.` };
      if (!isLimit(v)) return { ok: false, error: `categoryRequestsPerDay.${k} must be a non-negative integer or null.` };
      if (v !== null) out.limits.categoryRequestsPerDay[k] = v;
    }
  }
  return { ok: true, policy: out };
}

/** Categories the user may use: intersection of user and org scopes. */
function allowedScopes(userPolicy, orgPolicy) {
  let allowed = CATEGORY_NAMES;
  for (const p of [userPolicy, orgPolicy]) {
    if (p && Array.isArray(p.scopes)) allowed = allowed.filter((c) => p.scopes.includes(c));
  }
  return allowed;
}

/**
 * Per-category view for the owner: is each category usable right now, and if
 * not, why? Catches the "allowed but can't use" cases — blocked by the org,
 * a cap of 0, a per-category cap reached, or an overall quota exhausted.
 *
 * @param {object} p  { userPolicy, orgPolicy, userUsage, orgUsage } where
 *                    usage is usage.summary() output ({today, month}).
 */
function categoryStatus({ userPolicy, orgPolicy, userUsage, orgUsage }) {
  const ul = (userPolicy && userPolicy.limits) || {};
  const ol = (orgPolicy && orgPolicy.limits) || {};
  const inScope = (p, cat) => !p || !Array.isArray(p.scopes) || p.scopes.includes(cat);
  const reached = (used, cap) => Number.isInteger(cap) && used >= cap;
  const ut = userUsage.today, um = userUsage.month;
  const ot = orgUsage ? orgUsage.today : null, om = orgUsage ? orgUsage.month : null;

  // Overall quotas that block every category at once.
  let overall = null;
  if (reached(ut.requests, ul.requestsPerDay)) overall = 'daily_requests_used_up';
  else if (reached(um.requests, ul.requestsPerMonth)) overall = 'monthly_requests_used_up';
  else if (reached(ut.tokens, ul.tokensPerDay)) overall = 'daily_tokens_used_up';
  else if (reached(um.tokens, ul.tokensPerMonth)) overall = 'monthly_tokens_used_up';
  else if (ot && reached(ot.requests, ol.requestsPerDay)) overall = 'org_daily_pool_used_up';
  else if (om && reached(om.requests, ol.requestsPerMonth)) overall = 'org_monthly_pool_used_up';
  else if (ot && reached(ot.tokens, ol.tokensPerDay)) overall = 'org_daily_tokens_used_up';

  return CATEGORY_NAMES.map((cat) => {
    const userCap = (ul.categoryRequestsPerDay || {})[cat];
    const orgCap = (ol.categoryRequestsPerDay || {})[cat];
    const caps = [userCap, orgCap].filter(Number.isInteger);
    const cap = caps.length ? Math.min(...caps) : null;
    const used = (ut.byCategory || {})[cat] || 0;
    const orgUsed = ot ? (ot.byCategory || {})[cat] || 0 : 0;

    let status = 'ok';
    if (!inScope(userPolicy, cat)) status = 'not_in_plan';
    else if (!inScope(orgPolicy, cat)) status = 'blocked_by_org';
    else if (cap === 0) status = 'cap_is_zero';
    else if (reached(used, userCap)) status = 'cap_reached';
    else if (reached(orgUsed, orgCap)) status = 'org_cap_reached';
    else if (overall) status = overall;

    return {
      category: cat,
      description: CATEGORIES[cat],
      inPlan: status !== 'not_in_plan' && status !== 'blocked_by_org',
      usable: status === 'ok',
      status,
      cap, // per-category daily cap (null = shares the overall daily quota)
      used,
      remaining: cap === null ? null : Math.max(0, cap - used),
    };
  });
}

/** LLM access needs both the user and org policy to allow it (null = inherit/allow). */
function llmAllowed(userPolicy, orgPolicy) {
  return [userPolicy, orgPolicy].every((p) => !p || p.llm !== false);
}

module.exports = {
  llmAllowed,
  categoryStatus,
  CATEGORIES,
  CATEGORY_NAMES,
  LIMIT_FIELDS,
  DEFAULT_USER_POLICY,
  estimateTokens,
  validatePolicy,
  allowedScopes,
};

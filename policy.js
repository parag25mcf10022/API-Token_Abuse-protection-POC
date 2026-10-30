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
 *       // Per-category quotas — each category is independent:
 *       perCategoryRequestsPerDay,  perCategoryTokensPerDay,   // default for every category
 *       categoryRequestsPerDay: { coding: 50 }, categoryTokensPerDay: { coding: 40000 }, // overrides
 *       // Optional account-wide ceilings — these DO affect all categories:
 *       burstPerMinute, requestsPerDay, requestsPerMonth, tokensPerDay, tokensPerMonth,
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
  text: 'Writing & text: summarize, rewrite, translate, grammar; reverse/upper/lower/count',
  coding: 'Programming, debugging, APIs, tooling',
  cyber: 'Security: vulnerabilities, hardening, threat concepts',
  design: 'UI/UX, colour, typography, layout, branding',
  data: 'Data analysis, statistics, spreadsheets, visualisation',
};
const CATEGORY_NAMES = Object.keys(CATEGORIES);

// Account-wide limits (optional): shared by every category.
const LIMIT_FIELDS = [
  'burstPerMinute',
  'requestsPerDay',
  'requestsPerMonth',
  'tokensPerDay',
  'tokensPerMonth',
];
// Default daily quota applied to EACH category on its own.
const PER_CATEGORY_FIELDS = ['perCategoryRequestsPerDay', 'perCategoryTokensPerDay'];
// Per-category overrides.
const CATEGORY_MAP_FIELDS = ['categoryRequestsPerDay', 'categoryTokensPerDay'];
const MAX_LIMIT = 1e9;

// What a brand-new account gets until an admin changes it. Quotas are per
// category, so using one category never eats into another; the burst limit
// is abuse protection, not a quota.
const DEFAULT_USER_POLICY = Object.freeze({
  scopes: ['general', 'math', 'text'],
  llm: true,
  limits: {
    burstPerMinute: 30,
    // Sized so the two agree: 100 LLM answers (~650 tokens each for coding,
    // the most expensive category) fit in 100k tokens.
    perCategoryRequestsPerDay: 100,
    perCategoryTokensPerDay: 100000,
    categoryRequestsPerDay: {},
    categoryTokensPerDay: {},
  },
});

// The previous default (one shared daily budget for all categories) — policies
// still on it are migrated to DEFAULT_USER_POLICY's per-category limits.
const LEGACY_DEFAULT_LIMITS = {
  burstPerMinute: 30, requestsPerDay: 500, requestsPerMonth: 5000, tokensPerDay: 50000, tokensPerMonth: 500000,
};

/** Effective daily caps for one category under one policy's limits. */
function categoryCaps(limits, cat) {
  const l = limits || {};
  const pick = (map, dflt) => {
    const v = (l[map] || {})[cat];
    return Number.isInteger(v) ? v : Number.isInteger(l[dflt]) ? l[dflt] : null;
  };
  return {
    requests: pick('categoryRequestsPerDay', 'perCategoryRequestsPerDay'),
    tokens: pick('categoryTokensPerDay', 'perCategoryTokensPerDay'),
  };
}

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
  const out = { scopes: null, llm: null, limits: {} };
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
  for (const f of [...LIMIT_FIELDS, ...PER_CATEGORY_FIELDS]) {
    if (limits[f] === undefined) continue;
    if (!isLimit(limits[f])) {
      return { ok: false, error: `${f} must be a non-negative integer or null.` };
    }
    if (limits[f] !== null) out.limits[f] = limits[f];
  }
  for (const field of CATEGORY_MAP_FIELDS) {
    out.limits[field] = {};
    const map = limits[field];
    if (map === undefined || map === null) continue;
    if (typeof map !== 'object' || Array.isArray(map)) {
      return { ok: false, error: `${field} must be an object.` };
    }
    for (const [k, v] of Object.entries(map)) {
      if (!CATEGORY_NAMES.includes(k)) return { ok: false, error: `Unknown category: ${k}.` };
      if (!isLimit(v)) return { ok: false, error: `${field}.${k} must be a non-negative integer or null.` };
      if (v !== null) out.limits[field][k] = v;
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
 * Per-category view for the owner: each category's own daily quota (requests
 * and tokens), usage, and whether it's usable now — and if not, why. Using one
 * category only affects that category; only account-wide or org-pool limits
 * (opt-in) can block everything, and they're reported as such.
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
  const minCap = (...v) => {
    const caps = v.filter(Number.isInteger);
    return caps.length ? Math.min(...caps) : null;
  };

  // Account-wide / org-pool ceilings: only these block every category.
  let ceiling = null;
  if (reached(ut.requests, ul.requestsPerDay)) ceiling = 'account_daily_requests_used_up';
  else if (reached(um.requests, ul.requestsPerMonth)) ceiling = 'account_monthly_requests_used_up';
  else if (reached(ut.tokens, ul.tokensPerDay)) ceiling = 'account_daily_tokens_used_up';
  else if (reached(um.tokens, ul.tokensPerMonth)) ceiling = 'account_monthly_tokens_used_up';
  else if (ot && reached(ot.requests, ol.requestsPerDay)) ceiling = 'org_daily_pool_used_up';
  else if (om && reached(om.requests, ol.requestsPerMonth)) ceiling = 'org_monthly_pool_used_up';
  else if (ot && reached(ot.tokens, ol.tokensPerDay)) ceiling = 'org_daily_tokens_used_up';

  return CATEGORY_NAMES.map((cat) => {
    const uc = categoryCaps(ul, cat);
    const oc = categoryCaps(ol, cat);
    const used = (ut.byCategory || {})[cat] || 0;
    const usedTokens = (ut.tokensByCategory || {})[cat] || 0;
    const orgUsed = ot ? (ot.byCategory || {})[cat] || 0 : 0;
    const orgUsedTokens = ot ? (ot.tokensByCategory || {})[cat] || 0 : 0;
    const cap = minCap(uc.requests, oc.requests);
    const tokenCap = minCap(uc.tokens, oc.tokens);

    let status = 'ok';
    if (!inScope(userPolicy, cat)) status = 'not_in_plan';
    else if (!inScope(orgPolicy, cat)) status = 'blocked_by_org';
    else if (cap === 0 || tokenCap === 0) status = 'cap_is_zero';
    else if (reached(used, uc.requests)) status = 'cap_reached';
    else if (reached(usedTokens, uc.tokens)) status = 'token_cap_reached';
    else if (reached(orgUsed, oc.requests) || reached(orgUsedTokens, oc.tokens)) status = 'org_cap_reached';
    else if (ceiling) status = ceiling;

    return {
      category: cat,
      description: CATEGORIES[cat],
      inPlan: status !== 'not_in_plan' && status !== 'blocked_by_org',
      usable: status === 'ok',
      status,
      cap, // this category's own daily request quota (null = unlimited)
      used,
      remaining: cap === null ? null : Math.max(0, cap - used),
      tokenCap, // this category's own daily token quota (null = unlimited)
      usedTokens,
      tokensRemaining: tokenCap === null ? null : Math.max(0, tokenCap - usedTokens),
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
  categoryCaps,
  PER_CATEGORY_FIELDS,
  CATEGORY_MAP_FIELDS,
  LEGACY_DEFAULT_LIMITS,
  CATEGORIES,
  CATEGORY_NAMES,
  LIMIT_FIELDS,
  DEFAULT_USER_POLICY,
  estimateTokens,
  validatePolicy,
  allowedScopes,
};

/**
 * Lightweight response engine for /api/message.
 *
 * Design goal: feel responsive without being heavy on the server or an LLM.
 *
 *   1. A local rule/command/FAQ engine answers the vast majority of messages
 *      in microseconds, with zero network calls. (Pure string work.)
 *   2. Results are cached by normalized message, so repeats are free.
 *   3. ONLY when the local engine is unsure (low confidence) AND an LLM hook
 *      is configured do we fall back to the LLM — and that answer is cached
 *      too, so a given question costs the LLM at most once.
 *
 * Default: local-only. No LLM, no model, no external calls.
 * Opt in by passing an `llmFallback` async fn (see server.js / README).
 */

'use strict';

// --- tiny LRU-ish cache --------------------------------------------------
const CACHE_MAX = 500;
const cache = new Map(); // normalizedMessage -> { reply, source }

function cacheGet(key) {
  if (!cache.has(key)) return null;
  const val = cache.get(key);
  cache.delete(key); // re-insert to mark as recently used
  cache.set(key, val);
  return val;
}

function cacheSet(key, val) {
  cache.set(key, val);
  if (cache.size > CACHE_MAX) {
    cache.delete(cache.keys().next().value); // evict oldest
  }
}

function normalize(msg) {
  return msg.trim().toLowerCase().replace(/\s+/g, ' ');
}

// --- safe arithmetic (no eval) ------------------------------------------
// Shunting-yard → RPN → evaluate. Supports + - * / ( ) and decimals.
function safeCalc(expr) {
  const tokens = expr.match(/(\d+\.?\d*|[()+\-*/])/g);
  if (!tokens || tokens.join('') !== expr.replace(/\s+/g, '')) return null;
  const prec = { '+': 1, '-': 1, '*': 2, '/': 2 };
  const out = [];
  const ops = [];
  for (const t of tokens) {
    if (/^\d/.test(t)) {
      out.push(parseFloat(t));
    } else if (t === '(') {
      ops.push(t);
    } else if (t === ')') {
      while (ops.length && ops[ops.length - 1] !== '(') out.push(ops.pop());
      if (ops.pop() !== '(') return null; // mismatched parens
    } else {
      while (ops.length && prec[ops[ops.length - 1]] >= prec[t]) out.push(ops.pop());
      ops.push(t);
    }
  }
  while (ops.length) {
    const op = ops.pop();
    if (op === '(') return null;
    out.push(op);
  }
  const stack = [];
  for (const t of out) {
    if (typeof t === 'number') {
      stack.push(t);
    } else {
      const b = stack.pop();
      const a = stack.pop();
      if (a === undefined || b === undefined) return null;
      if (t === '+') stack.push(a + b);
      else if (t === '-') stack.push(a - b);
      else if (t === '*') stack.push(a * b);
      else if (t === '/') stack.push(b === 0 ? NaN : a / b);
    }
  }
  const result = stack.pop();
  if (stack.length || result === undefined || Number.isNaN(result)) return null;
  return result;
}

// --- a small FAQ knowledge base (retrieval by keyword overlap) ----------
const FAQ = [
  {
    keywords: ['api', 'key', 'work', 'how'],
    answer:
      'Your API key is account-bound: it only works while your browser session is active. Log out and the key stops working immediately.',
  },
  {
    keywords: ['session', 'active', 'login', 'log', 'browser'],
    answer:
      'A session is created when you log in on the web app and stored server-side in MongoDB. The API checks for a live session before honoring any request.',
  },
  {
    keywords: ['stolen', 'steal', 'leak', 'safe', 'secure', 'security'],
    answer:
      'Even if your key is stolen, it is useless without an active session for your account — that is the whole point of AAP.',
  },
  {
    keywords: ['disable', 'enable', 'admin', 'toggle', 'revoke'],
    answer:
      'An admin can disable any user\'s key from the admin panel. A disabled key is rejected even if the session is active.',
  },
];

// --- rule handlers -------------------------------------------------------
// Each returns a string (handled), { reply, cache: false } for answers that
// change over time and must not be cached, or null (not my job). Order
// matters: specific commands first, fuzzy/FAQ matching last.
const RULES = [
  // explicit commands: "calc 2+3*4"
  (raw) => {
    const m = raw.match(/^(?:calc|calculate|math|=)\s*(.+)$/i);
    if (!m) return null;
    if (/\/\s*0(?:\.0*)?(?:\D|$)/.test(m[1])) return 'Cannot divide by zero.';
    const r = safeCalc(m[1]);
    return r === null ? "I couldn't parse that as arithmetic." : `${m[1].trim()} = ${r}`;
  },
  // "reverse hello"
  (raw) => {
    const m = raw.match(/^reverse\s+(.+)$/i);
    return m ? [...m[1]].reverse().join('') : null;
  },
  // "upper ..." / "lower ..."
  (raw) => {
    const m = raw.match(/^(upper|lower)\s+(.+)$/i);
    if (!m) return null;
    return m[1].toLowerCase() === 'upper' ? m[2].toUpperCase() : m[2].toLowerCase();
  },
  // "echo ..."
  (raw) => {
    const m = raw.match(/^echo\s+(.+)$/i);
    return m ? m[1] : null;
  },
  // "count ..." → words + chars
  (raw) => {
    const m = raw.match(/^count\s+(.+)$/i);
    if (!m) return null;
    const text = m[1];
    const words = text.split(/\s+/).filter(Boolean).length;
    return `${words} word(s), ${text.length} character(s).`;
  },
  // time / date
  (raw, norm) => {
    if (/\b(what.*time|current time|^time$)\b/.test(norm)) {
      return { reply: `It is ${new Date().toLocaleTimeString()}.`, cache: false };
    }
    if (/\b(what.*date|today.*date|^date$)\b/.test(norm)) {
      return { reply: `Today is ${new Date().toLocaleDateString()}.`, cache: false };
    }
    return null;
  },
  // greetings
  (raw, norm) => {
    if (/^(hi|hello|hey|yo|hiya|good (morning|afternoon|evening))\b/.test(norm)) {
      return 'Hello! Your session is active, so your API key is working. Type "help" to see what I can do.';
    }
    return null;
  },
  // help
  (raw, norm) => {
    if (/^(help|commands|\?|what can you do)\b/.test(norm)) {
      return [
        'I can: calc <expr>, reverse <text>, upper/lower <text>, echo <text>,',
        'count <text>, "what time is it", "what is the date",',
        'and answer questions about API keys, sessions, and security.',
      ].join(' ');
    }
    return null;
  },
  // thanks
  (raw, norm) => (/\b(thanks|thank you|thx|ty)\b/.test(norm) ? "You're welcome!" : null),
];

// --- category knowledge (coding / cyber / design / data) -------------------
// Short, defensive, general-purpose answers so each content category has
// something useful locally. Anything deeper falls through to the optional LLM.
const CATEGORY_KB = [
  { keywords: ['debug', 'bug', 'error', 'exception', 'stack', 'trace'],
    answer: 'Debugging tip: reproduce the bug with the smallest input, read the full stack trace from the top frame in your code, and add a failing test before fixing it.' },
  { keywords: ['regex', 'regular', 'expression', 'pattern'],
    answer: 'Regex tip: anchor patterns with ^ and $, prefer explicit character classes over .*, and test against both matching and non-matching samples.' },
  { keywords: ['api', 'rest', 'endpoint', 'http', 'json'],
    answer: 'API tip: version your endpoints, validate every input server-side, return consistent error shapes, and never put secrets in URLs.' },
  { keywords: ['xss', 'cross', 'site', 'scripting', 'escape', 'sanitize'],
    answer: 'XSS defense: encode output for its context (HTML, attribute, JS, URL), render untrusted data with textContent, and add a strict Content-Security-Policy.' },
  { keywords: ['sql', 'injection', 'nosql', 'query', 'parameterized'],
    answer: 'Injection defense: use parameterized queries, validate input types (strings must be strings), and never build queries by string concatenation.' },
  { keywords: ['password', 'hash', 'hashing', 'bcrypt', 'scrypt', 'argon2'],
    answer: 'Password storage: use a slow, salted KDF such as Argon2id, scrypt, or bcrypt — never plain SHA or MD5 — and rate-limit login attempts.' },
  { keywords: ['phishing', 'malware', 'ransomware', 'threat', 'incident'],
    answer: 'Incident basics: isolate affected systems, rotate exposed credentials and API keys, preserve logs for analysis, and notify your security team.' },
  { keywords: ['color', 'colour', 'palette', 'contrast', 'accessible', 'accessibility'],
    answer: 'Colour tip: keep body text contrast at least 4.5:1 (WCAG AA), limit the palette to a few roles (primary, accent, neutral), and never rely on colour alone.' },
  { keywords: ['font', 'typography', 'typeface', 'heading', 'readability'],
    answer: 'Typography tip: use one or two typefaces, a consistent type scale, 45–75 characters per line, and a line height around 1.4–1.6 for body text.' },
  { keywords: ['layout', 'grid', 'spacing', 'responsive', 'whitespace'],
    answer: 'Layout tip: build on a consistent spacing scale (e.g. 4/8 px), align to a grid, and design mobile-first so content reflows gracefully.' },
  { keywords: ['average', 'mean', 'median', 'statistics', 'outlier'],
    answer: 'Stats tip: report the median alongside the mean when data is skewed, and check for outliers before drawing conclusions.' },
  { keywords: ['csv', 'spreadsheet', 'dataset', 'clean', 'cleaning'],
    answer: 'Data cleaning tip: standardize types and units first, handle missing values explicitly, and keep the raw data untouched alongside the cleaned copy.' },
  { keywords: ['chart', 'graph', 'visualization', 'visualisation', 'plot'],
    answer: 'Chart tip: pick the chart for the question — bars to compare, lines for trends over time — start bar axes at zero, and label units.' },
];

// --- content classification -----------------------------------------------
// Decides which content category (scope) a message belongs to, BEFORE it is
// processed, so the API can enforce per-key scopes and per-category limits.
const CATEGORY_KEYWORDS = {
  coding: ['code', 'coding', 'program', 'programming', 'function', 'bug', 'debug', 'error',
    'exception', 'stack', 'compile', 'javascript', 'typescript', 'python', 'java', 'golang',
    'rust', 'node', 'regex', 'api', 'endpoint', 'json', 'git', 'sql', 'class', 'variable',
    'algorithm', 'refactor', 'library', 'framework'],
  cyber: ['security', 'secure', 'vulnerability', 'vulnerabilities', 'xss', 'csrf', 'injection',
    'exploit', 'malware', 'phishing', 'ransomware', 'encryption', 'encrypt', 'firewall',
    'pentest', 'cve', 'threat', 'attack', 'hash', 'hashing', 'tls', 'ssl', 'auth',
    'authentication', 'sanitize', 'incident', 'breach', 'bcrypt', 'argon2', 'scrypt'],
  design: ['design', 'ui', 'ux', 'color', 'colour', 'palette', 'font', 'typography',
    'typeface', 'layout', 'logo', 'figma', 'branding', 'icon', 'contrast', 'grid',
    'spacing', 'responsive', 'wireframe', 'mockup', 'accessibility'],
  data: ['data', 'dataset', 'csv', 'spreadsheet', 'excel', 'statistics', 'stats', 'average',
    'mean', 'median', 'chart', 'graph', 'plot', 'visualization', 'visualisation',
    'analytics', 'regression', 'correlation', 'outlier'],
};

const TEXT_COMMAND = /^(reverse|upper|lower|echo|count)\s+/i;
const MATH_COMMAND = /^(?:calc|calculate|math|=)\s*/i;
const GENERAL_RULE = /^(hi|hello|hey|yo|hiya|good (morning|afternoon|evening)|help|commands|\?|what can you do)\b|\b(what.*time|current time|what.*date|today.*date|thanks|thank you|thx)\b|^(time|date)$/;

/** Return the content category for a message (one of policy.CATEGORY_NAMES). */
function classify(message) {
  const raw = String(message || '').trim();
  const norm = normalize(raw);
  if (MATH_COMMAND.test(raw)) return 'math';
  if (TEXT_COMMAND.test(raw)) return 'text';
  if (GENERAL_RULE.test(norm)) return 'general';
  if (faqMatch(norm, FAQ)) return 'general'; // questions about this service
  const words = new Set(norm.match(/[a-z0-9]+/g) || []);
  let best = 'general';
  let bestHits = 0;
  for (const [cat, kws] of Object.entries(CATEGORY_KEYWORDS)) {
    const hits = kws.filter((k) => words.has(k)).length;
    if (hits > bestHits) {
      best = cat;
      bestHits = hits;
    }
  }
  return best;
}

/** Try the local FAQ by keyword overlap; returns {answer, score} best match. */
function faqMatch(norm, entries = FAQ) {
  // Tokenize on word chars so trailing punctuation ("stolen?") still matches.
  const words = new Set(norm.match(/[a-z0-9]+/g) || []);
  let best = null;
  for (const item of entries) {
    const hits = item.keywords.filter((k) => words.has(k)).length;
    if (hits >= 2 && (!best || hits > best.score)) best = { answer: item.answer, score: hits };
  }
  return best;
}

/**
 * Generate a reply.
 * @param {string} message
 * @param {object} [opts]
 * @param {function(string):Promise<string>} [opts.llmFallback] optional async LLM
 * @returns {Promise<{reply:string, source:string}>}
 *   source ∈ "rule" | "faq" | "cache" | "llm" | "fallback"
 */
async function generate(message, opts = {}) {
  const raw = String(message || '').trim();
  if (!raw) return { reply: 'Say something and I will respond.', source: 'fallback' };

  const norm = normalize(raw);

  // 1. cache (covers both prior local + prior LLM answers)
  const cached = cacheGet(norm);
  if (cached) return { reply: cached.reply, source: 'cache' };

  // 2. local rules (cheap, deterministic)
  for (const rule of RULES) {
    const out = rule(raw, norm);
    if (out) {
      const reply = typeof out === 'string' ? out : out.reply;
      if (out.cache !== false) cacheSet(norm, { reply, source: 'rule' });
      return { reply, source: 'rule' };
    }
  }

  // 3. local FAQ retrieval
  const faq = faqMatch(norm, FAQ) || faqMatch(norm, CATEGORY_KB);
  if (faq) {
    cacheSet(norm, { reply: faq.answer, source: 'faq' });
    return { reply: faq.answer, source: 'faq' };
  }

  // 4. low confidence → optional LLM fallback (only if configured), cached
  if (typeof opts.llmFallback === 'function') {
    try {
      const reply = await opts.llmFallback(raw);
      if (reply) {
        cacheSet(norm, { reply, source: 'llm' });
        return { reply, source: 'llm' };
      }
    } catch (e) {
      // fall through to local fallback on any LLM error
    }
  }

  // 5. cheap reflective fallback — no LLM needed
  const reply = `I don't have a canned answer for that. You said: "${raw}". Type "help" for what I can do.`;
  cacheSet(norm, { reply, source: 'fallback' });
  return { reply, source: 'fallback' };
}

module.exports = { generate, classify, safeCalc, _cache: cache };

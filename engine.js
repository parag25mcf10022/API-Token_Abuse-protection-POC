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
 * With an LLM provider (llm.js, local Ollama by default), questions the
 * local engine can't answer are streamed from the model; rules and product
 * questions always stay local.
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
  // natural arithmetic: "15% of 80", "what is 12 * 7", "how much is (3+4)*2?"
  (raw) => {
    const pct = raw.match(/(\d+(?:\.\d+)?)\s*%\s*of\s*(\d+(?:\.\d+)?)/i);
    if (pct) {
      const r = (Number(pct[1]) / 100) * Number(pct[2]);
      return `${pct[1]}% of ${pct[2]} = ${Number(r.toFixed(10))}`;
    }
    const m = raw.match(/^(?:what(?:'s|s| is)|compute|calculate|evaluate|how much is)\s+([\d\s.+\-*\/()×÷]+?)\s*\??$/i);
    if (!m || !/\d\s*[-+*\/×÷]\s*\(?\d/.test(m[1])) return null;
    const expr = m[1].replace(/×/g, '*').replace(/÷/g, '/').trim();
    if (/\/\s*0(?:\.0*)?(?:\D|$)/.test(expr)) return 'Cannot divide by zero.';
    const r = safeCalc(expr);
    return r === null ? null : `${expr} = ${r}`;
  },
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
  coding: ['code', 'coding', 'program', 'programming', 'function', 'functions', 'bug', 'debug',
    'error', 'exception', 'stack', 'compile', 'javascript', 'typescript', 'python', 'java', 'golang',
    'rust', 'node', 'regex', 'api', 'endpoint', 'json', 'git', 'sql', 'class', 'variable',
    'algorithm', 'refactor', 'library', 'framework', 'css', 'html', 'div', 'react', 'recursion',
    'loop', 'array', 'script', 'bash', 'docker', 'npm', 'php', 'kotlin', 'swift', 'c++', 'compiler'],
  cyber: ['security', 'secure', 'vulnerability', 'vulnerabilities', 'xss', 'csrf', 'injection',
    'exploit', 'malware', 'phishing', 'ransomware', 'encryption', 'encrypt', 'firewall',
    'pentest', 'cve', 'threat', 'attack', 'hash', 'hashing', 'tls', 'ssl', 'auth',
    'authentication', 'sanitize', 'incident', 'breach', 'bcrypt', 'argon2', 'scrypt', 'trust',
    'mfa', '2fa', 'vpn', 'ddos', 'owasp'],
  design: ['design', 'ui', 'ux', 'color', 'colour', 'palette', 'font', 'fonts', 'typography',
    'typeface', 'layout', 'logo', 'figma', 'branding', 'icon', 'contrast', 'grid',
    'spacing', 'responsive', 'wireframe', 'mockup', 'accessibility', 'portfolio'],
  data: ['data', 'dataset', 'csv', 'spreadsheet', 'excel', 'statistics', 'stats', 'average',
    'mean', 'median', 'mode', 'chart', 'graph', 'plot', 'visualization', 'visualisation',
    'analytics', 'regression', 'correlation', 'outlier', 'deviation', 'variance', 'percentile',
    'distribution', 'pandas'],
  math: ['math', 'maths', 'mathematics', 'solve', 'equation', 'equations', 'calculate',
    'calculation', 'percent', 'percentage', 'sum', 'multiply', 'divide', 'divided', 'plus',
    'minus', 'times', 'sqrt', 'root', 'square', 'integral', 'derivative', 'algebra', 'geometry',
    'area', 'volume', 'fraction', 'fractions', 'radius', 'perimeter', 'factorial', 'prime'],
  text: ['summarize', 'summarise', 'summary', 'rewrite', 'paraphrase', 'rephrase', 'grammar',
    'proofread', 'translate', 'translation', 'spelling', 'essay', 'sentence', 'paragraph',
    'tone', 'formally', 'shorten', 'wording', 'letter', 'email', 'headline', 'caption'],
};

// Ties go to the more specific category ("prevent sql injection" → cyber).
const CATEGORY_PRIORITY = ['cyber', 'design', 'data', 'math', 'text', 'coding'];

// Arithmetic written inline: "12 * 7", "2x + 5 = 11", "15% of 80".
const MATH_EXPR = /\d\s*[-+*\/^×÷=]\s*\(?\d|\d+(\.\d+)?\s*%\s*of\s*\d/;

const TEXT_COMMAND = /^(reverse|upper|lower|echo|count)\s+/i;
const MATH_COMMAND = /^(?:calc|calculate|math|=)\s*/i;
const GENERAL_RULE = /^(hi|hello|hey|yo|hiya|good (morning|afternoon|evening)|help|commands|\?|what can you do)\b|\b(what.*time|current time|what.*date|today.*date|thanks|thank you|thx)\b|^(time|date)$/;

/** Category of a single message, plus whether it had real evidence. */
function classifyOne(message) {
  const raw = String(message || '').trim();
  const norm = normalize(raw);
  if (MATH_COMMAND.test(raw)) return { cat: 'math', evidence: true };
  if (TEXT_COMMAND.test(raw)) return { cat: 'text', evidence: true };
  if (GENERAL_RULE.test(norm)) return { cat: 'general', evidence: true };
  if (faqMatch(norm, FAQ)) return { cat: 'general', evidence: true }; // questions about this service
  const words = new Set(norm.match(/[a-z0-9+]+/g) || []);
  const hits = Object.fromEntries(
    Object.entries(CATEGORY_KEYWORDS).map(([cat, kws]) => [cat, kws.filter((k) => words.has(k)).length])
  );
  if (MATH_EXPR.test(raw)) hits.math += 2; // an inline expression is strong evidence
  let best = 'general';
  let bestHits = 0;
  for (const cat of CATEGORY_PRIORITY) {
    if (hits[cat] > bestHits) {
      best = cat;
      bestHits = hits[cat];
    }
  }
  return { cat: best, evidence: bestHits > 0 };
}

// A short message that points back at the conversation ("explain it more",
// "what about the second one?", "again but shorter").
const FOLLOW_UP = /^(and|also|now|then|so|ok|okay|what about|how about|why|again)\b|\b(it|that|this|those|these|them|same|previous|above|again|more|shorter|simpler|longer)\b/;

/**
 * Return the content category for a message (one of policy.CATEGORY_NAMES).
 * With conversation history, a short follow-up that has no category of its
 * own inherits the category of the latest user turn that had one. History is
 * client-supplied, so only genuine follow-ups inherit — "tell me a joke"
 * stays "general" no matter what came before.
 */
function classify(message, history = []) {
  const own = classifyOne(message);
  if (own.evidence || !Array.isArray(history) || !history.length) return own.cat;
  const norm = normalize(String(message || ''));
  if (norm.length > 80 || !FOLLOW_UP.test(norm)) return own.cat;
  for (let i = history.length - 1; i >= 0; i--) {
    const turn = history[i];
    if (!turn || turn.role !== 'user') continue;
    const prev = classifyOne(turn.content);
    if (prev.evidence && prev.cat !== 'general') return prev.cat;
  }
  return own.cat;
}

/** Try the local FAQ by keyword overlap; returns {answer, score} best match. */
// Product FAQ needs 3 keyword hits (its keywords are generic, e.g. "api",
// "key" — two of them shouldn't hijack a coding question); category tips use
// distinctive keywords ("xss", "regex"), so 1 hit is enough.
function faqMatch(norm, entries = FAQ, minHits = 3) {
  // Tokenize on word chars so trailing punctuation ("stolen?") still matches.
  const words = new Set(norm.match(/[a-z0-9]+/g) || []);
  let best = null;
  for (const item of entries) {
    const hits = item.keywords.filter((k) => words.has(k)).length;
    if (hits >= minHits && (!best || hits > best.score)) best = { answer: item.answer, score: hits };
  }
  return best;
}

/**
 * Generate a reply.
 *
 * Order: cache → deterministic rules → product FAQ (all local, instant) →
 * LLM (if allowed and available; streamed) → local category tips → fallback.
 *
 * @param {string} message
 * @param {object} [opts]
 * @param {object} [opts.llm]       provider with chat({category, history, message, onDelta})
 * @param {string} [opts.category]  content category (from classify)
 * @param {Array}  [opts.history]   prior turns [{role, content}] for multi-turn chat
 * @param {function(string)} [opts.onDelta] receives streamed text
 * @returns {Promise<{reply, source, model?, usage?}>}
 *   source ∈ "rule" | "faq" | "cache" | "llm" | "fallback"
 */
async function generate(message, opts = {}) {
  const raw = String(message || '').trim();
  if (!raw) return { reply: 'Say something and I will respond.', source: 'fallback' };

  const norm = normalize(raw);
  const history = Array.isArray(opts.history) ? opts.history : [];
  // Conversation context changes the answer, so only single-turn requests
  // read from / write to the shared cache.
  const cacheable = history.length === 0;

  // 1. cache (covers both prior local + prior LLM answers)
  if (cacheable) {
    const cached = cacheGet(norm);
    if (cached) return { reply: cached.reply, source: 'cache' };
  }

  // 2. local rules (cheap, deterministic)
  for (const rule of RULES) {
    const out = rule(raw, norm);
    if (out) {
      const reply = typeof out === 'string' ? out : out.reply;
      if (out.cache !== false) cacheSet(norm, { reply, source: 'rule' });
      return { reply, source: 'rule' };
    }
  }

  // 3. questions about this service — answered locally, always accurate
  const faq = faqMatch(norm, FAQ);
  if (faq) {
    cacheSet(norm, { reply: faq.answer, source: 'faq' });
    return { reply: faq.answer, source: 'faq' };
  }

  // 4. LLM (streamed). Falls through to local answers on any failure.
  if (opts.llm) {
    try {
      const out = await opts.llm.chat({
        category: opts.category || classify(raw),
        history,
        message: raw,
        onDelta: opts.onDelta,
      });
      if (cacheable) cacheSet(norm, { reply: out.reply, source: 'llm' });
      return { reply: out.reply, source: 'llm', model: out.model, usage: out.usage, truncated: !!out.truncated };
    } catch (e) {
      // LLM down/slow → local tips or fallback below
    }
  }

  // 5. local category tips (coding / cyber / design / data)
  const tip = faqMatch(norm, CATEGORY_KB, 1);
  if (tip) {
    if (cacheable) cacheSet(norm, { reply: tip.answer, source: 'faq' });
    return { reply: tip.answer, source: 'faq' };
  }

  // 6. cheap reflective fallback
  const reply = `I don't have a canned answer for that. You said: "${raw}". Type "help" for what I can do.`;
  return { reply, source: 'fallback' };
}

module.exports = { generate, classify, safeCalc, _cache: cache };

/**
 * Account-Bound API Key Protection (AAP) — demo server.
 *
 * One Express process plays three roles:
 *   1. Web app   — sign up / log in, dashboard showing the user's API key.
 *   2. API server — POST /api/message, honored ONLY if the key's owner has a
 *                   live browser session.
 *   3. Auth bridge — GET /auth/session-status, polled by the shell client.
 *
 * The whole point: an API key is account-bound. Stealing the key is not
 * enough — the attacker also needs an active authenticated session for that
 * account, and sessions live in a server-side, queryable store.
 *
 * Storage: MongoDB, database "AAP" (users + sessions), inspectable in Compass.
 */

const crypto = require('crypto');
const path = require('path');
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;

const db = require('./db');
const engine = require('./engine');
const security = require('./security');
const { createLimiter, limit, tooMany } = require('./rateLimit');

// Optional LLM fallback for messages the local engine can't confidently
// answer. Disabled unless you wire one up (kept null here so the demo makes
// ZERO model calls by default). See README for how to plug in Claude with
// prompt caching. Results are cached by the engine, so the LLM is hit at most
// once per unique message.
const llmFallback = null;

const PORT = process.env.PORT || 3000;

// Sessions expire after 30 min idle (sliding), and after 8 h no matter what.
const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;

async function main() {
  // Connect to MongoDB ("AAP") before wiring up anything that needs it.
  await db.connect();

  const app = express();
  app.disable('x-powered-by');
  // Output encoding for every JSON response: <, >, & are emitted as \u003c,
  // \u003e, \u0026. Values decode identically, but a response can never be
  // parsed as markup even if it ends up somewhere it shouldn't.
  app.set('json escape', true);
  app.use(security.securityHeaders);
  app.use(express.json({ limit: '10kb' }));
  // Behind a TLS-terminating proxy, set TRUST_PROXY=1 so req.secure (and the
  // Secure cookie flag) reflect the original HTTPS request.
  if (process.env.TRUST_PROXY) app.set('trust proxy', 1);

  // --- Session store -----------------------------------------------------
  // connect-mongo persists sessions in the SAME "AAP" database (collection
  // "sessions"), reusing the MongoClient from db.js. Crucially it exposes
  // `.all()`, letting us *query* every live session and ask "does the owner
  // of this API key currently have one?". That queryability is what makes
  // account-binding possible — and you can watch the collection in Compass.
  const sessionStore = MongoStore.create({
    client: db.getClient(),
    dbName: db.getDbName(),
    collectionName: 'sessions',
    ttl: SESSION_IDLE_MS / 1000, // seconds — matches the cookie maxAge below
    // Store sessions as real sub-documents (not JSON strings) so we can query
    // and index `session.userId` directly instead of scanning every session.
    stringify: false,
  });
  await db.getClient()
    .db(db.getDbName())
    .collection('sessions')
    .createIndex({ 'session.userId': 1 });

  app.use(
    session({
      name: 'aap.sid',
      // From SESSION_SECRET, or a random secret generated once and persisted
      // in the DB — never a hard-coded value.
      secret: process.env.SESSION_SECRET || (await db.getOrCreateSecret('sessionSecret')),
      store: sessionStore,
      resave: false,
      saveUninitialized: false,
      // Re-issue the cookie on every response so the browser's expiry slides
      // in step with the server-side session (no zombie sessions that the
      // server still honors after the browser has dropped the cookie).
      rolling: true,
      cookie: {
        httpOnly: true, // not readable from JS — mitigates XSS token theft
        sameSite: 'lax',
        secure: 'auto', // Secure flag whenever the request arrived over HTTPS
        maxAge: SESSION_IDLE_MS,
      },
    })
  );

  // Enforce the absolute lifetime: a session older than 8 h is destroyed even
  // if it has been continuously active.
  app.use((req, res, next) => {
    const s = req.session;
    if (s && s.userId && !(s.createdAt > Date.now() - SESSION_ABSOLUTE_MS)) {
      return s.destroy(() => next());
    }
    next();
  });

  // --- Core binding check ------------------------------------------------
  const sessionsCol = db.getClient().db(db.getDbName()).collection('sessions');

  /**
   * Returns a Promise<boolean>: is there at least one live session whose
   * userId matches the given user? This is the heart of AAP — it reaches into
   * the session store and answers the "is the browser logged in?" question for
   * an arbitrary account, independent of who is calling the API.
   *
   * Indexed lookup on `session.userId`; `expires` is maintained by
   * connect-mongo from the cookie expiry, so stale sessions never count.
   */
  // A session counts as live if it hasn't hit its idle expiry AND is within
  // the absolute lifetime.
  const liveSessionQuery = (userId) => ({
    'session.userId': userId,
    'session.createdAt': { $gt: Date.now() - SESSION_ABSOLUTE_MS },
    expires: { $gt: new Date() },
  });

  async function userHasActiveSession(userId) {
    const doc = await sessionsCol.findOne(liveSessionQuery(userId), {
      projection: { _id: 1 },
    });
    return !!doc;
  }

  /** How many live sessions (browsers/devices) the account currently has. */
  function countActiveSessions(userId) {
    return sessionsCol.countDocuments(liveSessionQuery(userId));
  }

  // Express 4 doesn't catch rejected promises from async handlers — the
  // request would hang. Route errors to the error middleware instead.
  const wrap = (fn) => (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);


  // Start a fresh session ID on authentication (prevents session fixation).
  function startSession(req, userId) {
    return new Promise((resolve, reject) => {
      req.session.regenerate((err) => {
        if (err) return reject(err);
        req.session.userId = userId;
        req.session.createdAt = Date.now(); // for the absolute lifetime
        req.session.save((err2) => (err2 ? reject(err2) : resolve()));
      });
    });
  }

  function requireLogin(req, res, next) {
    if (!req.session || !req.session.userId) {
      return res.status(401).json({ error: 'Not logged in' });
    }
    next();
  }

  const requireAdmin = wrap(async (req, res, next) => {
    const user = req.session && (await db.getUserById(req.session.userId));
    if (!user || !user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  });

  function maskEmail(email) {
    const [name, domain] = email.split('@');
    const shown = name.slice(0, 2);
    return `${shown}${'*'.repeat(Math.max(1, name.length - 2))}@${domain}`;
  }

  // --- Rate limits ---------------------------------------------------------
  const MIN = 60 * 1000;
  const limits = {
    // Failed logins per (IP, email): blocks password guessing on one account.
    loginFail: createLimiter({ windowMs: 15 * MIN, max: 5 }),
    // All login attempts per IP: blocks spraying many accounts.
    loginIp: createLimiter({ windowMs: 15 * MIN, max: 30 }),
    signupIp: createLimiter({ windowMs: 60 * MIN, max: 5 }),
    // CLI polls every 2 s (30/min); leave headroom.
    statusIp: createLimiter({ windowMs: MIN, max: 60 }),
    messageIp: createLimiter({ windowMs: MIN, max: 120 }),
    // Per account, so a stolen key can't be hammered from many IPs.
    messageUser: createLimiter({ windowMs: MIN, max: 60 }),
  };
  const byIp = (req) => req.ip;

  // =======================================================================
  // AUTH / WEB APP
  // =======================================================================

  app.post('/auth/signup', limit(limits.signupIp, byIp), wrap(async (req, res) => {
    const { email, password } = req.body || {};
    const cleanEmail = security.cleanEmail(email);
    if (!cleanEmail.ok) {
      return res.status(400).json({ error: cleanEmail.error });
    }
    if (!security.isPassword(password)) {
      return res.status(400).json({
        error: `Password is required (max ${security.LIMITS.password} characters).`,
      });
    }
    let user;
    try {
      user = await db.createUser(cleanEmail.value, password);
    } catch (e) {
      return res.status(409).json({ error: e.message });
    }
    await startSession(req, user.id);
    res.json({ email: user.email, apiKey: user.apiKey, isAdmin: user.isAdmin });
  }));

  app.post('/auth/login', limit(limits.loginIp, byIp), wrap(async (req, res) => {
    const { email, password } = req.body || {};
    const cleanEmail = security.cleanEmail(email);
    if (!cleanEmail.ok || !security.isPassword(password)) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    // Locked out after too many failures — checked BEFORE the password, so a
    // correct guess during the lockout is rejected too.
    const failKey = `${req.ip}|${cleanEmail.value}`;
    const lock = limits.loginFail.blocked(failKey);
    if (lock.blocked) return tooMany(res, lock.retryAfterSec);

    const user = await db.getUserByEmail(cleanEmail.value);
    if (!user || !db.verifyPassword(password, user.passwordHash)) {
      limits.loginFail.hit(failKey);
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    limits.loginFail.reset(failKey);
    await startSession(req, user.id);
    res.json({ email: user.email, apiKey: user.apiKey, isAdmin: user.isAdmin });
  }));

  app.post('/auth/logout', (req, res) => {
    // Ends THIS browser's session. The key stops working once no other
    // session for the account is live (see /auth/logout-all).
    req.session.destroy(() => {
      res.clearCookie('aap.sid');
      res.json({ ok: true });
    });
  });

  // Ends EVERY session for the account (all browsers/devices), so the API
  // key stops working immediately.
  app.post('/auth/logout-all', requireLogin, wrap(async (req, res) => {
    const { deletedCount } = await sessionsCol.deleteMany({
      'session.userId': req.session.userId,
    });
    res.clearCookie('aap.sid');
    res.json({ ok: true, sessionsEnded: deletedCount });
  }));

  // Used by the dashboard to load the current user's info.
  app.get('/auth/me', requireLogin, wrap(async (req, res) => {
    const user = await db.getUserById(req.session.userId);
    if (!user) return res.status(401).json({ error: 'Not logged in' });
    res.json({
      email: user.email,
      apiKey: user.apiKey,
      keyEnabled: user.keyEnabled,
      isAdmin: user.isAdmin,
      activeSessions: await countActiveSessions(user.id),
    });
  }));

  // =======================================================================
  // AUTH BRIDGE — polled by the shell client
  // =======================================================================

  // The CLI asks "is the account that owns this key currently logged in?"
  // It purposely does NOT require the caller to be logged in (the CLI has no
  // cookie). It only reveals a boolean (+ masked email), never the key.
  app.get('/auth/session-status', limit(limits.statusIp, byIp), wrap(async (req, res) => {
    const apiKey = req.query.api_key;
    // Must be a well-formed key string — `?api_key[$ne]=x` parses to an
    // object and would otherwise be passed to MongoDB as a query operator.
    if (apiKey === undefined) {
      return res.status(400).json({ error: 'api_key query param required' });
    }
    if (!security.isApiKey(apiKey)) {
      // Same answer as an unknown key — don't reveal what's malformed.
      return res.json({ active: false });
    }
    const user = await db.getUserByApiKey(apiKey);
    if (!user) {
      // Don't leak whether a key exists; just report "no session".
      return res.json({ active: false });
    }
    const active = await userHasActiveSession(user.id);
    res.json({
      active: active && user.keyEnabled,
      keyEnabled: user.keyEnabled,
      email: maskEmail(user.email),
    });
  }));

  // =======================================================================
  // API SERVER — the account-bound, protected endpoint
  // =======================================================================

  app.post('/api/message', limit(limits.messageIp, byIp), wrap(async (req, res) => {
    const { api_key, message } = req.body || {};
    if (api_key === undefined || message === undefined) {
      return res.status(400).json({ error: 'api_key and message are required.' });
    }
    const msg = security.cleanText(message, 'message', security.LIMITS.message);
    if (!msg.ok) {
      return res.status(400).json({ error: msg.error });
    }

    // 1. Which user owns this key? Only well-formed key strings reach the
    // DB — an object like {"$ne": null} would act as a MongoDB operator.
    const user = security.isApiKey(api_key)
      ? await db.getUserByApiKey(api_key)
      : null;
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized: invalid API key' });
    }

    // 2. Has an admin disabled this key?
    if (!user.keyEnabled) {
      return res.status(403).json({ error: 'Forbidden: API key is disabled' });
    }

    // Per-account quota, regardless of which IP the key is used from.
    const quota = limits.messageUser.hit(user.id);
    if (!quota.allowed) return tooMany(res, quota.retryAfterSec);

    // 3. THE AAP CHECK — is the owner's browser session active right now?
    const active = await userHasActiveSession(user.id);
    if (!active) {
      return res
        .status(401)
        .json({ error: 'Unauthorized: No active session found' });
    }

    // 4. Session is live → run the lightweight response engine.
    const { reply, source } = await engine.generate(msg.value, {
      llmFallback: llmFallback || undefined,
    });
    res.json({
      reply,
      source, // "rule" | "faq" | "cache" | "llm" | "fallback" — handy for the demo
      processedAt: new Date().toISOString(),
    });
  }));

  // =======================================================================
  // ADMIN PANEL (bonus)
  // =======================================================================

  app.get('/api/admin/users', requireLogin, requireAdmin, wrap(async (req, res) => {
    const out = [];
    for (const u of await db.listUsers()) {
      out.push({
        id: u.id,
        email: u.email,
        apiKey: u.apiKey,
        keyEnabled: u.keyEnabled,
        isAdmin: u.isAdmin,
        hasActiveSession: await userHasActiveSession(u.id),
      });
    }
    res.json({ users: out });
  }));

  app.post('/api/admin/toggle-key', requireLogin, requireAdmin, wrap(async (req, res) => {
    const { userId, enabled } = req.body || {};
    if (!Number.isInteger(userId) || typeof enabled !== 'boolean') {
      return res.status(400).json({ error: 'userId (integer) and enabled (boolean) are required.' });
    }
    try {
      const state = await db.setKeyEnabled(userId, enabled);
      res.json({ userId, keyEnabled: state });
    } catch (e) {
      res.status(404).json({ error: e.message });
    }
  }));

  // --- Static frontend ----------------------------------------------------
  app.use(express.static(path.join(__dirname, 'public')));

  // --- Error handler ------------------------------------------------------
  // Catches errors forwarded by wrap() (and malformed JSON bodies) so the
  // client always gets a response instead of a hung request.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err.type === 'entity.parse.failed') {
      return res.status(400).json({ error: 'Malformed JSON body.' });
    }
    if (err.expose && err.status >= 400 && err.status < 500) {
      // Client errors from body-parser (e.g. 413 body too large).
      return res.status(err.status).json({ error: err.message });
    }
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  });

  // --- Seed a demo admin + a normal user (idempotent) ---------------------
  // Demo accounts are pre-approved; real signups need an admin to enable them.
  // Passwords come from env vars, or are generated randomly and printed ONCE
  // when the account is created — never hard-coded or published.
  const seeded = [
    await seedAccount(
      process.env.ADMIN_EMAIL || 'admin@example.com',
      process.env.ADMIN_PASSWORD,
      { isAdmin: true, keyEnabled: true }
    ),
    await seedAccount(
      process.env.DEMO_USER_EMAIL || 'user@example.com',
      process.env.DEMO_USER_PASSWORD,
      { keyEnabled: true }
    ),
  ];

  app.listen(PORT, () => {
    console.log(`\nAAP demo running → http://localhost:${PORT}`);
    console.log(`MongoDB: database "${db.getDbName()}"`);
    const fresh = seeded.filter((s) => s.generatedPassword);
    if (fresh.length) {
      console.log('\nGenerated credentials (shown once — save them now):');
      for (const s of fresh) {
        console.log(`  ${s.email} / ${s.generatedPassword}${s.isAdmin ? '  (admin)' : ''}`);
      }
    }
    console.log('');
  });
}

// Passwords that older versions of this demo seeded and published in the
// README. Any account still using one is rotated on boot.
const LEGACY_DEFAULT_PASSWORDS = ['admin123', 'user123'];

function randomPassword() {
  return crypto.randomBytes(12).toString('base64url');
}

/**
 * Create the account if missing. If it exists but still has a legacy
 * published password, rotate it. Returns the plaintext password only when
 * it was generated here (so it can be shown once), never otherwise.
 */
async function seedAccount(email, envPassword, opts) {
  const existing = await db.getUserByEmail(email);
  if (!existing) {
    const password = envPassword || randomPassword();
    await db.createUser(email, password, opts);
    return { email, isAdmin: !!opts.isAdmin, generatedPassword: envPassword ? null : password };
  }
  const legacy = LEGACY_DEFAULT_PASSWORDS.some((p) =>
    db.verifyPassword(p, existing.passwordHash)
  );
  if (legacy) {
    const password = envPassword || randomPassword();
    await db.setPassword(existing.id, password);
    console.warn(`Rotated published default password for ${email}.`);
    return { email, isAdmin: existing.isAdmin, generatedPassword: envPassword ? null : password };
  }
  return { email, isAdmin: existing.isAdmin, generatedPassword: null };
}

main().catch((err) => {
  console.error('Failed to start AAP server:', err.message);
  console.error('Is MongoDB running and reachable (MONGO_URL)?');
  process.exit(1);
});

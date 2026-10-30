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

const path = require('path');
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;

const db = require('./db');
const engine = require('./engine');

// Optional LLM fallback for messages the local engine can't confidently
// answer. Disabled unless you wire one up (kept null here so the demo makes
// ZERO model calls by default). See README for how to plug in Claude with
// prompt caching. Results are cached by the engine, so the LLM is hit at most
// once per unique message.
const llmFallback = null;

const PORT = process.env.PORT || 3000;

async function main() {
  // Connect to MongoDB ("AAP") before wiring up anything that needs it.
  await db.connect();

  const app = express();
  app.use(express.json());

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
    ttl: 30 * 60, // seconds — matches the cookie maxAge below
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
      secret: process.env.SESSION_SECRET || 'demo-only-not-secret',
      store: sessionStore,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true, // not readable from JS — mitigates XSS token theft
        sameSite: 'lax',
        maxAge: 1000 * 60 * 30, // 30 min
      },
    })
  );

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
  async function userHasActiveSession(userId) {
    const doc = await sessionsCol.findOne(
      { 'session.userId': userId, expires: { $gt: new Date() } },
      { projection: { _id: 1 } }
    );
    return !!doc;
  }

  // Express 4 doesn't catch rejected promises from async handlers — the
  // request would hang. Route errors to the error middleware instead.
  const wrap = (fn) => (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);

  const isNonEmptyString = (v) => typeof v === 'string' && v.length > 0;
  const EMAIL_RE = /^[^\s@<>"'&]+@[^\s@<>"'&]+\.[^\s@<>"'&]+$/;

  // Start a fresh session ID on authentication (prevents session fixation).
  function startSession(req, userId) {
    return new Promise((resolve, reject) => {
      req.session.regenerate((err) => {
        if (err) return reject(err);
        req.session.userId = userId;
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

  // =======================================================================
  // AUTH / WEB APP
  // =======================================================================

  app.post('/auth/signup', wrap(async (req, res) => {
    const { email, password } = req.body || {};
    if (!isNonEmptyString(email) || !isNonEmptyString(password)) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }
    if (!EMAIL_RE.test(email.trim()) || email.length > 254) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    let user;
    try {
      user = await db.createUser(email, password);
    } catch (e) {
      return res.status(409).json({ error: e.message });
    }
    await startSession(req, user.id);
    res.json({ email: user.email, apiKey: user.apiKey, isAdmin: user.isAdmin });
  }));

  app.post('/auth/login', wrap(async (req, res) => {
    const { email, password } = req.body || {};
    if (!isNonEmptyString(email) || !isNonEmptyString(password)) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    const user = await db.getUserByEmail(email);
    if (!user || !db.verifyPassword(password, user.passwordHash)) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    await startSession(req, user.id);
    res.json({ email: user.email, apiKey: user.apiKey, isAdmin: user.isAdmin });
  }));

  app.post('/auth/logout', (req, res) => {
    // Destroying the session immediately makes the user's API key unusable.
    req.session.destroy(() => {
      res.clearCookie('aap.sid');
      res.json({ ok: true });
    });
  });

  // Used by the dashboard to load the current user's info.
  app.get('/auth/me', requireLogin, wrap(async (req, res) => {
    const user = await db.getUserById(req.session.userId);
    if (!user) return res.status(401).json({ error: 'Not logged in' });
    res.json({
      email: user.email,
      apiKey: user.apiKey,
      keyEnabled: user.keyEnabled,
      isAdmin: user.isAdmin,
    });
  }));

  // =======================================================================
  // AUTH BRIDGE — polled by the shell client
  // =======================================================================

  // The CLI asks "is the account that owns this key currently logged in?"
  // It purposely does NOT require the caller to be logged in (the CLI has no
  // cookie). It only reveals a boolean (+ masked email), never the key.
  app.get('/auth/session-status', wrap(async (req, res) => {
    const apiKey = req.query.api_key;
    // Must be a plain string — `?api_key[$ne]=x` parses to an object and
    // would otherwise be passed to MongoDB as a query operator.
    if (!isNonEmptyString(apiKey)) {
      return res.status(400).json({ error: 'api_key query param required' });
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

  app.post('/api/message', wrap(async (req, res) => {
    const { api_key, message } = req.body || {};
    // Strings only: an object like {"$ne": null} would act as a MongoDB
    // operator and match an arbitrary user's key.
    if (!isNonEmptyString(api_key) || !isNonEmptyString(message)) {
      return res.status(400).json({ error: 'api_key and message are required strings.' });
    }

    // 1. Which user owns this key?
    const user = await db.getUserByApiKey(api_key);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized: invalid API key' });
    }

    // 2. Has an admin disabled this key?
    if (!user.keyEnabled) {
      return res.status(403).json({ error: 'Forbidden: API key is disabled' });
    }

    // 3. THE AAP CHECK — is the owner's browser session active right now?
    const active = await userHasActiveSession(user.id);
    if (!active) {
      return res
        .status(401)
        .json({ error: 'Unauthorized: No active session found' });
    }

    // 4. Session is live → run the lightweight response engine.
    const { reply, source } = await engine.generate(message, {
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
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  });

  // --- Seed a demo admin + a normal user (idempotent) ---------------------
  await seedIfMissing('admin@example.com', 'admin123', { isAdmin: true });
  await seedIfMissing('user@example.com', 'user123');

  app.listen(PORT, () => {
    console.log(`\nAAP demo running → http://localhost:${PORT}`);
    console.log(`MongoDB: database "${db.getDbName()}" @ mongodb://localhost:27017`);
    console.log('Seeded accounts:');
    console.log('  admin@example.com / admin123  (admin)');
    console.log('  user@example.com  / user123\n');
  });
}

async function seedIfMissing(email, password, opts) {
  if (!(await db.getUserByEmail(email))) {
    await db.createUser(email, password, opts);
  }
}

main().catch((err) => {
  console.error('Failed to start AAP server:', err.message);
  console.error('Is MongoDB running on mongodb://localhost:27017 ?');
  process.exit(1);
});

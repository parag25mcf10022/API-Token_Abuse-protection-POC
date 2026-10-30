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
const usage = require('./usage');
const alerts = require('./alerts');
const policyLib = require('./policy');
const { createAdminRouter } = require('./adminRoutes');

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
  const mongo = await db.connect();
  await usage.init(mongo);
  await alerts.init(mongo);

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
    // Per-account limits are admin-configurable policies (see usage.js).
    masterIp: createLimiter({ windowMs: MIN, max: 60 }),
  };
  const byIp = (req) => req.ip;

  // API keys travel ONLY in the X-API-Key header: never in the URL (it ends up
  // in server/proxy logs and shell history) or the JSON body. Returns the key
  // string, or sends a 400 and returns null.
  function readApiKey(req, res) {
    if (req.query.api_key !== undefined || (req.body && req.body.api_key !== undefined)) {
      res.status(400).json({ error: 'Send the API key in the X-API-Key header, not the URL or body.' });
      return null;
    }
    const key = req.get('X-API-Key');
    if (key === undefined) {
      res.status(400).json({ error: 'X-API-Key header required.' });
      return null;
    }
    return key;
  }

  const DEVICE_TOKEN_RE = /^[0-9a-f]{64}$/;

  /** Read + validate the CLI's device token header; sends 400 and returns null if bad. */
  function readDeviceToken(req, res) {
    const token = req.get('X-AAP-Device');
    if (typeof token !== 'string' || !DEVICE_TOKEN_RE.test(token)) {
      res.status(400).json({ error: 'X-AAP-Device header required (64 hex chars).' });
      return null;
    }
    return token;
  }

  /**
   * Is this device approved by the key's owner? Unknown devices are recorded
   * as "pending" so the owner sees them on the dashboard (and learns their key
   * is being used somewhere new).
   */
  async function deviceApproved(user, token, req) {
    const device = await db.getDevice(user.id, token);
    if (!device) {
      const n = security.cleanText(req.get('X-AAP-Device-Name') || '', 'name', 64);
      const name = n.ok ? n.value.trim() : 'unnamed device';
      const d = await db.registerPendingDevice(user.id, token, name);
      await alerts.raise('new_device', user, {
        detail: `Key used from a new device "${name}" (code ${d.code}).`,
        ip: req.ip,
      });
      return false;
    }
    if (device.status !== 'approved') return false;
    await db.touchDevice(device._id);
    return true;
  }

  // Auth/API responses can carry keys or account state — never cache them.
  app.use(['/auth', '/api'], (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  // =======================================================================
  // AUTH / WEB APP
  // =======================================================================

  app.post('/auth/signup', limit(limits.signupIp, byIp), wrap(async (req, res) => {
    const { email, password } = req.body || {};
    const cleanEmail = security.cleanEmail(email);
    if (!cleanEmail.ok) {
      return res.status(400).json({ error: cleanEmail.error });
    }
    const weak = security.passwordProblem(password, cleanEmail.value);
    if (weak) {
      return res.status(400).json({ error: weak });
    }
    let user;
    try {
      user = await db.createUser(cleanEmail.value, password);
    } catch (e) {
      return res.status(409).json({ error: e.message });
    }
    await startSession(req, user.id);
    // The plaintext key is returned exactly once, here. Only its hash is stored.
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
    // Always run scrypt (against a dummy hash for unknown emails) so response
    // time doesn't reveal whether the account exists.
    const passwordOk = db.verifyPassword(password, user ? user.passwordHash : db.DUMMY_HASH);
    if (!user || !passwordOk) {
      limits.loginFail.hit(failKey);
      // Alert once, on the failure that triggers the lockout.
      if (user && limits.loginFail.blocked(failKey).blocked) {
        await alerts.raise('login_lockout', user, {
          detail: 'Too many failed login attempts; logins from this IP locked for 15 min.',
          ip: req.ip,
          daily: true,
        });
      }
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    limits.loginFail.reset(failKey);
    if (await db.noteLoginIp(user.id, req.ip)) {
      await alerts.raise('new_ip_login', user, { detail: 'Login from a new IP address.', ip: req.ip });
    }
    await startSession(req, user.id);
    res.json({ email: user.email, isAdmin: user.isAdmin });
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
      _id: { $ne: req.sessionID },
    });
    // Destroy the current one through express-session, so it doesn't try to
    // refresh (touch) a session that no longer exists after responding.
    req.session.destroy(() => {
      res.clearCookie('aap.sid');
      res.json({ ok: true, sessionsEnded: deletedCount + 1 });
    });
  }));

  // --- Device management (owner only, scoped to the session's user) -------
  const DEVICE_ID_RE = /^[0-9a-f]{16}$/;

  app.get('/auth/devices', requireLogin, wrap(async (req, res) => {
    res.json({ devices: await db.listDevices(req.session.userId) });
  }));

  app.post('/auth/devices/:action', requireLogin, wrap(async (req, res) => {
    const { id } = req.body || {};
    if (typeof id !== 'string' || !DEVICE_ID_RE.test(id)) {
      return res.status(400).json({ error: 'Valid device id required.' });
    }
    let ok;
    if (req.params.action === 'approve') ok = await db.approveDevice(req.session.userId, id);
    else if (req.params.action === 'remove') ok = await db.removeDevice(req.session.userId, id);
    else return res.status(404).json({ error: 'Unknown action.' });
    if (!ok) return res.status(404).json({ error: 'Device not found.' });
    res.json({ ok: true });
  }));

  // Used by the dashboard to load the current user's info.
  app.get('/auth/me', requireLogin, wrap(async (req, res) => {
    const user = await db.getUserById(req.session.userId);
    if (!user) return res.status(401).json({ error: 'Not logged in' });
    const org = await db.getOrg(user.orgId);
    res.json({
      email: user.email,
      apiKeyPrefix: user.apiKeyPrefix, // full key is never shown again
      keyEnabled: user.keyEnabled,
      keyRevoked: !!user.keyRevoked, // admin revoked it → owner must generate a new one
      isAdmin: user.isAdmin,
      activeSessions: await countActiveSessions(user.id),
      // Read-only view of what admins configured for this key.
      org: org ? { id: org.id, name: org.name, role: user.orgRole, masterKeyPrefix: user.orgRole === 'admin' ? org.masterKeyPrefix : undefined } : null,
      scopes: policyLib.allowedScopes(user.policy, org && org.policy),
      limits: (user.policy && user.policy.limits) || {},
      usage: await usage.summary(`u:${user.id}`),
    });
  }));

  // Replace a leaked/lost key. Requires the current password so a hijacked
  // session alone can't mint a key; failures share the login lockout.
  app.post('/auth/rotate-key', requireLogin, wrap(async (req, res) => {
    const { password } = req.body || {};
    const failKey = `rotate|${req.session.userId}`;
    const lock = limits.loginFail.blocked(failKey);
    if (lock.blocked) return tooMany(res, lock.retryAfterSec);

    const user = await db.getUserById(req.session.userId);
    if (!user) return res.status(401).json({ error: 'Not logged in' });
    if (!security.isPassword(password) || !db.verifyPassword(password, user.passwordHash)) {
      limits.loginFail.hit(failKey);
      return res.status(401).json({ error: 'Incorrect password.' });
    }
    limits.loginFail.reset(failKey);
    const apiKey = await db.rotateApiKey(user.id);
    res.json({ apiKey, keyEnabled: user.keyEnabled });
  }));

  // =======================================================================
  // AUTH BRIDGE — polled by the shell client
  // =======================================================================

  // The CLI asks "can this key be used right now?" It purposely does NOT
  // require the caller to be logged in (the CLI has no cookie). It reveals a
  // single boolean — not the owner's email, not WHY a key is unusable — so a
  // stolen key tells an attacker as little as possible.
  app.get('/auth/session-status', limit(limits.statusIp, byIp), wrap(async (req, res) => {
    const apiKey = readApiKey(req, res);
    if (apiKey === null) return;
    const deviceToken = readDeviceToken(req, res);
    if (deviceToken === null) return;
    if (!security.isApiKey(apiKey)) {
      // Same answer as an unknown key — don't reveal what's malformed.
      return res.json({ active: false });
    }
    const user = await db.getUserByApiKey(apiKey);
    if (!user) {
      // Don't leak whether a key exists; just report "no session".
      return res.json({ active: false });
    }
    const active =
      user.keyEnabled &&
      (await deviceApproved(user, deviceToken, req)) &&
      (await userHasActiveSession(user.id));
    res.json({ active });
  }));

  // =======================================================================
  // API SERVER — the account-bound, protected endpoint
  // =======================================================================

  app.post('/api/message', limit(limits.messageIp, byIp), wrap(async (req, res) => {
    const api_key = readApiKey(req, res);
    if (api_key === null) return;
    const deviceToken = readDeviceToken(req, res);
    if (deviceToken === null) return;
    const { message } = req.body || {};
    if (message === undefined) {
      return res.status(400).json({ error: 'message is required.' });
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

    // Is the key being used from a device its owner approved?
    if (!(await deviceApproved(user, deviceToken, req))) {
      return res.status(403).json({
        error: 'Forbidden: this device is not approved. Approve it on your dashboard.',
      });
    }

    // 3. THE AAP CHECK — is the owner's browser session active right now?
    const active = await userHasActiveSession(user.id);
    if (!active) {
      return res
        .status(401)
        .json({ error: 'Unauthorized: No active session found' });
    }

    // 4. Scope: is this key allowed to use this content category?
    const org = await db.getOrg(user.orgId);
    const category = engine.classify(msg.value);
    if (!policyLib.allowedScopes(user.policy, org && org.policy).includes(category)) {
      return res.status(403).json({
        error: `Forbidden: your key is not allowed to use the "${category}" category.`,
        category,
      });
    }

    // 5. Usage limits (user + org pool), configured by admins only.
    const est = policyLib.estimateTokens(msg.value);
    const quota = await usage.check(user, org, category, est);
    if (!quota.ok) {
      await alerts.raise('limit_exceeded', user, {
        detail: `${quota.level} limit ${quota.limit} (${quota.max}) reached.`,
        daily: true,
      });
      res.set('Retry-After', String(quota.retryAfterSec));
      return res.status(429).json({
        error: `Usage limit reached: ${quota.limit} (${quota.max}) for your ${quota.level === 'org' ? 'organization' : 'account'}.`,
        limit: quota.limit,
        retryAfter: quota.retryAfterSec,
      });
    }

    // 6. All checks passed → run the engine and meter the usage.
    const { reply, source } = await engine.generate(msg.value, {
      llmFallback: llmFallback || undefined,
    });
    const tokens = policyLib.estimateTokens(msg.value) + policyLib.estimateTokens(reply);
    await usage.record(user, org, category, tokens);
    res.json({
      reply,
      source, // "rule" | "faq" | "cache" | "llm" | "fallback" — handy for the demo
      category,
      tokens,
      processedAt: new Date().toISOString(),
    });
  }));

  // =======================================================================
  // ADMIN PANEL (bonus)
  // =======================================================================

  const admin = createAdminRouter({
    db, usage, alerts, security, wrap, sessionsCol, countActiveSessions,
  });

  // Session-authenticated admins: super admin, or an org admin (own org only).
  const sessionActor = wrap(async (req, res, next) => {
    const user = req.session && req.session.userId && (await db.getUserById(req.session.userId));
    if (!user) return res.status(401).json({ error: 'Not logged in' });
    if (user.isAdmin) req.actor = { kind: 'super', userId: user.id, via: 'session' };
    else if (user.orgId && user.orgRole === 'admin') {
      req.actor = { kind: 'org', orgId: user.orgId, userId: user.id, via: 'session' };
    } else return res.status(403).json({ error: 'Admin access required' });
    next();
  });

  // Master-key-authenticated org management. The master key alone is never
  // enough: the request must come from an APPROVED device of one of the org's
  // admins, and that admin must have a live browser session.
  const masterActor = wrap(async (req, res, next) => {
    const key = req.get('X-AAP-Master-Key');
    const token = req.get('X-AAP-Device');
    if (!security.isMasterKey(key)) return res.status(401).json({ error: 'Valid X-AAP-Master-Key header required.' });
    if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) {
      return res.status(400).json({ error: 'X-AAP-Device header required (64 hex chars).' });
    }
    const org = await db.getOrgByMasterKey(key);
    if (!org) return res.status(401).json({ error: 'Unauthorized: invalid master key' });
    for (const u of await db.listUsersInOrg(org.id)) {
      if (u.orgRole !== 'admin') continue;
      const device = await db.getDevice(u.id, token);
      if (!device || device.status !== 'approved') continue;
      if (!(await userHasActiveSession(u.id))) {
        return res.status(401).json({ error: 'Unauthorized: org admin has no active session' });
      }
      await db.touchDevice(device._id);
      req.actor = { kind: 'org', orgId: org.id, userId: u.id, via: 'master' };
      return next();
    }
    res.status(403).json({ error: "Forbidden: master key may only be used from an org admin's approved device." });
  });

  app.use('/api/admin', sessionActor, admin.router);
  app.use('/api/org', limit(limits.masterIp, byIp), masterActor, admin.router);

  // Org admins issue/rotate their org's master key from the web UI (password
  // required). It's shown once; only its hash is stored. Not available via the
  // master key itself, and not to super admins — it belongs to the org admin.
  app.post('/auth/org/master-key', requireLogin, wrap(async (req, res) => {
    const user = await db.getUserById(req.session.userId);
    if (!user || !user.orgId || user.orgRole !== 'admin') {
      return res.status(403).json({ error: 'Org admins only.' });
    }
    const failKey = `rotate|${user.id}`;
    const lock = limits.loginFail.blocked(failKey);
    if (lock.blocked) return tooMany(res, lock.retryAfterSec);
    const { password } = req.body || {};
    if (!security.isPassword(password) || !db.verifyPassword(password, user.passwordHash)) {
      limits.loginFail.hit(failKey);
      return res.status(401).json({ error: 'Incorrect password.' });
    }
    limits.loginFail.reset(failKey);
    res.json({ masterKey: await db.rotateOrgMasterKey(user.orgId) });
  }));

  // --- Static frontend ----------------------------------------------------
  app.use(express.static(path.join(__dirname, 'public')));

  // --- Error handler ------------------------------------------------------
  // Catches errors forwarded by wrap() (and malformed JSON bodies) so the
  // client always gets a response instead of a hung request.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err); // too late to send an error body
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
  if (envPassword && security.passwordProblem(envPassword, email)) {
    console.warn(`Warning: password for ${email} from env is weak: ${security.passwordProblem(envPassword, email)}`);
  }
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

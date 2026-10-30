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
const llm = require('./llm');
const { createLimiter, limit, tooMany } = require('./rateLimit');
const usage = require('./usage');
const alerts = require('./alerts');
const policyLib = require('./policy');
const { createAdminRouter } = require('./adminRoutes');
const { createProtection, ACTIONS: PROTECTION_ACTIONS } = require('./protection');


const PORT = process.env.PORT || 3000;

// Sessions expire after 30 min idle (sliding), and after 8 h no matter what.
const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;

async function main() {
  // Connect to MongoDB ("AAP") before wiring up anything that needs it.
  const mongo = await db.connect();
  await usage.init(mongo);
  await alerts.init(mongo);
  const protection = createProtection({ db, alerts });

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


  // Accounts whose password was chosen by someone else (org members added by
  // an admin) must set their own before any key action. Every sensitive action
  // checks the LOGGED-IN account's own password — never anyone else's.
  function needsOwnPassword(user, res) {
    if (!user.mustChangePassword) return false;
    res.status(403).json({
      error: 'Set your own password first (Change password on your dashboard). Your current one was chosen by your admin.',
      mustChangePassword: true,
    });
    return true;
  }

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
    // Viewing a key: 3 wrong passwords per account → 15 min lockout; at most
    // 10 successful views per account per hour; 20 attempts per IP / 15 min.
    revealFail: createLimiter({ windowMs: 15 * MIN, max: 3 }),
    revealOk: createLimiter({ windowMs: 60 * MIN, max: 10 }),
    revealIp: createLimiter({ windowMs: 15 * MIN, max: 20 }),
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
      const recent = await db.countDevicesSince(user.id, new Date(Date.now() - 24 * 3600 * 1000));
      if (protection.crossed('device_spray', recent)) {
        await protection.trigger(user, 'device_spray', { ip: req.ip });
      }
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
    res.json({ email: user.email, isAdmin: user.isAdmin, mustChangePassword: !!user.mustChangePassword });
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

  // View the current key again. Requires the current password, inside a live
  // session. Three wrong passwords lock viewing for 15 minutes, END this
  // session (a hijacked session gets three guesses, then is logged out) and
  // alert admins.
  app.post('/auth/reveal-key', requireLogin, limit(limits.revealIp, byIp), wrap(async (req, res) => {
    const userId = req.session.userId;
    const lock = limits.revealFail.blocked(userId);
    if (lock.blocked) return tooMany(res, lock.retryAfterSec);

    const user = await db.getUserById(userId);
    if (!user) return res.status(401).json({ error: 'Not logged in' });
    if (needsOwnPassword(user, res)) return;
    const { password } = req.body || {};
    if (!security.isPassword(password) || !db.verifyPassword(password, user.passwordHash)) {
      limits.revealFail.hit(userId);
      const now = limits.revealFail.blocked(userId);
      if (now.blocked) {
        await alerts.raise('reveal_lockout', user, {
          detail: 'Too many wrong passwords while viewing the API key; session ended.',
          ip: req.ip,
        });
        await protection.trigger(user, 'reveal_lockout', { ip: req.ip });
        return req.session.destroy(() => {
          res.clearCookie('aap.sid');
          res.status(401).json({
            error: 'Too many incorrect attempts. You have been logged out; key viewing is locked for 15 minutes.',
            loggedOut: true,
          });
        });
      }
      return res.status(401).json({ error: 'Incorrect password.' });
    }
    limits.revealFail.reset(userId);

    const apiKey = db.revealApiKey(user);
    if (!apiKey) {
      return res.status(404).json({
        error: user.keyRevoked
          ? 'You have no active key. Generate a new one.'
          : 'This key was created before key viewing existed. Generate a new key to enable viewing.',
      });
    }
    // Count only views that actually display a key.
    const quota = limits.revealOk.hit(userId);
    if (!quota.allowed) return tooMany(res, quota.retryAfterSec);
    res.json({ apiKey });
  }));

  // Personal accounts choose what happens automatically if their key looks
  // compromised. Requires the current password. Org members get their org's
  // setting, chosen by an admin.
  app.post('/auth/protection', requireLogin, wrap(async (req, res) => {
    const user = await db.getUserById(req.session.userId);
    if (!user) return res.status(401).json({ error: 'Not logged in' });
    if (needsOwnPassword(user, res)) return;
    if (await db.getOrg(user.orgId)) return res.status(403).json({ error: 'Set by your organization admin.' });
    const failKey = `rotate|${user.id}`;
    const lock = limits.loginFail.blocked(failKey);
    if (lock.blocked) return tooMany(res, lock.retryAfterSec);
    const { action, password } = req.body || {};
    if (!PROTECTION_ACTIONS.includes(action)) {
      return res.status(400).json({ error: `action must be one of: ${PROTECTION_ACTIONS.join(', ')}.` });
    }
    if (!security.isPassword(password) || !db.verifyPassword(password, user.passwordHash)) {
      limits.loginFail.hit(failKey);
      return res.status(401).json({ error: 'Incorrect password.' });
    }
    limits.loginFail.reset(failKey);
    await db.setProtection(user.id, action);
    res.json({ action });
  }));

  // Change your own password: requires your CURRENT password (wrong attempts
  // share the lockout used by other sensitive actions). Ends every other
  // session for the account, so a stolen session can't outlive the change.
  app.post('/auth/change-password', requireLogin, wrap(async (req, res) => {
    const user = await db.getUserById(req.session.userId);
    if (!user) return res.status(401).json({ error: 'Not logged in' });
    const failKey = `rotate|${user.id}`;
    const lock = limits.loginFail.blocked(failKey);
    if (lock.blocked) return tooMany(res, lock.retryAfterSec);
    const { currentPassword, newPassword } = req.body || {};
    if (!security.isPassword(currentPassword) || !db.verifyPassword(currentPassword, user.passwordHash)) {
      limits.loginFail.hit(failKey);
      return res.status(401).json({ error: 'Your current password is incorrect.' });
    }
    limits.loginFail.reset(failKey);
    const weak = security.passwordProblem(newPassword, user.email);
    if (weak) return res.status(400).json({ error: weak });
    if (newPassword === currentPassword) {
      return res.status(400).json({ error: 'Choose a password different from the current one.' });
    }
    await db.setPassword(user.id, newPassword, { ownChoice: true });
    const { deletedCount } = await sessionsCol.deleteMany({
      'session.userId': user.id,
      _id: { $ne: req.sessionID },
    });
    res.json({ ok: true, otherSessionsEnded: deletedCount });
  }));

  // Mark quota notifications as read (one by id, or all).
  app.post('/auth/notices/dismiss', requireLogin, wrap(async (req, res) => {
    const { id } = req.body || {};
    if (id !== undefined && !(typeof id === 'string' && /^[0-9a-f]{12}$/.test(id))) {
      return res.status(400).json({ error: 'Invalid notice id.' });
    }
    await db.dismissNotices(req.session.userId, id || null);
    res.json({ ok: true });
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
    const userUsage = await usage.summary(`u:${user.id}`);
    res.json({
      email: user.email,
      apiKeyPrefix: user.apiKeyPrefix, // full key only via /auth/reveal-key
      keyRevealable: !!user.apiKeyEnc && !user.keyRevoked,
      mustChangePassword: !!user.mustChangePassword,
      keyLock: user.keyLock
        ? { reason: user.keyLock.reason, action: user.keyLock.action, at: user.keyLock.at, regenApproved: !!user.keyLock.regenApproved }
        : null,
      protection: {
        action: await protection.effectiveAction(user),
        // Personal accounts choose for themselves; org members' is set by admins.
        canChange: !org,
      },
      keyEnabled: user.keyEnabled,
      keyRevoked: !!user.keyRevoked, // admin revoked it → owner must generate a new one
      isAdmin: user.isAdmin,
      activeSessions: await countActiveSessions(user.id),
      // Read-only view of what admins configured for this key.
      org: org ? { id: org.id, name: org.name, role: user.orgRole, masterKeyPrefix: user.orgRole === 'admin' ? org.masterKeyPrefix : undefined } : null,
      scopes: policyLib.allowedScopes(user.policy, org && org.policy),
      llmAllowed: llm.enabled() && policyLib.llmAllowed(user.policy, org && org.policy),
      limits: (user.policy && user.policy.limits) || {},
      usage: userUsage,
      // Every category with its quota and whether it's usable right now (and why not).
      categories: policyLib.categoryStatus({
        userPolicy: user.policy,
        orgPolicy: org && org.policy,
        userUsage,
        orgUsage: org ? await usage.summary(`o:${org.id}`) : null,
      }),
      notices: (user.notices || []).slice(-15).reverse(),
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
    if (needsOwnPassword(user, res)) return;
    if (!security.isPassword(password) || !db.verifyPassword(password, user.passwordHash)) {
      limits.loginFail.hit(failKey);
      return res.status(401).json({ error: 'Incorrect password.' });
    }
    limits.loginFail.reset(failKey);
    // Team/enterprise members whose key was locked as compromised need an
    // org admin to approve regeneration first. Personal accounts verify with
    // their password (above) and can regenerate straight away.
    if (user.keyLock && !user.keyLock.regenApproved && (await db.getOrg(user.orgId))) {
      return res.status(403).json({
        error: 'Your key was locked after suspected compromise. Your org admin must approve regeneration first.',
      });
    }
    const apiKey = await db.rotateApiKey(user.id);
    res.json({ apiKey, keyEnabled: user.keyEnabled });
  }));

  // =======================================================================
  // AUTH BRIDGE — polled by the shell client
  // =======================================================================

  // The CLI asks "can this key be used right now?" It purposely does NOT
  // require the caller to be logged in (the CLI has no cookie). Unknown keys
  // get a bare {active:false}; unapproved devices only learn they need
  // approval; only the owner's approved devices are told the reason.
  app.get('/auth/session-status', limit(limits.statusIp, byIp), wrap(async (req, res) => {
    const apiKey = readApiKey(req, res);
    if (apiKey === null) return;
    const deviceToken = readDeviceToken(req, res);
    if (deviceToken === null) return;
    // An unknown key learns only that it's not valid (as /api/message says
    // too) — so a client holding an old/rotated key can ask for a new one.
    const user = security.isApiKey(apiKey) ? await db.getUserByApiKey(apiKey) : null;
    if (!user) return res.json({ active: false, reason: 'invalid_key' });
    // Device first: an unapproved device learns only that it needs approval
    // (which /api/message already reveals) — never the account's state.
    if (!(await deviceApproved(user, deviceToken, req))) {
      // Approval is per account: say so if this machine is approved for a
      // different account (a common mix-up), without naming that account.
      const elsewhere = await db.deviceApprovedElsewhere(user.id, deviceToken);
      return res.json({ active: false, reason: elsewhere ? 'device_approved_for_other_account' : 'device_not_approved' });
    }
    // From an owner-approved device, say WHY the key isn't usable so the
    // client can guide its owner instead of waiting blindly.
    let reason = null;
    if (user.keyLock) {
      const org = await db.getOrg(user.orgId);
      reason = org && !user.keyLock.regenApproved ? 'key_locked_needs_approval' : 'key_locked';
    } else if (!user.keyEnabled) reason = 'key_disabled';
    else if (!(await userHasActiveSession(user.id))) reason = 'no_session';
    res.json(reason ? { active: false, reason } : { active: true });
  }));

  // =======================================================================
  // API SERVER — the account-bound, protected endpoint
  // =======================================================================

  /**
   * Shared checks for every key-authenticated call (steps 1–5 of the AAP
   * order): key format + owner, admin-enabled, not auto-locked, approved
   * device, live owner session. Sends the error response and returns null on
   * failure; returns the user on success.
   */
  async function authenticateKey(req, res) {
    const apiKey = readApiKey(req, res);
    if (apiKey === null) return null;
    const deviceToken = readDeviceToken(req, res);
    if (deviceToken === null) return null;

    // 1. Which user owns this key? Only well-formed key strings reach the
    // DB — an object like {"$ne": null} would act as a MongoDB operator.
    const user = security.isApiKey(apiKey) ? await db.getUserByApiKey(apiKey) : null;
    if (!user) {
      res.status(401).json({ error: 'Unauthorized: invalid API key' });
      return null;
    }
    // 2. Has an admin disabled this key?
    if (!user.keyEnabled) {
      res.status(403).json({ error: 'Forbidden: API key is disabled' });
      return null;
    }
    // 3. Locked automatically after suspected compromise/abuse?
    if (user.keyLock) {
      res.status(403).json({ error: 'Forbidden: key locked after suspected compromise' });
      return null;
    }
    // 4. Approved device? Repeated attempts from unapproved devices look like
    // a stolen key.
    if (!(await deviceApproved(user, deviceToken, req))) {
      const tries = await alerts.raise('unapproved_device_use', user, {
        detail: 'API call from a device the owner has not approved.',
        ip: req.ip,
        daily: true,
      });
      if (protection.crossed('unapproved_device_use', tries)) {
        await protection.trigger(user, 'unapproved_device_use', { ip: req.ip });
      }
      res.status(403).json({ error: 'Forbidden: this device is not approved. Approve it on your dashboard.' });
      return null;
    }
    // 5. THE AAP CHECK — is the owner's browser session active right now?
    if (!(await userHasActiveSession(user.id))) {
      res.status(401).json({ error: 'Unauthorized: No active session found' });
      return null;
    }
    return user;
  }

  /** Validate optional chat history: [{role: 'user'|'assistant', content}] */
  const MAX_HISTORY_TURNS = 12;
  const MAX_HISTORY_CHARS = 16000;
  function readHistory(input) {
    if (input === undefined || input === null) return { ok: true, value: [] };
    if (!Array.isArray(input) || input.length > MAX_HISTORY_TURNS) {
      return { ok: false, error: `history must be an array of at most ${MAX_HISTORY_TURNS} turns.` };
    }
    const out = [];
    let total = 0;
    for (const turn of input) {
      if (!turn || !['user', 'assistant'].includes(turn.role)) {
        return { ok: false, error: "history roles must be 'user' or 'assistant'." };
      }
      const c = security.cleanText(turn.content, 'history content', 8000);
      if (!c.ok) return { ok: false, error: c.error };
      total += c.value.length;
      out.push({ role: turn.role, content: c.value });
    }
    if (total > MAX_HISTORY_CHARS) return { ok: false, error: 'history is too long.' };
    return { ok: true, value: out };
  }

  // NDJSON writer with the same <, >, & escaping as res.json (json escape).
  const ndjson = (obj) =>
    JSON.stringify(obj).replace(/[<>&]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`) + '\n';

  app.post('/api/message', limit(limits.messageIp, byIp), wrap(async (req, res) => {
    const { message, stream } = req.body || {};
    if (message === undefined) {
      return res.status(400).json({ error: 'message is required.' });
    }
    const msg = security.cleanText(message, 'message', security.LIMITS.message);
    if (!msg.ok) return res.status(400).json({ error: msg.error });
    const hist = readHistory((req.body || {}).history);
    if (!hist.ok) return res.status(400).json({ error: hist.error });

    // Steps 1–5: key, enabled, lock, device, live session.
    const user = await authenticateKey(req, res);
    if (!user) return;

    // 6. Scope: is this key allowed to use this content category?
    const org = await db.getOrg(user.orgId);
    const category = engine.classify(msg.value, hist.value);
    const allowed = policyLib.allowedScopes(user.policy, org && org.policy);
    if (!allowed.includes(category)) {
      return res.status(403).json({
        error: `Forbidden: this message was classified as "${category}", which your key isn't allowed to use. Allowed: ${allowed.join(', ') || 'none'}.`,
        category,
        allowed,
      });
    }

    // 7. Usage limits (user + org pool), configured by admins only. The
    // estimate includes conversation history, which is sent to the model.
    const historyText = hist.value.map((h) => h.content).join(' ');
    const est = policyLib.estimateTokens(msg.value) + policyLib.estimateTokens(historyText);
    const quota = await usage.check(user, org, category, est);
    if (!quota.ok) {
      const hits = await alerts.raise('limit_exceeded', user, {
        detail: `${quota.level} limit ${quota.limit} (${quota.max}) reached.`,
        daily: true,
      });
      if (protection.crossed('limit_abuse', hits)) {
        await protection.trigger(user, 'limit_abuse');
      }
      res.set('Retry-After', String(quota.retryAfterSec));
      return res.status(429).json({
        error: `Usage limit reached: ${quota.limit} (${quota.max}) for your ${quota.level === 'org' ? 'organization' : 'account'}.`,
        limit: quota.limit,
        retryAfter: quota.retryAfterSec,
      });
    }

    // 8. All checks passed → run the engine (LLM only if policy allows it).
    const useLlm = llm.enabled() && policyLib.llmAllowed(user.policy, org && org.policy);
    const started = Date.now();
    const streaming = stream === true;
    if (streaming) {
      res.status(200);
      res.set('Content-Type', 'application/x-ndjson; charset=utf-8');
      res.set('X-Accel-Buffering', 'no');
      res.flushHeaders();
    }
    const out = await engine.generate(msg.value, {
      llm: useLlm ? llm : null,
      category,
      history: hist.value,
      onDelta: streaming ? (text) => res.write(ndjson({ type: 'delta', text })) : undefined,
    });

    // Meter real model token counts when the LLM answered. Local answers never
    // see the history, so they're charged for the message + reply only.
    const tokens = out.usage
      ? out.usage.input + out.usage.output
      : policyLib.estimateTokens(msg.value) + policyLib.estimateTokens(out.reply);
    await usage.record(user, org, category, tokens);

    // Did this request push any quota past 50/75/90/99%? Save it for the
    // dashboard (org-pool notices go to every member) and return it inline.
    const notices = await usage.quotaNotices(user, org, category, tokens);
    if (notices.length) {
      await db.addNotices(user.id, notices.filter((n) => n.scope === 'user'));
      if (org) await db.addOrgNotices(org.id, notices.filter((n) => n.scope === 'org'));
    }

    const meta = {
      source: out.source, // "rule" | "faq" | "cache" | "llm" | "fallback"
      category,
      tokens,
      model: out.model || null,
      truncated: !!out.truncated,
      notices: notices.map((n) => ({ level: n.level, text: n.text })),
      ms: Date.now() - started,
      processedAt: new Date().toISOString(),
    };
    if (streaming) {
      // Non-LLM answers arrive in one piece.
      if (out.source !== 'llm') res.write(ndjson({ type: 'delta', text: out.reply }));
      res.end(ndjson({ type: 'done', ...meta }));
    } else {
      res.json({ reply: out.reply, ...meta });
    }
  }));

  // Key-authenticated account summary for the CLI (/usage).
  app.get('/api/usage', limit(limits.statusIp, byIp), wrap(async (req, res) => {
    const user = await authenticateKey(req, res);
    if (!user) return;
    const org = await db.getOrg(user.orgId);
    res.json({
      org: org ? { name: org.name, role: user.orgRole } : null,
      scopes: policyLib.allowedScopes(user.policy, org && org.policy),
      llm: llm.enabled() && policyLib.llmAllowed(user.policy, org && org.policy),
      limits: (user.policy && user.policy.limits) || {},
      usage: await usage.summary(`u:${user.id}`),
      categories: policyLib.categoryStatus({
        userPolicy: user.policy,
        orgPolicy: org && org.policy,
        userUsage: await usage.summary(`u:${user.id}`),
        orgUsage: org ? await usage.summary(`o:${org.id}`) : null,
      }),
    });
  }));

  // Engine status (provider/model) for the CLI and dashboard. No secrets.
  app.get('/api/engine', limit(limits.statusIp, byIp), wrap(async (req, res) => {
    const user = await authenticateKey(req, res);
    if (!user) return;
    res.json(await llm.status());
  }));
  app.get('/auth/engine', requireLogin, wrap(async (req, res) => {
    res.json(await llm.status());
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
    if (needsOwnPassword(user, res)) return;
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

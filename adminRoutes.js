/**
 * Admin / org-management API.
 *
 * The same router is mounted twice with different authentication:
 *   /api/admin/*  — browser session of a super admin (isAdmin) or org admin
 *   /api/org/*    — an org's MASTER KEY (management only), which works only
 *                   for that org's admins, from an approved device, while
 *                   they have a live browser session
 *
 * Every handler acts through `req.actor`:
 *   { kind: 'super' }                    → may manage everyone
 *   { kind: 'org', orgId, via }          → may manage only members of orgId
 * Users can never change their own policy/limits.
 */

'use strict';

const express = require('express');
const policyLib = require('./policy');
const { ACTIONS: PROTECTION_ACTIONS, DEFAULT_ACTION } = require('./protection');

const isId = (v) => /^\d{1,9}$/.test(String(v));
const PUBLIC_ID_RE = /^[0-9a-f]{16}$/;

function createAdminRouter({ db, usage, alerts, security, wrap, sessionsCol, countActiveSessions, costGuide }) {
  const router = express.Router();

  // --- helpers ---------------------------------------------------------------
  function canManage(actor, target) {
    if (!target) return false;
    if (actor.kind === 'super') return true;
    // Org admins manage their own org only, and never a super admin.
    return target.orgId === actor.orgId && !target.isAdmin;
  }

  function canManageOrg(actor, orgId) {
    return actor.kind === 'super' || actor.orgId === Number(orgId);
  }

  const superOnly = (req, res, next) =>
    req.actor.kind === 'super' ? next() : res.status(403).json({ error: 'Super admin only.' });

  // Load :id user and check the actor may manage them.
  const withTarget = wrap(async (req, res, next) => {
    if (!isId(req.params.id)) return res.status(400).json({ error: 'Invalid user id.' });
    const target = await db.getUserById(req.params.id);
    if (!canManage(req.actor, target)) return res.status(404).json({ error: 'User not found.' });
    req.target = target;
    next();
  });

  async function describeUser(u) {
    return {
      id: u.id,
      email: u.email,
      isAdmin: !!u.isAdmin,
      orgId: u.orgId || null,
      orgRole: u.orgRole || null,
      apiKeyPrefix: u.apiKeyPrefix || null, // never the key itself
      keyEnabled: !!u.keyEnabled,
      keyRevoked: !!u.keyRevoked,
      keyLock: u.keyLock || null,
      protection: (u.protection && u.protection.action) || DEFAULT_ACTION, // personal accounts
      policy: u.policy,
      activeSessions: await countActiveSessions(u.id),
      usage: await usage.summary(`u:${u.id}`),
    };
  }

  async function describeOrg(o) {
    return {
      id: o.id,
      name: o.name,
      masterKeyPrefix: o.masterKeyPrefix,
      policy: o.policy,
      memberDefaults: o.memberDefaults,
      protection: (o.protection && o.protection.action) || DEFAULT_ACTION,
      usage: await usage.summary(`o:${o.id}`),
    };
  }

  // --- read ------------------------------------------------------------------
  router.get('/overview', wrap(async (req, res) => {
    const a = req.actor;
    const users = a.kind === 'super' ? await db.listUsers() : await db.listUsersInOrg(a.orgId);
    const orgs = a.kind === 'super' ? await db.listOrgs() : [await db.getOrg(a.orgId)].filter(Boolean);
    res.json({
      actor: { kind: a.kind, orgId: a.orgId || null, via: a.via },
      categories: policyLib.CATEGORIES,
      limitFields: policyLib.LIMIT_FIELDS,
      orgs: await Promise.all(orgs.map(describeOrg)),
      users: await Promise.all(users.map(describeUser)),
    });
  }));

  // What a single request costs, to help size quotas.
  router.get('/cost-guide', wrap(async (req, res) => {
    res.json(await costGuide());
  }));

  router.get('/alerts', wrap(async (req, res) => {
    const a = req.actor;
    res.json({ alerts: await alerts.listOpen(a.kind === 'super' ? undefined : a.orgId) });
  }));

  router.post('/alerts/:publicId/resolve', wrap(async (req, res) => {
    if (!PUBLIC_ID_RE.test(req.params.publicId)) return res.status(400).json({ error: 'Invalid alert id.' });
    const alert = await alerts.getByPublicId(req.params.publicId);
    if (!alert || (req.actor.kind !== 'super' && alert.orgId !== req.actor.orgId)) {
      return res.status(404).json({ error: 'Alert not found.' });
    }
    await alerts.resolve(alert.publicId);
    res.json({ ok: true });
  }));

  // --- per-user controls -----------------------------------------------------
  router.post('/users/:id/key-enabled', withTarget, wrap(async (req, res) => {
    const { enabled } = req.body || {};
    if (typeof enabled !== 'boolean') return res.status(400).json({ error: 'enabled (boolean) required.' });
    res.json({ userId: req.target.id, keyEnabled: await db.setKeyEnabled(req.target.id, enabled) });
  }));

  router.post('/users/:id/policy', withTarget, wrap(async (req, res) => {
    const v = policyLib.validatePolicy((req.body || {}).policy);
    if (!v.ok) return res.status(400).json({ error: v.error });
    await db.setUserPolicy(req.target.id, v.policy);
    res.json({ userId: req.target.id, policy: v.policy });
  }));

  // Respond to suspicious activity: kill the key AND every session at once.
  // The owner logs back in and generates the replacement — admins never see it.
  router.post('/users/:id/revoke-key', withTarget, wrap(async (req, res) => {
    await db.revokeApiKey(req.target.id);
    const { deletedCount } = await sessionsCol.deleteMany({ 'session.userId': req.target.id });
    await alerts.resolveAllForUser(req.target.id);
    await alerts.raise('key_revoked', req.target, {
      detail: `Key revoked by ${req.actor.kind === 'super' ? 'super admin' : 'org admin'}; ${deletedCount} session(s) ended.`,
    });
    res.json({ ok: true, sessionsEnded: deletedCount });
  }));

  // --- compromise recovery ------------------------------------------------------
  // Allow a member whose key was auto-locked to generate a new one (they still
  // confirm with their own password; the admin never sees the key).
  router.post('/users/:id/approve-regeneration', withTarget, wrap(async (req, res) => {
    if (!req.target.keyLock) return res.status(400).json({ error: 'This key is not locked.' });
    await db.approveRegeneration(req.target.id);
    res.json({ ok: true });
  }));

  // False alarm: lift a 'disable' lock so the same key works again. A
  // 'rotate' lock can't be undone — the old key is gone for good.
  router.post('/users/:id/unlock', withTarget, wrap(async (req, res) => {
    const lock = req.target.keyLock;
    if (!lock) return res.status(400).json({ error: 'This key is not locked.' });
    if (lock.action !== 'disable') {
      return res.status(400).json({ error: 'The old key was rotated and cannot be restored; approve regeneration instead.' });
    }
    await db.setKeyLock(req.target.id, null);
    res.json({ ok: true });
  }));

  // Automatic response for a personal account (org members follow their org).
  router.post('/users/:id/protection', withTarget, wrap(async (req, res) => {
    const { action } = req.body || {};
    if (!PROTECTION_ACTIONS.includes(action)) {
      return res.status(400).json({ error: `action must be one of: ${PROTECTION_ACTIONS.join(', ')}.` });
    }
    if (await db.getOrg(req.target.orgId)) return res.status(400).json({ error: 'Org members follow their org setting.' });
    await db.setProtection(req.target.id, action);
    res.json({ userId: req.target.id, action });
  }));

  // --- org controls ----------------------------------------------------------
  router.post('/orgs/:orgId/protection', wrap(async (req, res) => {
    const { orgId } = req.params;
    if (!isId(orgId) || !canManageOrg(req.actor, orgId)) return res.status(404).json({ error: 'Org not found.' });
    const { action } = req.body || {};
    if (!PROTECTION_ACTIONS.includes(action)) {
      return res.status(400).json({ error: `action must be one of: ${PROTECTION_ACTIONS.join(', ')}.` });
    }
    await db.setOrgPolicy(orgId, 'protection', { action });
    res.json({ orgId: Number(orgId), action });
  }));

  router.post('/orgs/:orgId/policy', wrap(async (req, res) => {
    const { orgId } = req.params;
    if (!isId(orgId) || !canManageOrg(req.actor, orgId)) return res.status(404).json({ error: 'Org not found.' });
    const { field } = req.body || {};
    if (!['policy', 'memberDefaults'].includes(field)) {
      return res.status(400).json({ error: "field must be 'policy' (org pool) or 'memberDefaults'." });
    }
    const v = policyLib.validatePolicy((req.body || {}).policy);
    if (!v.ok) return res.status(400).json({ error: v.error });
    await db.setOrgPolicy(orgId, field, v.policy);
    res.json({ orgId: Number(orgId), field, policy: v.policy });
  }));

  // Add a member to an org. They get the org's member-default policy and NO
  // key yet: they log in and generate it themselves (shown only to them).
  router.post('/orgs/:orgId/members', wrap(async (req, res) => {
    const { orgId } = req.params;
    if (!isId(orgId) || !canManageOrg(req.actor, orgId)) return res.status(404).json({ error: 'Org not found.' });
    const org = await db.getOrg(orgId);
    if (!org) return res.status(404).json({ error: 'Org not found.' });
    const { email, password } = req.body || {};
    const e = security.cleanEmail(email);
    if (!e.ok) return res.status(400).json({ error: e.error });
    const weak = security.passwordProblem(password, e.value);
    if (weak) return res.status(400).json({ error: weak });
    let user;
    try {
      user = await db.createUser(e.value, password, {
        keyEnabled: true, // approved by the org admin who created them
        // The admin chose this password, so the member must replace it with
        // their own before any key action — admins never know member passwords.
        mustChangePassword: true,
        orgId: org.id,
        orgRole: 'member',
        policy: org.memberDefaults,
      });
    } catch (err) {
      return res.status(409).json({ error: err.message });
    }
    await db.revokeApiKey(user.id); // no usable key until the member generates one
    res.json({ id: user.id, email: user.email, orgId: org.id, mustChangePassword: true });
  }));

  // --- super admin only --------------------------------------------------------
  router.post('/orgs', superOnly, wrap(async (req, res) => {
    const n = security.cleanText((req.body || {}).name, 'name', 80);
    if (!n.ok) return res.status(400).json({ error: n.error });
    try {
      res.json(await describeOrg(await db.createOrg(n.value.trim())));
    } catch (err) {
      res.status(409).json({ error: err.message });
    }
  }));

  // Move a user into/out of an org and set their role there.
  router.post('/users/:id/org', superOnly, withTarget, wrap(async (req, res) => {
    const { orgId, role } = req.body || {};
    if (orgId === null) {
      await db.setUserOrg(req.target.id, null, null);
      return res.json({ ok: true });
    }
    if (!isId(orgId) || !['admin', 'member'].includes(role)) {
      return res.status(400).json({ error: "orgId (integer or null) and role ('admin'|'member') required." });
    }
    const org = await db.getOrg(orgId);
    if (!org) return res.status(404).json({ error: 'Org not found.' });
    if (req.target.isAdmin) return res.status(400).json({ error: 'Super admins stay outside orgs.' });
    await db.setUserOrg(req.target.id, org.id, role);
    if (req.target.orgId !== org.id) await db.setUserPolicy(req.target.id, org.memberDefaults);
    res.json({ ok: true });
  }));

  return { router, canManage };
}

module.exports = { createAdminRouter };

/**
 * Automatic response to a compromised or abused API key.
 *
 * Signals (raised by server.js):
 *   unapproved_device_use — repeated /api/message attempts from devices the
 *                           owner never approved (the real CLI waits for
 *                           approval, so this looks like a stolen key)
 *   device_spray          — several new unapproved devices in 24 h (key spreading)
 *   reveal_lockout        — wrong passwords while viewing the key (hijacked
 *                           session)
 *   limit_abuse           — many limit-blocked requests in a day
 *
 * Action (per org for members, per user for personal accounts):
 *   alert   — alerts only (no automatic change)
 *   disable — key is locked; an admin can Unlock it if it was a false alarm
 *   rotate  — key is revoked for good; a new key must be generated
 *
 * Recovery: org members need an org admin to approve regeneration first;
 * personal users regenerate with their password.
 */

'use strict';

const ACTIONS = ['alert', 'disable', 'rotate'];
const DEFAULT_ACTION = 'disable';

const THRESHOLDS = {
  unapproved_device_use: 3, // message attempts from unapproved devices per day
  device_spray: 5, // new, still-unapproved devices per 24 h
  limit_abuse: 50, // limit-blocked requests per day
};

const REASONS = {
  unapproved_device_use: 'Key used repeatedly from unapproved devices',
  device_spray: 'Key appeared on many new devices',
  reveal_lockout: 'Repeated wrong passwords while viewing the key',
  limit_abuse: 'Excessive limit-blocked requests',
};

function createProtection({ db, alerts }) {
  /** Action in force for this user: the org's for members, their own otherwise. */
  async function effectiveAction(user) {
    const org = await db.getOrg(user.orgId);
    if (org) return (org.protection && org.protection.action) || DEFAULT_ACTION;
    return (user.protection && user.protection.action) || DEFAULT_ACTION;
  }

  /**
   * Apply the configured action for a signal. Idempotent: an already-locked
   * key isn't locked again. Returns the action taken ('alert' if none).
   */
  async function trigger(user, signal, { ip = null } = {}) {
    const action = await effectiveAction(user);
    if (action === 'alert' || user.keyLock) return 'alert';

    const lock = { reason: signal, action, at: new Date(), regenApproved: false };
    if (action === 'rotate') await db.revokeApiKey(user.id); // old key dies for good
    await db.setKeyLock(user.id, lock);

    const recovery = (await db.getOrg(user.orgId))
      ? 'An org admin must approve regeneration.'
      : 'The owner can generate a new key with their password.';
    await alerts.raise('auto_protect', user, {
      detail: `${REASONS[signal]} — key automatically ${action === 'rotate' ? 'rotated (old key revoked)' : 'disabled'}. ${recovery}`,
      ip,
    });
    return action;
  }

  /** Has a counter-style signal crossed its threshold? */
  function crossed(signal, count) {
    return count >= THRESHOLDS[signal];
  }

  return { trigger, crossed, effectiveAction };
}

module.exports = { createProtection, ACTIONS, DEFAULT_ACTION, REASONS, THRESHOLDS };

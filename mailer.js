/**
 * Outgoing email via Resend's HTTP API (no SDK; plain fetch).
 *
 * Configuration (env, or .env — see server.js):
 *   RESEND_API_KEY   send-only API key. Without it, mail is NOT sent: each
 *                    message is printed to the server console instead (dev).
 *   EMAIL_FROM       sender, e.g. '"AAP" <no-reply@your-domain>'. Resend's
 *                    shared onboarding@resend.dev can only deliver to the
 *                    email address that owns the Resend account; verify a
 *                    domain in Resend to reach anyone else.
 *   APP_URL          public base URL used in links (default http://localhost:PORT)
 *   RESEND_API_URL   override the API endpoint (tests)
 *
 * Sending never throws: callers get { ok, id?, error? }. Security
 * notifications use notify(), which runs in the background and only logs
 * failures, so a mail outage can never break a request.
 */

'use strict';

const TIMEOUT_MS = 10000;

const cfg = () => ({
  key: process.env.RESEND_API_KEY || '',
  from: process.env.EMAIL_FROM || '"AAP" <onboarding@resend.dev>',
  api: (process.env.RESEND_API_URL || 'https://api.resend.com').replace(/\/$/, ''),
});

function appUrl() {
  return (process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, '');
}

const configured = () => !!cfg().key;

const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
// Header values: no line breaks (defence in depth; the API takes JSON).
const oneLine = (s) => String(s).replace(/[\r\n]+/g, ' ').trim();

/** Send one email. Resolves { ok: true, id } or { ok: false, error }. */
async function send({ to, subject, text, html }) {
  const c = cfg();
  if (!c.key) {
    console.log(`\n[mail:console] To: ${to}\nSubject: ${subject}\n\n${text}\n[/mail]\n`);
    return { ok: true, id: null, console: true };
  }
  try {
    const r = await fetch(`${c.api}/emails`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${c.key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: c.from, to: [oneLine(to)], subject: oneLine(subject), text, html }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) {
      const error = body.message || `HTTP ${r.status}`;
      console.warn(`[mail] send to ${to} failed: ${error}`);
      return { ok: false, error };
    }
    return { ok: true, id: body.id || null };
  } catch (e) {
    console.warn(`[mail] send to ${to} failed: ${e.message}`);
    return { ok: false, error: e.message };
  }
}

// --- Templates -------------------------------------------------------------------
// Each email type has its own look and content: an accent colour and label
// for its purpose, a one-line reason, a details box (account, time, IP,
// expiry…), a call to action and type-specific next steps. HTML is built with
// tables and inline styles (what email clients reliably render); a plain-text
// version carries the same content. Every dynamic value is escaped.

const THEMES = {
  action: { color: '#4f46e5', soft: '#eef2ff', label: 'Action required' },
  reset: { color: '#d97706', soft: '#fffbeb', label: 'Password reset' },
  notice: { color: '#0f766e', soft: '#f0fdfa', label: 'Security notice' },
  alert: { color: '#dc2626', soft: '#fef2f2', label: 'Security alert' },
};

const fmtTime = (d = new Date()) =>
  new Date(d).toUTCString().replace(/:\d\d GMT$/, ' UTC'); // "Thu, 12 Nov 2026 07:30 UTC"

/**
 * Build one email from a spec:
 *   { theme, subject, preheader, title, intro: [..], details: [[label, value]],
 *     button: { label, url }, stepsTitle, steps: [..], note, reason }
 */
function compose(spec) {
  const t = THEMES[spec.theme];
  const e = escapeHtml;
  const details = (spec.details || []).filter(([, v]) => v !== undefined && v !== null && v !== '');
  const para = (x) => `<p style="margin:0 0 14px;font-size:15px;line-height:1.6;color:#374151">${e(x)}</p>`;

  const detailRows = details
    .map(([k, v]) =>
      `<tr><td style="padding:6px 12px 6px 0;font-size:13px;color:#6b7280;white-space:nowrap;vertical-align:top">${e(k)}</td>` +
      `<td style="padding:6px 0;font-size:13px;color:#111827;font-weight:600;word-break:break-word">${e(v)}</td></tr>`)
    .join('');
  const detailBox = detailRows
    ? `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:${t.soft};border-left:4px solid ${t.color};border-radius:6px;margin:4px 0 20px"><tr><td style="padding:12px 16px"><table role="presentation" cellpadding="0" cellspacing="0">${detailRows}</table></td></tr></table>`
    : '';
  const button = spec.button
    ? `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:6px 0 10px"><tr><td style="background:${t.color};border-radius:8px">` +
      `<a href="${e(spec.button.url)}" style="display:inline-block;padding:12px 22px;font-size:15px;font-weight:700;color:#ffffff;text-decoration:none">${e(spec.button.label)}</a></td></tr></table>` +
      `<p style="margin:0 0 20px;font-size:12px;line-height:1.5;color:#6b7280">Button not working? Paste this link into your browser:<br><span style="color:${t.color};word-break:break-all">${e(spec.button.url)}</span></p>`
    : '';
  const steps = spec.steps && spec.steps.length
    ? `<p style="margin:8px 0 8px;font-size:14px;font-weight:700;color:#111827">${e(spec.stepsTitle || 'What to do next')}</p>` +
      `<ol style="margin:0 0 18px;padding-left:20px;font-size:14px;line-height:1.6;color:#374151">${spec.steps.map((x) => `<li style="margin:0 0 4px">${e(x)}</li>`).join('')}</ol>`
    : '';
  const note = spec.note
    ? `<p style="margin:0 0 6px;padding:10px 12px;background:#f9fafb;border-radius:6px;font-size:13px;line-height:1.5;color:#4b5563">${e(spec.note)}</p>`
    : '';

  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>${e(spec.subject)}</title></head>` +
    `<body style="margin:0;padding:0;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif">` +
    `<span style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">${e(spec.preheader)}</span>` +
    `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6"><tr><td align="center" style="padding:28px 12px">` +
    `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e5e7eb">` +
    `<tr><td style="height:6px;background:${t.color};font-size:0;line-height:0">&nbsp;</td></tr>` +
    `<tr><td style="padding:22px 28px 0"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>` +
    `<td style="font-size:15px;font-weight:800;color:#111827">🔐 AAP</td>` +
    `<td align="right"><span style="display:inline-block;padding:4px 10px;border-radius:999px;background:${t.soft};color:${t.color};font-size:12px;font-weight:700">${e(t.label)}</span></td>` +
    `</tr></table></td></tr>` +
    `<tr><td style="padding:18px 28px 8px"><h1 style="margin:0 0 14px;font-size:22px;line-height:1.3;color:#111827">${e(spec.title)}</h1>` +
    spec.intro.map(para).join('') + detailBox + button + steps + note +
    `</td></tr>` +
    `<tr><td style="padding:16px 28px 22px;border-top:1px solid #f3f4f6;font-size:12px;line-height:1.6;color:#9ca3af">` +
    `${e(spec.reason)}<br>This is an automated message from AAP (Account-Bound API Key Protection) — replies aren't read. ` +
    `AAP will never ask for your password or API key by email.</td></tr>` +
    `</table></td></tr></table></body></html>`;

  const text = [
    `${t.label.toUpperCase()} — ${spec.title}`,
    '',
    ...spec.intro.flatMap((x) => [x, '']),
    ...(details.length ? [...details.map(([k, v]) => `${k}: ${v}`), ''] : []),
    ...(spec.button ? [`${spec.button.label}: ${spec.button.url}`, ''] : []),
    ...(spec.steps && spec.steps.length
      ? [`${spec.stepsTitle || 'What to do next'}:`, ...spec.steps.map((x, i) => `  ${i + 1}. ${x}`), '']
      : []),
    ...(spec.note ? [spec.note, ''] : []),
    '--',
    spec.reason,
    "Automated message from AAP — replies aren't read. AAP never asks for your password or API key by email.",
  ].join('\n');

  return { subject: spec.subject, text, html };
}

const templates = {
  /** New self-service account: confirm the address. */
  verifyEmail: ({ email, url, hours, ip }) =>
    compose({
      theme: 'action',
      subject: 'Confirm your email to activate your AAP account',
      preheader: `One click to confirm ${email} — the link expires in ${hours} hours.`,
      title: 'Confirm your email address',
      intro: [
        'Welcome to AAP! Please confirm this is your email address. Until you do, your API key stays inactive — even after an admin enables it.',
      ],
      details: [['Account', email], ['Requested', fmtTime()], ['From IP', ip], ['Link expires', `in ${hours} hours (single use)`]],
      button: { label: 'Confirm my email', url },
      stepsTitle: 'After confirming',
      steps: [
        'Wait for an admin to enable your API key (you’ll see it on your dashboard).',
        'Run the shell client and approve your device with its pairing code.',
        'Keep the dashboard logged in — your key only works while your session is live.',
      ],
      note: "Didn't sign up? Ignore this email. The account can't use the API without this confirmation.",
      reason: `You received this because someone signed up for AAP with ${email}.`,
    }),

  /** Account created by an org admin: confirm the address and set a password. */
  memberVerify: ({ email, url, hours, org }) =>
    compose({
      theme: 'action',
      subject: `You've been added to ${org} on AAP — confirm your email`,
      preheader: `Your ${org} admin created an AAP account for you. Confirm your email to get started.`,
      title: `You've been added to ${org}`,
      intro: [
        `An admin of ${org} created an AAP account for you. Confirm your email address to activate API access.`,
      ],
      details: [['Account', email], ['Organization', org], ['Link expires', `in ${hours} hours (single use)`]],
      button: { label: 'Confirm my email', url },
      stepsTitle: 'Getting started',
      steps: [
        'Confirm your email with the button above.',
        'Log in with the temporary password your admin gave you, then set your own — your admin will never know it.',
        'Generate your API key on the dashboard; it is shown only to you.',
        'Run the shell client and approve your device with its pairing code.',
      ],
      note: `Not expecting this? Contact your ${org} admin, or ignore this email.`,
      reason: `You received this because an admin of ${org} added ${email} to AAP.`,
    }),

  /** Forgot-password link. */
  resetPassword: ({ email, url, minutes, ip }) =>
    compose({
      theme: 'reset',
      subject: 'Reset your AAP password',
      preheader: `Use this link within ${minutes} minutes to choose a new password.`,
      title: 'Reset your password',
      intro: [
        'We received a request to reset the password for your AAP account. Choose a new password with the button below.',
      ],
      details: [['Account', email], ['Requested', fmtTime()], ['From IP', ip], ['Link expires', `in ${minutes} minutes (single use)`]],
      button: { label: 'Choose a new password', url },
      stepsTitle: 'Good to know',
      steps: [
        'Resetting logs out every session on every device.',
        'Your API key stops working until you log in again with the new password.',
        'Your key itself, devices and limits stay the same.',
      ],
      note: "Didn't ask for this? Ignore this email — your password won't change. If it keeps happening, tell your admin.",
      reason: `You received this because a password reset was requested for ${email}.`,
    }),

  /** Confirmation after a change or reset. */
  passwordChanged: ({ email, how, ip, sessionsEnded }) =>
    compose({
      theme: 'notice',
      subject: 'Your AAP password was changed',
      preheader: `The password for ${email} was ${how}. Wasn't you? Act now.`,
      title: 'Your password was changed',
      intro: [`The password for your AAP account was ${how}. If this was you, there's nothing else to do.`],
      details: [
        ['Account', email],
        ['When', fmtTime()],
        ['How', how],
        ['From IP', ip],
        ['Other sessions ended', sessionsEnded === undefined ? null : String(sessionsEnded)],
      ],
      button: { label: 'Reset my password', url: `${appUrl()}/#forgot` },
      stepsTitle: "Wasn't you? Do this now",
      steps: [
        'Reset your password with the button above — this logs everyone else out.',
        'On your dashboard, remove any device you don’t recognise and generate a new API key.',
        'Tell your admin so they can review your account’s alerts.',
      ],
      reason: `You received this because the password for ${email} changed.`,
    }),

  /** A Google/GitHub/Microsoft sign-in was connected to the account. */
  identityLinked: ({ email, provider, providerEmail, ip, automatic }) =>
    compose({
      theme: 'notice',
      subject: `${provider} sign-in was connected to your AAP account`,
      preheader: `You can now sign in to AAP with ${provider}${providerEmail ? ` (${providerEmail})` : ''}. Wasn't you? Act now.`,
      title: `${provider} sign-in connected`,
      intro: [
        automatic
          ? `Someone signed in to AAP with a ${provider} account that uses your verified email address, so it was connected to your account. You can now sign in with ${provider} as well.`
          : `A ${provider} account was connected to your AAP account. You can now sign in with ${provider} as well.`,
      ],
      details: [['Account', email], [`${provider} account`, providerEmail], ['When', fmtTime()], ['From IP', ip]],
      button: { label: 'Review sign-in methods', url: appUrl() },
      stepsTitle: "Wasn't you? Do this now",
      steps: [
        `Log in and disconnect ${provider} under Sign-in methods.`,
        'Reset your password, which logs everyone else out.',
        'Tell your admin so they can review your account’s alerts.',
      ],
      reason: `You received this because a sign-in method was added to ${email}.`,
    }),

  /** Automatic protection locked or rotated the key. */
  keyLocked: ({ email, reason, action, recovery, ip }) =>
    compose({
      theme: 'alert',
      subject: action === 'rotate' ? 'Security alert: your AAP API key was revoked' : 'Security alert: your AAP API key was disabled',
      preheader: `${reason}. Your key was ${action === 'rotate' ? 'revoked' : 'disabled'} automatically.`,
      title: action === 'rotate' ? 'We revoked your API key' : 'We disabled your API key',
      intro: [
        'AAP spotted activity that looks like your API key may be in someone else’s hands, so it acted automatically to protect your account.',
      ],
      details: [
        ['Account', email],
        ['What we saw', reason],
        ['Action taken', action === 'rotate' ? 'Key revoked for good' : 'Key disabled (can be unlocked)'],
        ['When', fmtTime()],
        ['Seen from IP', ip],
      ],
      button: { label: 'Open my dashboard', url: appUrl() },
      stepsTitle: 'How to recover',
      steps: [
        recovery,
        'Check your devices and remove any you don’t recognise.',
        'If you can’t explain the activity, change your password too.',
      ],
      reason: `You received this because a security rule fired for ${email}.`,
    }),

  /** An admin revoked the key. */
  keyRevoked: ({ email, by, sessionsEnded }) =>
    compose({
      theme: 'alert',
      subject: 'Your AAP API key was revoked by an admin',
      preheader: `Your API key was revoked by ${by} and every session was ended.`,
      title: 'Your API key was revoked',
      intro: [`Your API key was revoked by ${by}. It stopped working immediately, and every session for your account was ended.`],
      details: [['Account', email], ['Revoked by', by], ['When', fmtTime()], ['Sessions ended', sessionsEnded === undefined ? null : String(sessionsEnded)]],
      button: { label: 'Log in and get a new key', url: appUrl() },
      stepsTitle: 'What to do next',
      steps: [
        'Log in to the dashboard.',
        'Generate a new key — it is shown only to you, never to admins.',
        'Update the key in the shell client on your approved devices.',
      ],
      note: 'Not sure why? Ask your admin — admins usually revoke a key after a security alert.',
      reason: `You received this because an admin revoked the API key for ${email}.`,
    }),
};

/**
 * Background security notification to a user's verified address. Unverified
 * addresses get nothing (no mail to an address its owner never confirmed).
 */
function notify(user, template, data) {
  if (!user || !user.email || user.emailVerified === false) return;
  const m = templates[template]({ email: user.email, ...data });
  send({ to: user.email, ...m }).catch(() => {});
}

module.exports = { send, notify, templates, configured, appUrl, escapeHtml };

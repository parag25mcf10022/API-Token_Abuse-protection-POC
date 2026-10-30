/**
 * XSS hardening for the AAP demo: response headers + input validation.
 *
 * Strategy (defense in depth):
 *   • Validate input on the way in — right type, bounded length, no control
 *     characters, strict allow-list for emails. We deliberately do NOT try to
 *     "strip <script>" from free text: blacklist filters are bypassable and
 *     corrupt legitimate data (e.g. "calc 2<3").
 *   • Encode on the way out — JSON is escaped by Express (`json escape`), the
 *     browser only ever renders data via textContent, and the CLI strips
 *     terminal control sequences.
 *   • Contain whatever slips through — a strict CSP blocks inline/injected
 *     script and Trusted Types makes string-to-HTML sinks (innerHTML…) throw.
 */

'use strict';

const LIMITS = {
  email: 254,
  passwordMin: 8,
  password: 256,
  message: 2000,
};

// Control characters except tab / newline / carriage return. These have no
// business in user text and are used to smuggle payloads past filters or to
// inject terminal escape sequences.
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/;

// Bidi overrides / isolates can visually disguise content ("Trojan Source").
const BIDI_CHARS = /[\u202A-\u202E\u2066-\u2069]/;

// Allow-list: local part and domain use only characters that are inert in
// HTML, attributes, and URLs. No quotes, angle brackets, ampersands, spaces.
const EMAIL_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/;

// Exact shape produced by db.generateApiKey().
const API_KEY_RE = /^ak_[0-9a-f]{48}$/;

const isApiKey = (v) => typeof v === 'string' && API_KEY_RE.test(v);

// Passwords are hashed, never displayed, so any characters are fine — only
// enforce type and a length cap (bounds scrypt work per request).
const isPassword = (v) =>
  typeof v === 'string' && v.length > 0 && v.length <= LIMITS.password;

// A short deny-list of the most common passwords. Not exhaustive — for
// production, check against a breached-password list (e.g. HIBP k-anonymity).
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', '12345678', '123456789',
  '1234567890', 'qwertyui', 'qwerty123', 'iloveyou', 'admin123',
  'administrator', 'letmein1', 'welcome1', 'abc12345', '11111111',
  'passw0rd', 'changeme', 'user1234', 'football', 'sunshine',
]);

/**
 * Password policy for NEW passwords (signup). Returns an error string, or
 * null if acceptable. Existing passwords are never re-checked at login.
 */
function passwordProblem(password, email) {
  if (!isPassword(password)) {
    return `Password is required (max ${LIMITS.password} characters).`;
  }
  if (password.length < LIMITS.passwordMin) {
    return `Password must be at least ${LIMITS.passwordMin} characters.`;
  }
  const lower = password.toLowerCase();
  if (COMMON_PASSWORDS.has(lower)) {
    return 'That password is too common. Please choose another.';
  }
  if (/^(.)\1*$/.test(password)) {
    return 'Password cannot be a single repeated character.';
  }
  const local = typeof email === 'string' ? email.split('@')[0].toLowerCase() : '';
  if (local.length >= 3 && lower.includes(local)) {
    return 'Password must not contain your email name.';
  }
  return null;
}

/**
 * Validate and normalize a free-text field.
 * @returns {{ok: true, value: string} | {ok: false, error: string}}
 */
function cleanText(value, field, max) {
  if (typeof value !== 'string') {
    return { ok: false, error: `${field} must be a string.` };
  }
  const v = value.normalize('NFC');
  if (v.trim().length === 0) {
    return { ok: false, error: `${field} is required.` };
  }
  if (v.length > max) {
    return { ok: false, error: `${field} must be at most ${max} characters.` };
  }
  if (CONTROL_CHARS.test(v) || BIDI_CHARS.test(v)) {
    return { ok: false, error: `${field} contains invalid characters.` };
  }
  return { ok: true, value: v };
}

/** Validate an email against the allow-list; returns normalized lowercase. */
function cleanEmail(value) {
  const r = cleanText(value, 'Email', LIMITS.email);
  if (!r.ok) return r;
  const email = r.value.trim().toLowerCase();
  if (!EMAIL_RE.test(email)) {
    return { ok: false, error: 'Please enter a valid email address.' };
  }
  return { ok: true, value: email };
}

/** Express middleware: security headers on every response. */
function securityHeaders(req, res, next) {
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data:",
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "require-trusted-types-for 'script'",
    ].join('; ')
  );
  res.setHeader('X-Content-Type-Options', 'nosniff'); // no MIME sniffing JSON → HTML
  res.setHeader('X-Frame-Options', 'DENY'); // legacy clickjacking guard
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  next();
}

module.exports = {
  LIMITS,
  cleanText,
  cleanEmail,
  isApiKey,
  isPassword,
  passwordProblem,
  securityHeaders,
};

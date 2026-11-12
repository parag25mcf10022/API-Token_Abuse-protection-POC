/**
 * Sign-in with Google, GitHub and Microsoft (OAuth 2.0 / OpenID Connect).
 *
 * Authorization-code flow with PKCE, `state` (CSRF) and, for the OpenID
 * providers, `nonce`. No SDK: plain fetch over TLS.
 *
 * Configuration (env or .env). A provider is offered only when both are set:
 *   GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
 *   GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET
 *   MICROSOFT_CLIENT_ID / MICROSOFT_CLIENT_SECRET   (MICROSOFT_TENANT, default "common")
 * Redirect URI to register with each provider:
 *   <APP_URL>/auth/oauth/<google|github|microsoft>/callback
 *
 * Email trust:
 *   google    — trusted when Google says email_verified
 *   github    — trusted when GitHub lists the address as verified
 *   microsoft — never trusted: the email claim of multi-tenant Microsoft
 *               accounts can be set by the account's tenant ("nOAuth"), so it
 *               can't prove ownership. Microsoft accounts are matched only by
 *               their stable id and verify their email with us like anyone.
 *
 * ID tokens are read without a signature check, which OpenID Connect allows
 * for tokens received directly from the token endpoint over TLS (Core
 * §3.1.3.7); audience, nonce and auth_time are still checked.
 */

'use strict';

const crypto = require('crypto');

const TIMEOUT_MS = 10000;
const b64url = (buf) => buf.toString('base64url');

// Tests point every provider at a local mock (never in production).
const mockBase = () =>
  process.env.NODE_ENV !== 'production' && process.env.OAUTH_MOCK_BASE
    ? process.env.OAUTH_MOCK_BASE.replace(/\/$/, '')
    : null;

function endpoints(id) {
  const mock = mockBase();
  if (mock) {
    return {
      authorize: `${mock}/${id}/authorize`,
      token: `${mock}/${id}/token`,
      userinfo: `${mock}/${id}/userinfo`,
      emails: `${mock}/${id}/emails`,
      me: `${mock}/${id}/me`,
    };
  }
  const tenant = encodeURIComponent(process.env.MICROSOFT_TENANT || 'common');
  return {
    google: {
      authorize: 'https://accounts.google.com/o/oauth2/v2/auth',
      token: 'https://oauth2.googleapis.com/token',
      userinfo: 'https://openidconnect.googleapis.com/v1/userinfo',
    },
    github: {
      authorize: 'https://github.com/login/oauth/authorize',
      token: 'https://github.com/login/oauth/access_token',
      userinfo: 'https://api.github.com/user',
      emails: 'https://api.github.com/user/emails',
    },
    microsoft: {
      authorize: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
      token: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
      userinfo: 'https://graph.microsoft.com/oidc/userinfo',
      me: 'https://graph.microsoft.com/v1.0/me',
    },
  }[id];
}

const PROVIDERS = {
  google: {
    name: 'Google',
    env: 'GOOGLE',
    oidc: true,
    scope: 'openid email profile',
    loginParams: { prompt: 'select_account' },
    // Force a real sign-in (password/2FA), not a silent session reuse.
    reauthParams: { prompt: 'login', max_age: '0' },
    trustsEmail: true,
  },
  github: {
    name: 'GitHub',
    env: 'GITHUB',
    oidc: false,
    scope: 'read:user user:email',
    loginParams: { prompt: 'select_account' },
    // GitHub can't force a password prompt; a fresh round trip still proves
    // the person in THIS browser controls the linked GitHub account.
    reauthParams: { prompt: 'select_account' },
    trustsEmail: true,
  },
  microsoft: {
    name: 'Microsoft',
    env: 'MICROSOFT',
    oidc: true,
    scope: 'openid email profile User.Read',
    loginParams: { prompt: 'select_account' },
    reauthParams: { prompt: 'login', max_age: '0' },
    trustsEmail: false,
  },
};

function creds(id) {
  const p = PROVIDERS[id];
  return {
    clientId: process.env[`${p.env}_CLIENT_ID`] || '',
    clientSecret: process.env[`${p.env}_CLIENT_SECRET`] || '',
  };
}

const isProvider = (id) => Object.prototype.hasOwnProperty.call(PROVIDERS, id);
const configured = (id) => isProvider(id) && !!(creds(id).clientId && creds(id).clientSecret);
const enabledProviders = () =>
  Object.keys(PROVIDERS).filter(configured).map((id) => ({ id, name: PROVIDERS[id].name }));

/**
 * Build the provider redirect for one sign-in attempt. Returns { url, state }
 * where `state` holds the secrets to keep server-side (in the session) until
 * the callback: { state, verifier, nonce, provider, intent, startedAt }.
 */
function begin(id, intent, redirectUri, { loginHint } = {}) {
  const p = PROVIDERS[id];
  const state = b64url(crypto.randomBytes(32));
  const verifier = b64url(crypto.randomBytes(32));
  const nonce = b64url(crypto.randomBytes(16));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  const params = new URLSearchParams({
    client_id: creds(id).clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: p.scope,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...(p.oidc ? { nonce } : {}),
    ...(intent === 'reauth' ? p.reauthParams : p.loginParams),
    ...(loginHint ? { login_hint: loginHint } : {}),
  });
  return {
    url: `${endpoints(id).authorize}?${params}`,
    state: { state, verifier, nonce, provider: id, intent, startedAt: Date.now() },
  };
}

async function getJson(url, init = {}) {
  const r = await fetch(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS) });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`${new URL(url).host} answered ${r.status}`);
  return body;
}

function decodeJwtPayload(jwt) {
  const part = String(jwt || '').split('.')[1];
  if (!part) throw new Error('missing id_token');
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

/**
 * Finish a sign-in: exchange the code and read the profile.
 * Resolves { provider, sub, email, emailVerified, name, authTime }.
 */
async function complete(id, code, saved, redirectUri) {
  const p = PROVIDERS[id];
  const ep = endpoints(id);
  const { clientId, clientSecret } = creds(id);
  const tok = await getJson(ep.token, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      client_secret: clientSecret,
      code_verifier: saved.verifier,
    }),
  });
  if (!tok.access_token) throw new Error('no access token');
  const auth = { Authorization: `Bearer ${tok.access_token}`, Accept: 'application/json', 'User-Agent': 'AAP' };

  let claims = null;
  if (p.oidc) {
    claims = decodeJwtPayload(tok.id_token);
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!aud.includes(clientId)) throw new Error('id_token audience mismatch');
    if (claims.nonce !== saved.nonce) throw new Error('id_token nonce mismatch');
    if (claims.exp && claims.exp * 1000 < Date.now() - 60000) throw new Error('id_token expired');
  }

  if (id === 'google') {
    const u = await getJson(ep.userinfo, { headers: auth });
    if (u.sub !== claims.sub) throw new Error('subject mismatch');
    return {
      provider: id,
      sub: String(u.sub),
      email: u.email || null,
      emailVerified: u.email_verified === true,
      name: u.name || null,
      authTime: claims.auth_time ? claims.auth_time * 1000 : null,
    };
  }

  if (id === 'github') {
    const u = await getJson(ep.userinfo, { headers: auth });
    const emails = await getJson(ep.emails, { headers: auth }).catch(() => []);
    const list = Array.isArray(emails) ? emails : [];
    const verified = list.find((e) => e.primary && e.verified) || list.find((e) => e.verified) || null;
    // No verified address: still use the primary one, but as UNVERIFIED (it
    // goes through our own email verification and never auto-links).
    const primary = list.find((e) => e.primary) || null;
    return {
      provider: id,
      sub: String(u.id),
      email: verified ? verified.email : (primary && primary.email) || u.email || null,
      emailVerified: !!verified,
      name: u.name || u.login || null,
      authTime: null, // GitHub doesn't report it
    };
  }

  // microsoft
  const u = await getJson(ep.userinfo, { headers: auth });
  if (u.sub !== claims.sub) throw new Error('subject mismatch');
  let email = u.email || claims.email || null;
  if (!email) {
    const me = await getJson(ep.me, { headers: auth }).catch(() => ({}));
    email = me.mail || me.userPrincipalName || null;
  }
  return {
    provider: id,
    // tid + oid identify the account across apps; sub is per-app. Use both.
    sub: claims.tid && claims.oid ? `${claims.tid}:${claims.oid}` : String(u.sub),
    email,
    emailVerified: false, // see header: never trusted
    name: u.name || claims.name || null,
    authTime: claims.auth_time ? claims.auth_time * 1000 : null,
  };
}

module.exports = { PROVIDERS, isProvider, configured, enabledProviders, begin, complete };

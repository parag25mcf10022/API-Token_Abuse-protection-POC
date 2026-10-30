# Changelog

All notable changes to this project. Dates are in YYYY-MM-DD.

## 2026-10-30

### Added (key viewing)
- **View your API key** (`POST /auth/reveal-key`) after re-entering your
  password, in a live session:
  - 3 wrong passwords lock viewing for 15 minutes, end the session, and raise
    a `reveal_lockout` alert.
  - At most 10 views per account per hour, plus a per-IP cap on attempts.
  - The revealed key auto-hides after 30 seconds.
- Keys are now stored encrypted (AES-256-GCM, bound to the user id) next to
  the lookup hash. The encryption key comes from `KEY_ENCRYPTION_KEY` or
  `.secrets/key-encryption.key` (mode 600, git-ignored), never MongoDB.
  Keys created before this can't be viewed; generate a new one.

### Added
- **Organizations:** a super admin creates orgs and assigns org admins and
  members. Org admins manage only their own org.
- **Org master key** (`mk_...`):
  - Management only; it can't send messages.
  - Issued by the org admin with their password, shown once, stored hashed.
  - Accepted only from an org admin's approved device while that admin has a
    live session.
- **Policies (admin-only):**
  - Per-key content-category scopes: `general`, `math`, `text`, `coding`,
    `cyber`, `design`, `data`.
  - Usage limits per user and per org pool: burst per minute, requests per
    day and month, tokens per day and month, and per-category daily caps.
  - Org "member defaults" for new members.
- **Usage metering** in MongoDB buckets with automatic expiry. Responses
  include `category` and `tokens`.
- **Content classifier** in the engine, plus local knowledge for the coding,
  cyber, design and data categories.
- **Security alerts:**
  - Raised for a new device, a new-IP login, a login lockout, a limit hit,
    and a revoked key.
  - Admins can **revoke** a user's key from an alert. That also ends all of
    the user's sessions; the owner generates the replacement.
- **Device binding:**
  - Keys work only from devices the owner approved, matched by pairing code.
  - Unknown devices become pending, capped at 5 per account.
- **Key rotation** by the owner (password required). Keys are shown once.
- **Log out everywhere**, plus a count of active sessions on the dashboard.
- **Admin approval for new keys:** new signups start with the key disabled.
- **Admin panel:** alerts, orgs, users, and a policy editor.
- **Dashboard:** plan and usage view, devices, master key generation for org
  admins.
- **`org_client.py`:** manage an org with its master key.
- `CHANGELOG.md`, MIT `LICENSE`, and a roadmap in the README.
- Refreshed UI: status strip, card layout, usage meters, admin summary tiles,
  and dark mode.

### Security
- Fixed **NoSQL operator injection**: keys and credentials must be strings
  of the exact expected format.
- Fixed **session fixation**: the session ID is regenerated on login and
  signup.
- Fixed **stored XSS** in the admin panel. Added a strict CSP with Trusted
  Types, JSON output escaping, terminal output sanitizing, and input
  validation (types, lengths, control/bidi characters, email allow-list).
- Removed **published default credentials**. Seed passwords come from env
  vars or are random and shown once. Legacy defaults are rotated on boot.
- **Sessions:**
  - The secret comes from env or is generated once and stored, never
    hard-coded.
  - The cookie now rolls with the server-side session.
  - Absolute 8-hour lifetime.
  - `Secure` cookie over HTTPS.
- **Rate limiting:**
  - Login lockout per IP+email.
  - Per-IP login, signup, session-status and API caps.
- **Enumeration:** constant-time login for unknown emails, and a generic
  signup error.
- **Password policy** for new passwords.
- **Key storage:** API keys are stored as SHA-256 hashes (existing keys
  migrated). Admins see prefixes only.
- **Key transport:** keys are accepted only in the `X-API-Key` header, never
  in the URL or body. `Cache-Control: no-store` on auth and API responses.
- **`session-status`** now returns only `{active}`, with no email and no key
  state.
- **CLI:** hidden key prompt or env var, and a warning when `--key` is used.

### Fixed
- Requests could hang when an async route failed. A JSON error handler now
  catches these.
- Active-session lookup scanned every session; it's now an indexed query.
- The dashboard showed "Key is enabled" for disabled users right after login.
- Time and date answers were cached forever.
- "Log out everywhere" logged a server error when refreshing a deleted
  session.
- Oversized request bodies returned 500 instead of 413.

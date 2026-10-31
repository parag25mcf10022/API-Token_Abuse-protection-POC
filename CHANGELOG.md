# Changelog

All notable changes to this project. Dates are in YYYY-MM-DD.

## 2026-10-31

### Added (M1: Claude provider and cost tracking)
- **Claude as a hosted LLM provider** (`llm.js`, official `@anthropic-ai/sdk`):
  - Any model id starting with `claude-` is served by Anthropic, so Claude
    can be the default (`LLM_PROVIDER=anthropic`, default `claude-opus-5-5`)
    or serve chosen categories alongside Ollama (`LLM_MODEL_CODING=...`).
  - Used only when `ANTHROPIC_API_KEY` is set; otherwise Claude routes fall
    back to the default model. The key is never shown in engine status.
  - Streams like Ollama; `CLAUDE_EFFORT` (default `medium`) and
    `CLAUDE_MAX_TOKENS` (default 16000, thinking included).
  - **Prompt caching** of the conversation prefix, so follow-up turns re-read
    it at the cache price. System prompts stay byte-stable for this.
  - **Refusal fallbacks:** if a safety classifier declines, Anthropic retries
    on its recommended model in the same call (`fallbacks: "default"`; not
    sent for Haiku). If everything declines, the engine answers locally.
- **Per-model cost tracking** (`pricing.js`):
  - Each request's USD cost is computed from real usage, including cache
    reads and writes, with every attempt priced at its own model's rate.
    Local models cost $0; unknown models are counted as "unpriced".
  - `LLM_PRICES` overrides or adds prices.
  - Usage buckets record cost per category and requests, tokens and cost per
    model. Spend from declined requests is counted too.
  - The **admin cost guide** shows spend per model for the last 30 days and
    a daily cost estimate per category quota.
  - The **dashboard** and CLI `/usage` show today's and this month's spend;
    each CLI reply shows its cost and cached tokens. `/api/message` returns
    `costUsd` and `cache`.

  - Tested against a mock of the Anthropic API (streaming, caching, fallback
    and refusal paths, cost). Not yet tested with a real API key.

### Changed
- Token metering counts cached input tokens too, so caching lowers cost
  without changing quotas.
- Milestone 1 is complete.

### Security
- Fixed all `npm audit` findings (0 left):
  - Express 4.22.3, which brings `qs` 6.16.2 (DoS fixes);
  - `body-parser` 1.20.9 (body-size and DoS fixes);
  - `proxy-addr` 2.0.8 (IP spoofing through IPv4-mapped IPv6 trust
    subnets).
- Checked afterwards: login, NoSQL operator-injection rejection, 413 for
  oversized bodies, and nested query strings all behave as before.

## 2026-10-30

### Changed (independent per-category quotas, cost guide)
- **Quotas are per category.** Each category has its own daily request and
  token allowance:
  - `perCategoryRequestsPerDay` / `perCategoryTokensPerDay` as the default,
  - `categoryRequestsPerDay` / `categoryTokensPerDay` as overrides.

  Using one category no longer makes the others "used up".
- Account-wide limits are now **opt-in** and labelled as affecting all
  categories. New default: 100 requests and 100,000 tokens per category per
  day, plus a burst of 30/min.
- Policies still on the old shared-budget default are migrated automatically
  (existing per-category caps are kept).
- Per-category token metering, and notifications for category token quotas.
- **Cost guide** (`GET /api/admin/cost-guide`) in the admin policy editor:
  observed or estimated tokens per request per category, local/LLM/worst-case
  ranges, live "what this quota buys" estimates, and a warning when the token
  quota would run out first.
- The user dashboard and CLI `/usage` show per-category request and token
  quotas and the typical cost per request.

### Added (quotas, notifications, classification)
- **Categories & quotas** on the dashboard and in CLI `/usage`: every
  category's daily quota, usage, remaining allowance, and why it's
  unavailable.
- **Quota notifications at 50/75/90/99%** for daily/monthly requests and
  tokens, per-category caps, and the org pool. They're stored per user,
  dismissable, shown as a pop-up on the open dashboard and inline in the CLI.
- **Classifier fixes:**
  - natural maths (`what's 2+3?`, `15% of 80`), writing tasks, and more
    coding/cyber/data terms;
  - ties go to the more specific category;
  - short follow-ups inherit the conversation's category (forged history
    can't pull unrelated questions in).
- The built-in engine computes natural arithmetic without an LLM.
- Scope errors name the classified category and the allowed ones.
- `session-status` reports `invalid_key` and
  `device_approved_for_other_account`; the CLI explains both and accepts a
  new key without restarting.
- **README:** full step-by-step installation (prerequisites per OS,
  `pip install -r requirements.txt` in a venv, MongoDB, optional models,
  troubleshooting).

### Added (setup, routing, account safety)
- **`npm run setup`:** guided, cross-platform setup.
  - Checks Node, Python, MongoDB, Ollama, RAM, GPU and free disk.
  - Installs small dependencies, and **asks before any large download**
    (models, MongoDB image), defaulting to No.
  - Skipping is fine: the built-in engine still answers.
- `requirements.txt` for the Python clients.
- **Coding questions go to `qwen2.5-coder:7b` by default.** A missing routed
  model falls back to the default model; with no model, the engine answers
  locally.
- **Own-password rule:**
  - Every sensitive action verifies the logged-in account's own password.
  - Members created by an admin must set their own password before any key
    action.
  - New `POST /auth/change-password` (current password required; ends other
    sessions), plus a Password card on the dashboard.
- `session-status` gives a `reason` (`no_session`, `key_disabled`,
  `key_locked`, `device_not_approved`) to the owner's approved devices only.
  The CLI shows exactly what it's waiting for and can take a new key after a
  lock without restarting.

### Changed
- The device-spray threshold is now 5 unapproved devices in 24 hours.

### Added (M1: LLM integration, in progress)
- **Local LLM via Ollama** (`llm.js`), used only after every AAP check:
  - Default model `llama3.2:3b`, with per-category routing through
    `LLM_MODEL_<CATEGORY>`.
  - Scope-aware system prompts; the cyber prompt is defensive only.
  - Timeouts, and a fallback to local answers if the model is unavailable.
- `/api/message` can **stream** (`stream: true`, NDJSON with the same output
  escaping) and takes chat **history** for multi-turn conversations.
- **Real token metering** from the model's counts. Local answers aren't
  charged for history. Truncated replies are flagged.
- Admin-only **LLM access** switch per user and org (allow, block, inherit).
- `GET /api/usage` and `/api/engine` for the CLI; `/auth/engine` for the
  dashboard.
- **New shell client:**
  - welcome panel, streamed markdown rendering, a status line per reply,
  - slash commands (`/help /usage /model /device /clear /save /status
    /exit`),
  - one-shot `-p`, `--no-stream`, plain output when piped.
- **Web UI:** engine status and today-by-category cards on the dashboard;
  LLM access in the admin policy editor; engine line in the admin panel.
- The device-spray signal now counts only unapproved devices.

### Added (compromise auto-response)
- Keys are **automatically disabled or rotated** when they look compromised
  or abused:
  - repeated use from unapproved devices (3 per day),
  - 5+ new unapproved devices in 24 hours,
  - a lockout while viewing the key,
  - 50+ limit-blocked requests in a day.
- The action (`alert` | `disable` | `rotate`, default `disable`) is set per
  org by org admins, or per personal account by its owner (password
  required) or the super admin.
- **Recovery:**
  - Team/enterprise members need an org admin to **approve regeneration**,
    then generate the new key with their password.
  - Personal users regenerate with their password.
  - Admins can **unlock** a disabled key after a false alarm.
- New alerts `auto_protect` and `unapproved_device_use`; dashboard lock
  banner and protection setting; admin approve/unlock controls;
  `org_client.py approve-regen | unlock | protection`.
- Accounts pointing at an org that no longer exists are treated as personal.
- Documented that email verification is deferred to M3.

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

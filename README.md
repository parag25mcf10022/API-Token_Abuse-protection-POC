# Account-Bound API Key Protection (AAP) — Demo

API keys here are **account-bound**. A stolen key is useless on its own: the
server only honors a request if

1. the key's owner has an **active authenticated browser session**,
2. an admin has **enabled** the key,
3. the request comes from a **device the owner approved**, and
4. it stays within the key's **scopes and usage limits**, which only admins
   can configure.

Log out, and the very same key stops working.

```
┌──────────┐   login (session cookie)   ┌─────────────────────────────┐
│ Browser  │ ─────────────────────────▶ │  Server (Express)           │
└──────────┘                            │  • web app + dashboards     │
                                        │  • API server /api/message  │
┌──────────┐  1. session-status         │  • org management /api/org  │
│ Shell    │ ─────────────────────────▶ │  • session store (queryable)│
│ client   │  2. POST /api/message      │                             │
│ (CLI)    │ ─────────────────────────▶ │  honors a call ONLY if all  │
└──────────┘  X-API-Key + X-AAP-Device  │  checks pass (see below)    │
                                        └─────────────────────────────┘
```

The shell client is the **bridge**: before sending an API call, it asks the
server whether the key is usable. The CLI itself holds no cookie. The browser
session is what keeps the key alive.

## Files

| File                 | Role                                                          |
|----------------------|---------------------------------------------------------------|
| `server.js`          | Express server: web app, auth, API endpoint, wiring           |
| `adminRoutes.js`     | Admin / org-management API (session or master key)            |
| `db.js`              | MongoDB data layer: users, orgs, devices, hashed keys          |
| `policy.js`          | Content categories, scope/limit policy validation             |
| `usage.js`           | Usage metering + limit enforcement (MongoDB buckets)          |
| `alerts.js`          | Security alerts (new device, new IP, lockout, limits, revoke) |
| `security.js`        | Security headers (CSP) + input validation                     |
| `rateLimit.js`       | In-memory per-IP rate limiter                                 |
| `engine.js`          | Lightweight response engine + content classifier (no LLM)     |
| `public/index.html`  | Login / signup + user dashboard                               |
| `public/app.js`      | Dashboard logic                                               |
| `public/admin.html`  | Admin panel (super admin and org admins)                      |
| `public/admin.js`    | Admin panel logic                                             |
| `public/styles.css`  | Styling                                                       |
| `client.py`          | Python shell client (the bridge)                              |
| `org_client.py`      | Org management CLI using the org master key                   |
| `CHANGELOG.md`       | History of changes                                            |

## Run it

### 0. MongoDB

Make sure MongoDB is reachable (default `mongodb://localhost:27017`). The
server connects on boot and exits with a clear message if it can't.

### 1. Start the server

```bash
npm install
npm start
# → http://localhost:3000
```

### Configuration (env vars)

| Env var              | Default                     | Purpose                                         |
|----------------------|-----------------------------|-------------------------------------------------|
| `PORT`               | `3000`                      | HTTP port                                       |
| `MONGO_URL`          | `mongodb://localhost:27017` | MongoDB connection                              |
| `MONGO_DB`           | `AAP`                       | Database name                                   |
| `SESSION_SECRET`     | random, persisted in DB     | Session-cookie signing secret                   |
| `TRUST_PROXY`        | unset                       | Set to `1` behind a TLS-terminating proxy       |
| `ADMIN_EMAIL`        | `admin@example.com`         | Seeded super admin                              |
| `ADMIN_PASSWORD`     | random, shown once          | Seeded super admin password                     |
| `DEMO_USER_EMAIL`    | `user@example.com`          | Seeded demo user                                |
| `DEMO_USER_PASSWORD` | random, shown once          | Seeded demo user password                       |

On first boot the server seeds a super admin and a demo user. **No passwords
are hard-coded.** Unless you set them through env vars, random passwords are
generated and printed **once** in the console when the accounts are created.

### 2. Open the web app

Go to **http://localhost:3000** and log in. New accounts start with their key
**disabled** until an admin enables it. The full key is shown **once**, at
signup or when you generate a new one; only a hash is stored. **Keep this tab
logged in.** The session is what keeps the key alive.

### 3. Run the shell client

```bash
pip install requests
python3 client.py                      # prompts for the key (hidden)
AAP_API_KEY=ak_... python3 client.py   # or from the environment
```

- On first run it creates a private device token (`~/.config/aap/device`,
  mode 600) and prints a **pairing code**.
- Approve the device on your dashboard. Only approve it if the code matches.
- Once you're logged in, the device is approved and your key is enabled, you
  can send messages.

Avoid `--key ak_...`: command-line arguments show up in `ps` and in shell history.

## Try the security demo

1. Log in, generate a key, run `client.py`, approve the device. ✅ Works.
2. **Log out** in the browser (or **Log out everywhere** if you're logged in
   in several browsers). ❌ `401 No active session found`.
3. Use the key from another machine. ❌ `403 this device is not approved`, and
   the owner sees a new pending device and an alert.
4. As an admin, **Revoke key** for the user. ❌ The old key is dead and all of
   the user's sessions end. The user logs back in and generates a new key,
   which only they ever see.

## Organizations, master keys, scopes and limits

### Roles

| Role            | Can do                                                                 |
|-----------------|------------------------------------------------------------------------|
| **Super admin** | Everything: create orgs, assign org admins and members, manage any user |
| **Org admin**   | Manage members of **their own org only**; generate the org master key  |
| **Member/user** | Use their own key; view their plan and usage; approve their devices    |

Users can **never** change their own scopes or limits.

### Org master key (management only)

- Each org has one master key (`mk_...`), generated by an **org admin** on their
  dashboard with their password. It's shown once and stored hashed.
- It **cannot** send messages. It's only for management: listing members,
  setting policies, enabling, disabling and revoking keys, adding members, and
  handling alerts.
- The server accepts it only **from one of that org admin's approved devices,
  while that admin has a live browser session**. A leaked master key on its own
  does nothing.

```bash
AAP_MASTER_KEY=mk_... python3 org_client.py overview
python3 org_client.py set-policy 7 --scopes general,math,coding \
    --limit requestsPerDay=200 --limit burstPerMinute=20 --cat coding=50
python3 org_client.py org-policy --field policy --limit requestsPerDay=5000
python3 org_client.py alerts
python3 org_client.py revoke 7
```

### Content categories (scopes)

Every message is classified before it's processed:

| Category  | Covers                                              |
|-----------|-----------------------------------------------------|
| `general` | Greetings, help, time/date, questions about AAP     |
| `math`    | Arithmetic (`calc ...`)                             |
| `text`    | `reverse`, `upper`/`lower`, `echo`, `count`         |
| `coding`  | Programming, debugging, APIs, tooling               |
| `cyber`   | Security: vulnerabilities, hardening, threats       |
| `design`  | UI/UX, colour, typography, layout                   |
| `data`    | Data analysis, statistics, spreadsheets, charts     |

A key may only use the categories in its scopes. Anything else gets
`403 your key is not allowed to use the "<category>" category`.

### Usage limits

Admins configure these per user and per org:

| Limit                    | Window                    |
|--------------------------|---------------------------|
| `burstPerMinute`         | requests per minute       |
| `requestsPerDay`         | requests per UTC day      |
| `requestsPerMonth`       | requests per UTC month    |
| `tokensPerDay`           | tokens per day (≈ chars/4, message + reply) |
| `tokensPerMonth`         | tokens per month          |
| `categoryRequestsPerDay` | per-category daily caps, e.g. `{ "coding": 50 }` |

- **User limits** apply to that user's key.
- **Org pool limits** apply to the total across all members.
- Both are enforced, and the stricter one wins. Scopes are intersected the same
  way.
- **Member defaults** are the policy new org members start with.
- New personal accounts get `general`, `math` and `text` scopes, 30/min,
  500/day, 5,000/month, 50k tokens/day and 500k tokens/month.
- Exceeding a limit returns `429` with `Retry-After` and raises an alert.

### Alerts and admin rotation

The server raises alerts for:
- a key used from a **new device**,
- a **login from a new IP**,
- a **login lockout**,
- a **limit exceeded**,
- a **key revoked**.

Super admins see all alerts; org admins see their own org's. **Revoke key**
kills the key and ends every session for that user at once. The owner then
generates the replacement, so admins never see member keys.

## Endpoints

| Method | Path                               | Auth            | Purpose                                         |
|--------|------------------------------------|-----------------|-------------------------------------------------|
| POST   | `/auth/signup`                     | —               | Create account; returns the key **once**        |
| POST   | `/auth/login`                      | —               | Log in, start session                           |
| POST   | `/auth/logout`                     | session         | End this browser's session                      |
| POST   | `/auth/logout-all`                 | session         | End every session for the account               |
| GET    | `/auth/me`                         | session         | Dashboard data (key prefix, plan, usage, org)   |
| POST   | `/auth/rotate-key`                 | session + password | New key, shown once; old key dies            |
| GET    | `/auth/devices`                    | session         | List your devices                               |
| POST   | `/auth/devices/approve`, `/remove` | session         | Approve / remove one of your devices            |
| POST   | `/auth/org/master-key`             | session + password | Org admin: new master key, shown once        |
| GET    | `/auth/session-status`             | `X-API-Key`, `X-AAP-Device` | Returns only `{active}`             |
| POST   | `/api/message`                     | `X-API-Key`, `X-AAP-Device` | **Protected** endpoint              |
| *      | `/api/admin/*`                     | admin session   | Admin API (see below)                           |
| *      | `/api/org/*`                       | `X-AAP-Master-Key`, `X-AAP-Device` | Same API with the master key   |

Admin API (`/api/admin/...` or `/api/org/...`):
- `GET overview`, `GET alerts`, `POST alerts/:id/resolve`
- `POST users/:id/key-enabled`, `POST users/:id/policy`, `POST users/:id/revoke-key`
- `POST orgs/:id/policy` (`field`: `policy` | `memberDefaults`), `POST orgs/:id/members`
- Super admin only: `POST orgs`, `POST users/:id/org`

Keys are accepted **only** in headers. A key in a URL or JSON body is rejected
so it can't end up in logs or shell history.

### `POST /api/message` check order

1. Input valid? (header key, device token, message) → `400`
2. Which user owns the key? → `401 invalid API key`
3. Key enabled by an admin? → `403`
4. Device approved by the owner? → `403` (unknown devices become pending and raise an alert)
5. **Owner has a live browser session?** → `401 No active session found`
6. Message category within the key's scopes (user ∩ org)? → `403`
7. Within user and org usage limits? → `429` with `Retry-After`
8. Run the engine, meter the usage, reply with `reply`, `source`, `category` and `tokens`

## Storage — MongoDB (database `AAP`)

| Collection | Contents                                                                |
|------------|-------------------------------------------------------------------------|
| `users`    | email, scrypt password hash, **SHA-256 key hash** + display prefix, flags, org, role, policy |
| `sessions` | written by `connect-mongo`; `session.userId` is the account binding      |
| `devices`  | per-user devices: token **hash**, pairing code, name, status             |
| `orgs`     | name, **master key hash**, pool policy, member defaults                  |
| `usage`    | per-user/org minute, day and month counters (auto-expire)                |
| `alerts`   | security alerts (kept one year)                                          |
| `config`   | generated secrets (e.g. the session secret)                              |
| `counters` | auto-increment ids                                                       |

No API key, master key or device token is stored in plaintext.

## The response engine (`engine.js`)

`/api/message` runs a **lightweight, local-first** engine instead of calling an
LLM:

1. **Cache:** answers are memoized by normalized message (LRU, 500 entries).
   Time-dependent answers aren't cached.
2. **Rules:** `calc <expr>` (safe arithmetic, no `eval`), `reverse`,
   `upper`/`lower`, `echo`, `count`, time and date, greetings, `help`.
3. **Knowledge:** a small FAQ about AAP, plus short defensive tips for the
   coding, cyber, design and data categories.
4. **Optional LLM fallback:** used *only* if you wire up `llmFallback` in
   `server.js`. Results are cached, so each question hits the LLM at most once.
   It's off by default.

Each response includes `source` (`rule` | `faq` | `cache` | `llm` | `fallback`)
and `category`.

## Security notes

- **Sessions:**
  - Passwords are hashed with scrypt and a per-user salt.
  - Login timing is the same for unknown accounts.
  - The session ID is regenerated on login.
  - Sessions expire after 30 minutes idle (rolling cookie) or 8 hours at most.
  - The cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` over HTTPS.
- **Keys:**
  - Stored as SHA-256 hashes and shown only once.
  - Owners can rotate them with their password.
  - Admins see prefixes only.
- **Rate limits:**
  - 5 failed logins per IP+email lock that account out for 15 minutes.
  - 30 login attempts per IP per 15 minutes.
  - 5 signups per IP per hour.
  - Per-IP caps on the API and on session-status.
- **Passwords:** at least 8 characters, not a common password, not built from
  the email, not a single repeated character.
- **Enumeration:** signup and login don't reveal whether an email is registered.
- **Out of scope for this demo:**
  - MongoDB without auth/TLS.
  - HTTP instead of HTTPS.
  - The in-memory IP limiter, which isn't shared across instances.
  - No email verification.

### XSS protection

Defense in depth: validate input, encode output, and contain anything that
slips through.

- **Input validation** (`security.js`):
  - Every field is type-checked and length-capped (email 254, password 256,
    message 2000; JSON bodies 10 KB).
  - Text is Unicode-normalized and rejected if it contains control or bidi
    override characters.
  - Emails must match a strict allow-list. API keys, master keys, device
    tokens and IDs must match exact formats.
- **Output encoding, per context:**
  - JSON: Express `json escape` encodes `<`, `>` and `&`.
  - HTML: the frontend renders all data with `textContent` and DOM APIs.
  - Terminal: the CLIs strip control characters from server text.
- **Containment headers:**
  - A strict Content-Security-Policy (`script-src 'self'`, no inline script
    or style).
  - **Trusted Types** are enforced.
  - `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and
    `Cache-Control: no-store` on auth and API responses.

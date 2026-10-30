# Account-Bound API Key Protection (AAP) — Demo

API keys here are **account-bound**. A stolen key is useless on its own: the
server only honors a request if the key's owner has an **active authenticated
browser session**. Log out, and the very same key stops working.

```
┌──────────┐   login (session cookie)   ┌─────────────────────────────┐
│ Browser  │ ─────────────────────────▶ │  Server (Express)           │
└──────────┘                            │  • web app + dashboard      │
                                        │  • API server /api/message  │
┌──────────┐  1. session-status?key=…   │  • session store (queryable)│
│ Shell    │ ─────────────────────────▶ │                             │
│ client   │  2. POST /api/message      │  honors call ONLY if the    │
│ (CLI)    │ ─────────────────────────▶ │  key's owner has a live     │
└──────────┘                            │  session in the store       │
                                        └─────────────────────────────┘
```

The shell client is the **bridge**: it asks the server whether the account is
logged in *before* it bothers sending an API call. The CLI itself holds no
cookie — the browser session is what keeps the key alive.

## Files

| File                 | Role                                                        |
|----------------------|-------------------------------------------------------------|
| `server.js`          | Express server: web app, API server, and auth bridge        |
| `engine.js`          | Lightweight response engine for `/api/message` (no LLM)     |
| `db.js`              | MongoDB data layer — database **AAP** (users + counters)    |
| `security.js`        | XSS hardening: security headers (CSP) + input validation    |
| `public/index.html`  | Login / signup + dashboard (shows the user's API key)       |
| `public/admin.html`  | Admin panel — toggle any user's key on/off (bonus)          |
| `public/admin.js`    | Admin panel logic                                           |
| `public/app.js`      | Frontend logic                                              |
| `public/styles.css`  | Styling                                                     |
| `client.py`          | Python shell client (the bridge)                            |

## Storage — MongoDB (database `AAP`)

All state lives in a MongoDB database named **`AAP`**, so you can watch it live
in **MongoDB Compass**:

- Connect Compass to `mongodb://localhost:27017`
- Open the **`AAP`** database. You'll see three collections:
  - **`users`** — one document per account (email, scrypt password hash, API key, `keyEnabled`, `isAdmin`)
  - **`sessions`** — written by `connect-mongo`; each doc's `session.userId` is the account binding. Log in/out and watch docs appear/disappear.
  - **`counters`** — auto-increment source for the numeric user `id`

The AAP check (`userHasActiveSession`) runs an indexed query on the `sessions`
collection (`session.userId` + unexpired `expires`) — exactly the state you can
see in Compass.

Override the connection with env vars if needed:
`MONGO_URL=mongodb://host:27017 MONGO_DB=AAP npm start`.

## Run it

### 0. MongoDB

Make sure MongoDB is running and reachable at `mongodb://localhost:27017`
(the server connects on boot and exits with a clear message if it can't).

### 1. Start the server

```bash
npm install
npm start
# → http://localhost:3000
```

On first boot it seeds two accounts (idempotent — re-runs won't duplicate them).

Seeded accounts:

- `admin@example.com` / `admin123` (admin)
- `user@example.com` / `user123`

You can also sign up a fresh account on the page. **New accounts start with
their API key disabled**: an admin has to enable it in the admin panel
(`/admin.html`) before the key works. The seeded accounts are pre-approved.

### 2. Open the web app

Go to **http://localhost:3000**, log in, and you'll see your API key on the
dashboard. **Keep this tab logged in** — it's the session that keeps the key
alive.

### 3. Run the shell client

```bash
pip install requests
python3 client.py
```

- It prompts for your API key (or pass `--key ak_...`).
- It calls `/auth/session-status` to check if your browser is logged in.
- **If logged in** → it lets you send messages, which it POSTs to
  `/api/message` and prints the reply.
- **If not** → it prints `No active session. Please log in at
  http://localhost:3000`, opens the browser, and polls until you log in.

## Try the security demo

1. Log in on the web app, copy your key, send a message via `client.py`. ✅ Works.
2. **Log out** in the browser. (If the same account is logged in in another
   browser too, that session keeps the key alive. Use **Log out everywhere**
   on the dashboard to end them all at once.)
3. Run `client.py` again with the *same key*. ❌ `401 Unauthorized: No active
   session found`. The key alone is worthless.

## Endpoints

| Method | Path                          | Purpose                                            |
|--------|-------------------------------|----------------------------------------------------|
| POST   | `/auth/signup`                | Create account, start session, return API key      |
| POST   | `/auth/login`                 | Log in, start session                              |
| POST   | `/auth/logout`                | End this browser's session                         |
| POST   | `/auth/logout-all`            | End every session for the account (key stops now)  |
| GET    | `/auth/me`                    | Current user info (dashboard)                      |
| GET    | `/auth/session-status?api_key=` | Is the key's owner logged in? (polled by the CLI) |
| POST   | `/api/message`                | **Protected** — honored only with a live session   |
| GET    | `/api/admin/users`            | Admin: list users + session/key state              |
| POST   | `/api/admin/toggle-key`       | Admin: enable/disable a user's key                 |

### `POST /api/message` validation order

1. Look up which user owns `api_key` → `401` if unknown.
2. Has an admin enabled the key? → `403` if not. (New signups start disabled.)
3. **Does that user have an active session in the store?** → `401 No active
   session found` if not. Any live session for the account counts, so the key
   works while the owner is logged in in at least one browser.
4. All good → process the message and return a reply.

## The response engine (`engine.js`)

`/api/message` runs a **lightweight, local-first** engine instead of calling an
LLM. The goal is responsiveness without being heavy on the server or a model:

1. **Cache** — answers are memoized by normalized message (LRU, 500 entries),
   so repeats are free.
2. **Rules / commands** — deterministic handlers answer most messages in
   microseconds, no network: `calc <expr>` (safe arithmetic, no `eval`),
   `reverse`, `upper`/`lower`, `echo`, `count`, "what time/date is it",
   greetings, `help`, thanks.
3. **FAQ retrieval** — a tiny in-memory knowledge base matched by keyword
   overlap (questions about keys, sessions, security, admin).
4. **Optional LLM fallback** — *only* if the local engine is unsure **and** you
   wire up an `llmFallback`. The result is cached, so a given question hits the
   LLM **at most once**. Disabled by default → the demo makes **zero** model
   calls.

Each response includes a `source` field (`rule` | `faq` | `cache` | `llm` |
`fallback`) so you can see which path answered.

```bash
# all answered locally, no LLM:
{"reply":"12*(3+4) = 84","source":"rule", ...}
{"reply":"Your API key is account-bound...","source":"faq", ...}
{"reply":"Hello! Your session is active...","source":"cache", ...}
```

The engine sits **behind** the AAP check — no active session means a `401`
before the engine ever runs.

### Plugging in an LLM (optional)

In `server.js`, replace `const llmFallback = null;` with an async function
`async (message) => "..."`. To keep it cheap, the engine already caches the
result. If you use Claude, enable **prompt caching** on the system prompt so
repeated calls share a cached prefix and cost less. Because only low-confidence
misses reach the LLM and every answer is cached, model usage stays minimal.

## How the binding works

`server.js` uses `connect-mongo` as the session store (collection `sessions`
in the `AAP` database) with `stringify: false`, so each session is stored as a
real sub-document. `userHasActiveSession(userId)` does a single indexed
`findOne` on `session.userId` (ignoring expired sessions) to see whether the
key's owner is logged in. Because the store is queryable server-side — and persisted in
MongoDB — the API server can answer "is this account logged in?" for any key,
independent of who is calling, and the state survives restarts.

## Security notes (demo scope)

- Passwords are hashed with `scrypt` + per-user salt (`db.js`).
- Session cookie is `HttpOnly` + `SameSite=Lax`, 30-minute expiry.
- `session-status` returns only a boolean and a masked email — never the key.
- `api_key` (and other inputs) must be strings, so MongoDB query operators like
  `{"$ne": null}` can't be injected to match someone else's key.
- The session ID is regenerated on login/signup (no session fixation).

### XSS protection

Defense in depth — validate input, encode output, and contain anything that
slips through:

- **Input validation** (`security.js`): every field is type-checked and
  length-capped (email 254, password 256, message 2000; JSON bodies 10 KB).
  Text is Unicode-normalized and rejected if it contains control or bidi
  override characters. Emails must match a strict allow-list (no quotes,
  angle brackets, `&`, spaces). API keys must match the exact `ak_` + 48-hex
  format before they ever reach the database. Free text is *not* run through
  a "strip `<script>`" filter — those are bypassable and corrupt real data;
  output encoding is what makes it safe.
- **Output encoding, per context:**
  - JSON: Express `json escape` emits `<`, `>`, `&` as `\u003c`, `\u003e`,
    `\u0026`, so no API response can be parsed as markup.
  - HTML: the frontend renders all data with `textContent` / DOM APIs — there
    are no `innerHTML`-style sinks.
  - Terminal: `client.py` strips control characters from server text so
    replies can't inject ANSI/OSC escape sequences.
- **Containment headers:** a strict Content-Security-Policy (`script-src
  'self'`, no inline script or style, `object-src 'none'`, `frame-ancestors
  'none'`) with **Trusted Types** enforced, so string-to-HTML sinks throw even
  if one is added later. Plus `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- This is a **demo**: it uses an unauthenticated local MongoDB, a hard-coded
  session secret, and HTTP. For production: secured MongoDB (auth + TLS),
  env-provided secret, HTTPS, rate limiting, and CSRF protection on the auth
  routes.
```

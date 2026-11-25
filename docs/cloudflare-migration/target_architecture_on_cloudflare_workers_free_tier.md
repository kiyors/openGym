Forking `DuarteSantos8/openGym` and patching it to run on the **Cloudflare Workers Free Tier** is very doable—especially because its backend (`api/`) is intentionally tiny (plain `node:http`, JSON persistence, and only three npm dependencies: `@simplewebauthn/server`, `web-push`, and `undici`).

The clean way to keep your fork easy to rebase against upstream is **not** to rewrite openGym from scratch, and **not** to rely on Cloudflare's virtual `node:fs` (which is ephemeral in-memory per isolate and loses all writes on recycle). Instead, add a thin **Workers adapter directory** (e.g., `worker/`) that reuses openGym's existing domain modules (`api/sync-stamps.js`, `api/coach/core/`, `mcp/` tool logic) while swapping only the HTTP entry point and persistence layer.

---

## 1. Target Architecture on Cloudflare Workers Free Tier

Every piece of openGym's Docker stack maps cleanly onto Cloudflare's Free Plan services:

| openGym Component                            | Upstream (Docker)                                          | Cloudflare Workers Free Replacement                                            | Free Tier Headroom                              |
| -------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------ | ----------------------------------------------- |
| **Web UI + 180 px Media**                    | `web` container (`nginx` + Vite build + `catalogue/media`) | **Workers Static Assets** (with R2 overflow if media exceeds 20k files)        | 20,000 files/version, up to 25 MiB/file         |
| **HTTP API**                                 | `api/server.js` (`node:http`)                              | **Cloudflare Worker** (`Hono` or Web Fetch router)                             | 100,000 req/day, 128 MB RAM, 64 MiB bundle      |
| **JSON Files (`db.json`, `state-uid.json`)** | Local disk (`./data` via `durable.js`)                     | **Cloudflare D1** (SQLite)                                                     | 5 GB storage, 5M reads/day, 100k writes/day     |
| **Custom Media (`uploads/`)**                | Local disk (`./data/uploads`)                              | **Cloudflare R2** _(optional; disable via `MEDIA_UPLOADS=0` if skipped)_       | 10 GB-mo, 1M Class A, 10M Class B ops/mo        |
| **Remote MCP (`/mcp`)**                      | Separate `COMPOSE_PROFILES=mcp` container                  | **Streamable HTTP `/mcp` route** on the same Worker (or SQLite Durable Object) | SQLite DOs included on Free: 100k req/day, 5 GB |

_(Note: Verify `catalogue/media` file count before deploying—if stills + animations + frontend build stay under 20,000 files, Workers Static Assets hosts the entire app and media for free with zero R2 setup; otherwise serve `/exercise-media/*` from R2.)_

---

## 2. The 5 Core Patches Needed in Your Fork

### Patch 1: Replace `durable.js` File I/O with a D1 Storage Adapter

Upstream stores accounts in `db.json` and each user's workout state in `state-<uid>.json`, relying on atomic temp-file renames for concurrency. Replace that with a small `worker/storage.js` module backed by **Cloudflare D1**, using SQLite's `WHERE rev = ?` for atomic optimistic locking (preserving openGym's exact `409 Conflict` merge protocol):

```sql
-- worker/migrations/0001_init.sql
CREATE TABLE IF NOT EXISTS users (
  uid TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE,
  session_version INTEGER NOT NULL DEFAULT 1,
  is_admin INTEGER NOT NULL DEFAULT 0,
  is_owner INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS passkeys (
  credential_id TEXT PRIMARY KEY,
  uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  label TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_states (
  uid TEXT PRIMARY KEY REFERENCES users(uid) ON DELETE CASCADE,
  rev INTEGER NOT NULL DEFAULT 0,
  state_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Short-lived WebAuthn challenges, 5-min mobile pairing codes, and MCP OAuth codes
CREATE TABLE IF NOT EXISTS ephemeral_codes (
  code TEXT PRIMARY KEY,
  kind TEXT NOT NULL,       -- 'challenge' | 'pair' | 'oauth_code'
  uid TEXT,
  payload_json TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

-- Scoped API tokens (including tokens issued to Claude/Gemini/OpenCode via MCP)
CREATE TABLE IF NOT EXISTS api_tokens (
  token_sha256 TEXT PRIMARY KEY,
  uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  label TEXT NOT NULL,
  scopes_json TEXT NOT NULL, -- per-category 'off' | 'view' | 'apply'
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);

```

For `PUT /api/data`, execute an atomic compare-and-swap update:

```js
// Atomic revision check matching openGym's 409 sync contract
const res = await env.DB.prepare(`
  UPDATE user_states
  SET rev = rev + 1, state_json = ?, updated_at = ?
  WHERE uid = ? AND rev = ?
`)
  .bind(nextJson, Date.now(), uid, baseRev)
  .run();

if (res.meta.changes === 0) {
  const current = await env.DB.prepare("SELECT rev, state_json FROM user_states WHERE uid = ?")
    .bind(uid)
    .first();
  return Response.json(
    { error: "conflict", rev: current.rev, data: JSON.parse(current.state_json) },
    { status: 409, headers: corsHeaders(request) },
  );
}
```

### Patch 2: Keep Every Request Under the 10 ms Free-Tier CPU Ceiling

Cloudflare Workers Free enforces a strict **10 ms CPU time cap per HTTP request** (wall-clock time waiting on `fetch()` or D1 does not count—only active JS/crypto execution counts). Four small patches guarantee you never hit `exceededCpu`:

- **Keep `PASSWORD_LOGIN` disabled:** Upstream hashes passwords with `scrypt`, which blows past 10 ms CPU on Workers Free. Use **Passkeys** (`@simplewebauthn/server` v14+ runs natively on Workers via WebCrypto) plus **mobile pairing codes**—both finish in under 2 ms.
- **Use WebCrypto for HMAC session tokens:** Keep openGym's exact `<uid>:<expiry-ms>:<session-version>.<hmac-sha256>` token format using `crypto.subtle` and store `SESSION_SECRET` as a Wrangler secret instead of `./data/secret`.
- **Fast-path `PUT /api/data` for modern clients:** Upstream runs `sync-stamps.js` across the entire JSON document on every write to protect legacy clients. Since your own phone app and PWA already stamp every field client-side, skip full-tree server re-stamping when the payload already carries `_stamps` (saving several milliseconds of CPU on multi-year logs).
- **Drop `undici` and `web-push`:** Replace `undici` with Workers' built-in global `fetch()`. Native iOS/Android apps already handle rest timers via local OS notifications, so omit `web-push` to shrink bundle size and cold-start time.

### Patch 3: Preserve Exact Mobile App Pairing & CORS/CSRF Rules

So you can connect the **unmodified official iOS/Android openGym app** directly to your Worker URL without recompiling the mobile apps, replicate these three behaviors from `api/openapi.yaml`:

- **CORS Reflection:** Always echo the incoming `Origin` header (`https://localhost` on Android, `capacitor://localhost` on iOS) in `Access-Control-Allow-Origin`, allow `GET, POST, PUT, DELETE, OPTIONS` and headers `Content-Type, Authorization`, and **never** send `Access-Control-Allow-Credentials: true`.
- **Pairing Flow:** Implement `POST /api/pair/create` (authenticated by browser cookie, writes a 5-minute code to `ephemeral_codes`) and `POST /api/pair/redeem` (exempt from CSRF origin check, returns `{ token }` signed with your HMAC secret).
- **Auto-Renewing Bearer Token:** On `GET /api/me`, if a Bearer token is past half its `SESSION_DAYS` lifetime, include a freshly signed `token` in the response JSON so the phone stays logged in indefinitely.

### Patch 4: Embed the Remote MCP Endpoint (`/mcp`) Directly in the Worker

This directly solves your subscription goal—connecting your existing **Claude**, **Gemini**, or **OpenCode** subscription to your workout data without a separate container:

- **Stateless Streamable HTTP (`POST /mcp`):** Handle JSON-RPC (`initialize`, `tools/list`, `tools/call`) directly inside the Worker by reading/writing the user's `user_states` row in D1 via their scoped Bearer token from `api_tokens`. (If a client requires stateful MCP sessions, route `/mcp` to Cloudflare's `McpAgent` on a **SQLite-backed Durable Object**, which is also included on Workers Free.)
- **OAuth Discovery for Claude & Gemini Apps:** Expose `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`, `/api/mcp/authorize` (consent screen minting an `ephemeral_codes` entry), and `/api/mcp/token` (exchanging the code for a scoped `api_tokens` Bearer token).
- **Direct Token Support for OpenCode / CLI:** For OpenCode, Gemini CLI, or Claude Code, you can skip OAuth completely and mint a scoped token from `Settings → API Tokens` to pass as `Authorization: Bearer <token>` to `https://<your-worker>/mcp`.

### Patch 5: Configure `wrangler.jsonc` with `run_worker_first`

Without `run_worker_first`, Cloudflare Static Assets can intercept `/api/*` or `/mcp` before your Worker runs. Use a `compatibility_date` of `2026-08-04` or later so Node.js compatibility (`nodejs_compat` + `nodejs_compat_v2`) is active automatically:

```jsonc
// wrangler.jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "opengym-worker",
  "main": "worker/src/index.js",
  "compatibility_date": "2026-11-01",
  "assets": {
    "directory": "./frontend/dist",
    "binding": "ASSETS",
    "not_found_handling": "single-page-application",
    "run_worker_first": ["/api/*", "/mcp", "/mcp/*", "/.well-known/*"],
  },
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "opengym-db",
      "database_id": "<your-d1-id>",
      "migrations_dir": "worker/migrations",
    },
  ],
  "vars": {
    "RP_ID": "gym.yourdomain.com",
    "ORIGIN": "https://gym.yourdomain.com",
    "RP_NAME": "openGym",
    "FIRST_USER_ADMIN": "1",
    "MCP": "on",
    "MEDIA_UPLOADS": "0",
    "PASSWORD_LOGIN": "0",
  },
}
```

---

## 3. Step-by-Step Build & Deployment Order

1. **Fork openGym and create a dedicated Worker branch:** Keep patches isolated inside worker/ for clean upstream rebases.
   Fork `DuarteSantos8/openGym`, clone it locally, and create a `cloudflare-worker` branch. Keep all Cloudflare-specific code inside a new `worker/` folder and `wrangler.jsonc` at the repo root so merging upstream frontend/catalogue updates rarely causes conflicts. _(Licensing note: openGym is AGPL-3.0, so if you expose your modified server to other users over the network, keep your fork public under AGPL-3.0.)_

2. **Verify frontend build and static asset file count:** Must stay under 20,000 files for Workers Static Assets Free Tier.
   Run the frontend build (`npm ci && npm run build` inside `frontend/`) and copy `catalogue/media` into `frontend/dist/exercise-media`. Check total file count (`find frontend/dist -type f | wc -l`). If it is under 20,000, Static Assets hosts everything; if over 20,000, upload `catalogue/media` to an R2 bucket and proxy `/exercise-media/*` through the Worker (or a public R2 custom domain).

3. **Provision D1 database and Wrangler secrets:**
   Run `npx wrangler d1 create opengym-db`, paste the returned ID into `wrangler.jsonc`, apply `worker/migrations/0001_init.sql` (`--remote`), and generate your HMAC signing key via `openssl rand -hex 32 | npx wrangler secret put SESSION_SECRET`.

4. **Implement core Worker routes first (Auth + Pairing + Data Sync + MCP):**
   Start with the minimum viable subset of `api/openapi.yaml` that powers 100% of personal use:

- **Meta:** `GET /api/health`, `GET /api/config`
- **Passkey Auth & Sessions:** `POST /api/register/{options,verify}`, `POST /api/login/{options,verify}`, `GET /api/me`, `POST /api/logout`, `POST /api/logout/all`
- **Mobile Pairing:** `POST /api/pair/create`, `POST /api/pair/redeem`
- **State Sync:** `GET /api/data`, `PUT /api/data`
- **Scoped Tokens & MCP:** `/api/tokens*`, `/.well-known/*`, `/api/mcp/*`, `POST /mcp`

Test locally with `npx wrangler dev` and run openGym's existing CORS preflight `curl -si -X OPTIONS` check against `http://localhost:8787/api/pair/redeem`.

5. **Deploy, pair your phone, and attach your AI subscriptions:**
   Run `npx wrangler deploy`. Visit your HTTPS URL (`[https://gym.yourdomain.com](https://gym.yourdomain.com)` or `*.workers.dev`), create your passkey profile, pair your Android/iOS openGym app under **Settings → Account → Pair the mobile app**, and connect **Claude**, **Gemini**, or **OpenCode** to `https://<your-host>/mcp`.

---

To kick off the actual code for your fork right now, we can scaffold the complete `worker/` implementation (Hono router + D1 adapter + WebAuthn passkeys + mobile pairing + Streamable HTTP `/mcp` tools) directly.

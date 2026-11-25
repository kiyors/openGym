Here is the complete end-to-end blueprint to fork `DuarteSantos8/openGym` and port **everything**—the **React Web PWA + exercise animations**, **full API backend**, **Remote MCP server**, and **optional custom media / AI Coach / webhooks**—onto **Cloudflare Workers Free Tier + D1 (+ optional R2)** while keeping your fork easy to rebase against upstream.

---

## 1. Full-Stack Target Architecture

Everything runs inside **one Cloudflare Worker** backed by **Workers Static Assets** and **Cloudflare D1** (plus **R2** only if you want custom exercise photos/videos or if static media ever crosses 20,000 files):

| Layer                         | Upstream (`DuarteSantos8/openGym`)                   | Your Cloudflare Worker Port                               | Free Tier Limit (Nov 2026)                                                                        |
| ----------------------------- | ---------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| **Web PWA + 180 px Media**    | `web` container (`nginx` + Vite + `catalogue/media`) | **Workers Static Assets** (`frontend/dist`)               | **Unlimited free asset requests**; up to **20,000 files** / version, **25 MiB** max/file          |
| **HTTP API**                  | `api/server.js` (`node:http`)                        | **Hono Worker** (`worker/src/index.ts`)                   | **100,000 req/day**, **10 ms CPU/req**, **128 MB RAM**, **64 MiB** bundle, **50 subrequests/req** |
| **Database & Sync State**     | `./data/db.json`, `state-<uid>.json`, `audit.log`    | **Cloudflare D1** (SQLite)                                | **5 GB** storage, **5M** row reads/day, **100k** row writes/day                                   |
| **Remote MCP (`/mcp`)**       | Separate `mcp` container                             | **Merged into same Worker** (Streamable HTTP + OAuth 2.1) | Shares Worker + D1 directly (zero extra hops or containers)                                       |
| **Custom Media (`uploads/`)** | Local disk `./data/uploads`                          | **Cloudflare R2** _(optional)_                            | **10 GB-mo** storage, **1M** Class A / **10M** Class B ops/mo, $0 egress                          |

> **Important billing note on R2:** Workers, Static Assets, and D1 run on the Free Plan with zero payment setup. **R2 is free up to 10 GB/mo, but Cloudflare requires a payment method on file to activate R2.** If you want strictly zero-card hosting, keep `MEDIA_UPLOADS=0` and ensure your frontend + exercise clips stay under 20,000 Static Asset files (180 px clips + stills for ~5,632 exercises total ~11,500–13,000 files, which fits inside the 20,000-file Free limit).

---

## 2. Clean Fork & Repository Layout

Do not rewrite `frontend/`, `catalogue/`, or `api/server.js` in place. Keep all Cloudflare code isolated so `git pull upstream main` stays conflict-free:

```text
openGym/
├── frontend/                   # Untouched upstream React 19 + Vite PWA
├── catalogue/                  # Untouched upstream 5,632 exercises + 180 px media
├── api/coach/core/             # Reused directly (pure prompt/validation logic)
├── mcp/src/                    # Reused pure logic (state.js, labels.js, tools.js)
├── scripts/
│   └── build-worker-assets.mjs # Builds frontend/dist + copies exercise-media + checks <20k file cap
├── worker/
│   ├── migrations/
│   │   └── 0001_init.sql       # Complete D1 schema
│   └── src/
│       ├── index.ts            # Hono app + CORS/CSRF + route mounting
│       ├── env.ts              # Typed Cloudflare bindings (DB, ASSETS, R2, secrets)
│       ├── crypto.ts           # WebCrypto HMAC-SHA256 sessions + AES-GCM secret sealing
│       ├── routes/
│       │   ├── meta.ts         # GET /api/health, GET /api/config
│       │   ├── auth.ts         # @simplewebauthn/server passkeys, device-link, sessions
│       │   ├── pair.ts         # POST /api/pair/create, POST /api/pair/redeem
│       │   ├── data.ts         # GET/PUT /api/data (atomic D1 CAS + 409 merge)
│       │   ├── tokens.ts       # /api/tokens* (scoped API tokens)
│       │   ├── admin.ts        # /api/admin/* (invites, users, audit log)
│       │   ├── media.ts        # /api/media/* (R2-backed, gated by MEDIA_UPLOADS)
│       │   ├── coach.ts        # /api/coach/* (direct fetch to Gemini/OpenAI/Anthropic/OpenCode)
│       │   ├── webhooks.ts     # /api/integrations/* (async ctx.waitUntil delivery)
│       │   └── mcp.ts          # /.well-known/*, /api/mcp/* (OAuth 2.1), POST /mcp
│       └── mcp/
│           └── adapter.ts      # Wraps upstream mcp/src tools against D1 user_states
└── wrangler.jsonc              # Worker, Static Assets, D1, optional R2, env vars

```

---

## 3. Complete Cloudflare D1 Schema (`worker/migrations/0001_init.sql`)

This schema covers **every subsystem** in openGym (multi-user passkeys, atomic workout sync, mobile pairing, scoped MCP/API tokens, OAuth 2.1 connectors, admin invites, audit logging, optional R2 media metadata, AI Coach config/history, and webhooks):

```sql
PRAGMA foreign_keys = ON;

-- 1. Accounts & roles (replaces users[] in db.json)
CREATE TABLE IF NOT EXISTS users (
  uid TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE,
  session_version INTEGER NOT NULL DEFAULT 1,
  is_admin INTEGER NOT NULL DEFAULT 0,
  is_owner INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

-- 2. WebAuthn Passkeys (multiple passkeys per profile)
CREATE TABLE IF NOT EXISTS passkeys (
  credential_id TEXT PRIMARY KEY,
  uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  public_key TEXT NOT NULL,          -- base64url encoded COSE key
  counter INTEGER NOT NULL DEFAULT 0,
  device_type TEXT,                  -- 'singleDevice' | 'multiDevice'
  backed_up INTEGER NOT NULL DEFAULT 0,
  transports_json TEXT,              -- JSON array e.g. ["internal","hybrid"]
  label TEXT,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_passkeys_uid ON passkeys(uid);

-- 3. Per-user app state blob (replaces state-<uid>.json with atomic CAS rev)
CREATE TABLE IF NOT EXISTS user_states (
  uid TEXT PRIMARY KEY REFERENCES users(uid) ON DELETE CASCADE,
  rev INTEGER NOT NULL DEFAULT 0,
  state_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

-- 4. Short-lived codes: WebAuthn challenges, 5-min mobile pair codes,
--    device-link codes, admin invites, and OAuth 2.1 authorization codes
CREATE TABLE IF NOT EXISTS ephemeral_codes (
  code TEXT PRIMARY KEY,
  kind TEXT NOT NULL,                -- 'challenge' | 'pair' | 'device_link' | 'invite' | 'oauth_code'
  uid TEXT REFERENCES users(uid) ON DELETE CASCADE,
  payload_json TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ephemeral_exp ON ephemeral_codes(expires_at);

-- 5. Scoped API tokens & OAuth 2.1 MCP tokens (only SHA-256 stored)
CREATE TABLE IF NOT EXISTS api_tokens (
  token_sha256 TEXT PRIMARY KEY,
  uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  label TEXT NOT NULL,
  scopes_json TEXT NOT NULL,         -- e.g. {"workouts":"apply","routines":"apply","body":"view"}
  client_id TEXT,                    -- populated for OAuth MCP clients (Claude/Gemini)
  refresh_sha256 TEXT UNIQUE,        -- rotating OAuth refresh token hash
  expires_at INTEGER,                -- NULL for manual tokens, timestamp for OAuth tokens
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_uid ON api_tokens(uid);

-- 6. Custom exercise & workout media index (bytes live in R2)
CREATE TABLE IF NOT EXISTS media_objects (
  uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  sha256 TEXT NOT NULL,
  mime TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  r2_key TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  deleted_at INTEGER,
  PRIMARY KEY (uid, sha256)
);

-- 7. Admin & security audit log (replaces audit.log)
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  uid TEXT,
  action TEXT NOT NULL,
  ip TEXT,
  detail_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

-- 8. Optional AI Coach config (instance-level) & per-user chat state
CREATE TABLE IF NOT EXISTS coach_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  enabled INTEGER NOT NULL DEFAULT 0,
  active_provider TEXT,
  providers_enc_json TEXT NOT NULL,  -- AES-GCM sealed provider keys & endpoints
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS coach_threads (
  uid TEXT PRIMARY KEY REFERENCES users(uid) ON DELETE CASCADE,
  intake_json TEXT,
  messages_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

-- 9. Optional outbound webhooks (Home Assistant, n8n, ntfy)
CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY,
  uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  url TEXT NOT NULL,
  secret_enc TEXT NOT NULL,
  events_json TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);

```

---

## 4. Critical Free-Tier Engineering Rules (Avoiding the 10 ms CPU Trap)

Cloudflare Workers Free gives you **unlimited wall-clock wait time** on network/D1 calls, but strictly enforces **10 ms of active CPU time per HTTP request**. Follow these five rules across all phases:

1. **Use Passkeys, Not `scrypt` Passwords:** Keep `PASSWORD_LOGIN=0`. `@simplewebauthn/server` (v13+) runs natively on Workers via WebCrypto in ~1–3 ms CPU. `scrypt` password hashing will exceed 10 ms and throw Error 1102.
2. **Use `crypto.subtle` for All Crypto:** Implement openGym's `<uid>:<expiry-ms>:<session-version>.<hmac>` session cookies/tokens, SHA-256 API token hashing, and AES-GCM secret sealing (for Coach keys & webhook secrets) using WebCrypto rather than Node's synchronous crypto helpers.
3. **Skip Full-Tree Server Re-Stamping for Modern Clients:** In `PUT /api/data`, rely on atomic SQLite compare-and-swap (`WHERE uid = ? AND rev = ?`) and only run `sync-stamps.js` if a payload arrives without client-generated `_stamps`. That keeps sync writes around ~1–2 ms CPU even with years of workouts.
4. **Serve Static Assets Before the Worker:** Configure `wrangler.jsonc` with `run_worker_first: ["/api/*", "/mcp", "/mcp/*", "/.well-known/*"]`. Every HTML, JS, CSS, locale, and 180 px exercise animation request is served directly by Cloudflare's edge CDN for **0 ms Worker CPU** and **0 daily Worker quota**.
5. **Run Webhooks & Cleanup Asynchronously:** Deliver outbound webhooks and prune expired `ephemeral_codes` inside `c.executionCtx.waitUntil(...)` so API responses stay instant.

---

## 5. `wrangler.jsonc` Master Configuration

```jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "opengym",
  "main": "worker/src/index.ts",
  "compatibility_date": "2026-11-01",
  "compatibility_flags": ["nodejs_compat"],
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
  // Uncomment only if enabling custom exercise photos/videos (MEDIA_UPLOADS=1)
  // "r2_buckets": [
  //   { "binding": "MEDIA", "bucket_name": "opengym-media" }
  // ],
  "vars": {
    "RP_ID": "gym.yourdomain.com",
    "ORIGIN": "https://gym.yourdomain.com",
    "RP_NAME": "openGym",
    "SESSION_DAYS": "90",
    "FIRST_USER_ADMIN": "1",
    "INVITE_ONLY": "1",
    "ALLOW_GUEST": "0",
    "PASSWORD_LOGIN": "0",
    "MCP": "on",
    "MEDIA_UPLOADS": "0",
    "INTEGRATIONS": "webhook",
  },
}
```

> **Pick your final hostname before creating your first account.** Passkeys are permanently bound to `RP_ID` (`gym.yourdomain.com` or `opengym.<subdomain>.workers.dev`). Changing `RP_ID` later invalidates previously registered passkeys.

---

## 6. Phased Execution Plan (Zero to Full Parity)

### Phase 1: Fork, Build Pipeline & Static Web Deployment

- Fork `DuarteSantos8/openGym` and create a `cf-worker` branch.
- Write `scripts/build-worker-assets.mjs` to:

1. Run `npm ci && npm run build` inside `frontend/`.
2. Copy `catalogue/media` into `frontend/dist/exercise-media`.
3. Assert total file count is under `20,000` (and individual files under `25 MiB`).

- Provision D1 (`wrangler d1 create opengym-db`), apply `0001_init.sql`, and set `SESSION_SECRET` + `ENC_KEY` via `wrangler secret put`.
- **Verification:** Deploy a skeleton Hono Worker with `GET /api/health` and `GET /api/config`. Open your HTTPS URL—the full React PWA loads, all 5,632 exercise animations play, and Workers dashboard reports 0 Worker invocations for static assets.

### Phase 2: Passkeys, Sessions, Mobile Pairing & Atomic State Sync

- Implement `routes/auth.ts` using `@simplewebauthn/server` (`register/{options,verify}`, `login/{options,verify}`, multi-passkey CRUD, `device-link`, `GET /api/me`, `POST /api/logout`, `POST /api/logout/all`).
- Implement CSRF enforcement (`Sec-Fetch-Site` / `Origin` check against `env.ORIGIN`, exempting `POST /api/pair/redeem` and Bearer-only API requests) plus exact CORS reflection (`Access-Control-Allow-Origin` echoed for `https://localhost` and `capacitor://localhost`, **no** `Allow-Credentials`).
- Implement `routes/pair.ts` (`/api/pair/create` + `/api/pair/redeem`) and auto-renewing Bearer tokens inside `GET /api/me`.
- Implement `routes/data.ts` (`GET /api/data` and atomic CAS `PUT /api/data` returning `409` on revision mismatch).
- **Verification:**

1. Register your passkey on the Web PWA (becomes owner/admin via `FIRST_USER_ADMIN=1`).
2. Run `curl -si -X OPTIONS https://<your-host>/api/pair/redeem -H 'Origin: https://localhost'` and verify `204` with a single `access-control-allow-origin: https://localhost`.
3. Pair the unmodified official Android/iOS app via **Settings → Account → Pair the mobile app**, log a workout on the phone, and confirm it appears immediately on the Web PWA.

### Phase 3: Merged Remote MCP Server + OAuth 2.1 (Claude, Gemini & OpenCode)

- Implement `routes/tokens.ts` (`/api/tokens*`) so you can mint scoped Bearer tokens directly from the Web UI's Settings page for **OpenCode**, **Claude Code**, and **Gemini CLI**.
- Port `mcp/src/state.js`, `mcp/src/labels.js`, and `mcp/src/tools.js` into `worker/src/mcp/adapter.ts`, reading/writing D1 `user_states` with atomic `rev` increments so AI-created routines merge cleanly onto your phone.
- Implement Streamable HTTP at `POST /mcp` plus RFC 9728 / OAuth 2.1 + PKCE discovery endpoints (`/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`, `/api/mcp/authorize`, `/api/mcp/token`, `/api/mcp/revoke`)—wired into the Web PWA's built-in consent screen. _(You can implement these 4 routes directly against D1 `ephemeral_codes` + `api_tokens` to avoid needing KV.)_
- **Verification:** Connect OpenCode/CLI via Bearer token and Claude/Gemini apps via **Settings → Use your subscription**. Ask your AI to inspect your recent workouts and push a new routine, then confirm it syncs to both Web and Mobile.

### Phase 4: Admin Dashboard, Optional AI Coach, Webhooks & Optional R2 Media

- Implement `routes/admin.ts` (`/api/admin/*`) for invite codes, account management, and audit logs.
- Wire `routes/coach.ts` using `api/coach/core/` over standard `fetch()` so the built-in **Plan → Coach** also works with Gemini free-tier keys, OpenRouter, or OpenCode Go (remembering that LLM wait time does not count against the 10 ms CPU cap).
- Wire `routes/webhooks.ts` using HMAC-signed outbound `fetch()` inside `ctx.waitUntil(...)`.
- _(Optional, if you enable R2)_ Wire `routes/media.ts` (`GET/PUT/DELETE /api/media/:hash`) against `env.MEDIA` + `media_objects` table, and flip `MEDIA_UPLOADS=1`.

### Phase 5: Automated CI/CD & Safe Upstream Syncs

- Add `.github/workflows/deploy-worker.yml` to run on pushes to `cf-worker`: build frontend + exercise media → verify file count under 20,000 → apply pending D1 migrations (`wrangler d1 migrations apply opengym-db --remote`) → `wrangler deploy`.
- Periodically run `git fetch upstream && git rebase upstream/main` to pull new exercises, translations, and frontend improvements automatically.
- _(License reminder)_ openGym is **AGPL-3.0**—if anyone besides you uses your hosted Worker, keep your fork public under AGPL-3.0.

---

## Interactive Full-Stack Migration & Architecture Roadmap

Step through the **5 migration phases** or switch between the **Legacy Docker Stack** and **Cloudflare Workers Edge Stack** below to inspect how Web, API, MCP, D1, and R2 connect and how each layer fits inside Cloudflare's Free Tier:
./target_architecture_on_cloudflare_workers_free_tier_visual_representation_v3.html
---

Ready to start building? The fastest next step is generating the Phase 1–2 runnable starter files (`wrangler.jsonc`, `scripts/build-worker-assets.mjs`, `worker/migrations/0001_init.sql`, and the Hono Worker with Passkeys, Mobile Pairing, and Atomic D1 Sync) so you can deploy a working Web + Mobile instance in one session, then drop in Phase 3 (`/mcp`) immediately after.

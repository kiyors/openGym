openGym has **no native desktop app** (only iOS/iPadOS, Android APK, and the browser PWA) [1.1.1, 2.1.5]. Since you are using the **mobile app + your AI subscriptions** and skipping web usage for now, you do **not** need to port the React frontend or its ~80 MB exercise animation library.

Instead, your best architecture is **one single Cloudflare Worker** that merges the **trimmed API + Remote MCP endpoint**, backed by **Cloudflare D1**—with a clean slot to drop in the full Web UI later with zero backend rewrite.

---

## 1. Scope Decision Matrix: What to Port vs. Skip

| Component                      | Upstream Stack                                                                       | Your Fork Plan                            | Why                                                                                                                                                               |
| ------------------------------ | ------------------------------------------------------------------------------------ | ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Core Sync & Pairing API**    | `api/server.js` (`node:http` + JSON disk)                                            | **Port Now (Trimmed)**                    | Required for mobile app sync (`GET/PUT /api/data`), bearer token renewal (`/api/me`), and pairing (`/api/pair/redeem`) [1.3.1, 2.2.2].                            |
| **Remote MCP Server**          | Separate `mcp` container (`mcp/src/http.js`)                                         | **Port Now (Merged into same Worker)**    | Powers your Claude, Gemini, and OpenCode subscriptions at `/mcp`—running inside the same Worker eliminates network hops and reads D1 directly [2.2.2, 2.2.3].     |
| **Auth & Consent Bridge**      | Full React Settings UI                                                               | **Replace with CLI script OR ~2 KB HTML** | You only need a way to mint a 5-minute phone pairing code and (optionally) approve Claude/Gemini OAuth [1.3.1, 2.2.3].                                            |
| **Full Web UI + 180 px Media** | `web` container (`nginx` + Vite + 5,632 clips)                                       | **Skip for Now**                          | The Android/iOS app already bundles all 5,632 exercise animations locally offline [1.1.2, 2.1.4]. Adding Web later is a 5-line `wrangler.jsonc` change.           |
| **Heavy / Unused Features**    | `scrypt` passwords, `web-push`, built-in `coach/`, `trainers`, `library`, `uploads/` | **Skip for Now**                          | Phone handles local notifications natively [1.1.2]; MCP replaces the built-in Coach; skipping `scrypt` keeps CPU comfortably under Cloudflare's 10 ms Free limit. |

---

## 2. One Key Design Choice: How You Handle Login Without the Web UI

Even if you never open openGym in a browser to log workouts, upstream relies on a browser for two setup tasks: **pairing your phone** (mobile WebViews cannot run WebAuthn passkeys) and **OAuth consent** (for remote connectors) [1.3.1, 2.2.3]. Pick the track that matches which AI clients you actually use:

- **Track A — Pure Headless + CLI Bootstrap (Zero HTML, Simplest):**
- **Best if you only connect CLI/IDE clients** (**OpenCode**, **Claude Code**, **Gemini CLI**).
- Skip passkeys and OAuth completely. Use two tiny local scripts (`wrangler d1 execute`) to seed your single user profile, generate an 8-character pairing code for the phone app, and mint a scoped Bearer token for `/mcp`.
- **Zero frontend code, zero WebAuthn dependencies.**

- **Track B — Headless API + Tiny Micro-Auth UI (~2 KB Server-Rendered HTML):**
- **Required if you want to connect the Claude or Gemini web/mobile apps** via remote MCP connectors (which enforce OAuth 2.1 + PKCE + consent screen) [2.2.3].
- Your Worker serves 3 ultra-light HTML pages (no React, no Vite, no static assets): `/setup` (one-time passkey registration), `/pair` (click to get an 8-char mobile pairing code), and `/api/mcp/authorize` (approve/deny OAuth connector screen).

---

## 3. Phased Implementation Plan

### Phase 0: Fork & Repo Structure (Keep Upstream Rebases Clean)

1. Fork `DuarteSantos8/openGym` and create a `cf-worker` branch.
2. Put **all** new code inside a dedicated `worker/` directory plus a root `wrangler.jsonc`. Do **not** modify `frontend/` or `api/server.js` directly—import reusable pure logic (such as `mcp/src/state.js`, `mcp/src/tools.js`, and `mcp/src/labels.js`) so pulling upstream updates stays painless [2.2.2].
3. _(License reminder)_ openGym is **AGPL-3.0-or-later** [2.1.5]—if only you use it privately, you're fine; if you let others use your hosted server, keep your fork public under AGPL-3.0.

### Phase 1: Minimal Sync API + D1 (Unmodified Mobile App Connects)

Build a lightweight Hono Worker (`worker/src/index.js`) with a 4-table D1 schema (`users`, `user_states`, `ephemeral_codes`, `api_tokens`) implementing only the routes the official mobile app calls:

- **Meta & CORS:** `GET /api/health`, `GET /api/config` (returning `media_uploads: false`, `password_login: false`, `mcp: true`), plus CORS reflection for `https://localhost` (Android) and `capacitor://localhost` (iOS) with `OPTIONS` returning `204` and **no** `Allow-Credentials` header.
- **Pairing & Session:**
- `POST /api/pair/redeem` — Validates your 8-char code from `ephemeral_codes`, deletes it, and returns an HMAC-SHA256 Bearer token (`<uid>:<expiry-ms>:<session-version>.<sig>`) signed via WebCrypto (`SESSION_SECRET`).
- `GET /api/me` — Validates the Bearer token and auto-issues a fresh `token` whenever it passes half of `SESSION_DAYS` (90 days), so your phone never silently logs out.

- **Atomic State Sync:**
- `GET /api/data` — Returns `{ rev, data }` from `user_states`.
- `PUT /api/data` — Runs an atomic SQLite compare-and-swap (`UPDATE user_states SET rev = rev + 1, state_json = ? WHERE uid = ? AND rev = ?`). If 0 rows change, return `409` with the current `{ rev, data }` so the phone runs its built-in field-level merge (`lib/sync-merge.js`) and retries cleanly [2.2.2].

- **Milestone check:** Deploy to `*.workers.dev` (or a custom domain), mint a pairing code via CLI (Track A) or `/pair` (Track B), enter the URL + code in the official openGym mobile app, log a test set, and verify the row updates in D1.

### Phase 2: Merged Remote MCP Endpoint (`/mcp`)

Instead of deploying openGym's separate `mcp` Docker container [2.2.3], mount `/mcp` directly inside the same Worker:

1. **Reuse openGym's MCP tool definitions:** Port `mcp/src/state.js`, `mcp/src/labels.js`, and `mcp/src/tools.js` into `worker/src/mcp/`, replacing filesystem reads (`DATA_DIR`) and HTTP loopback writes with direct D1 queries against `user_states` (bumping `rev` atomically so your phone merges AI-written routines cleanly on its next sync) [2.2.2].
2. **Expose Streamable HTTP (`POST /mcp`):** Authenticate every request via SHA-256 hashed Bearer tokens in `api_tokens`, enforcing openGym's per-category scopes (`off`, `view`, `apply`).
3. **Add OAuth 2.1 + PKCE _(Track B only)_:** Expose `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`, `/api/mcp/authorize`, `/api/mcp/token` (with refresh tokens), and `/api/mcp/revoke` so Claude and Gemini apps accept your Worker URL as a native connector [2.2.3].
4. **Milestone check:** Connect **OpenCode / Claude Code / Gemini CLI** (via Bearer token) or **Claude / Gemini apps** (via OAuth), ask it to read your last workout, and have it push a new routine—then watch the routine appear on your phone automatically.

### Phase 3: Future-Proofing (Only If & When You Want It Later)

Because Phase 1–2 follow openGym's exact API contract, adding the remaining pieces later takes minimal work:

- **Want custom exercise photos / form-check videos synced off-device?** Bind a free **Cloudflare R2** bucket (10 GB/month free), implement `GET/PUT/DELETE /api/media/:hash`, and flip `MEDIA_UPLOADS=1`.
- **Want the Web / Desktop PWA later?** Run `npm run build` in `frontend/`, copy `catalogue/media` into `frontend/dist/exercise-media` (or R2 if file count exceeds 20,000), add the `assets` block with `run_worker_first: ["/api/*", "/mcp", "/.well-known/*"]` to `wrangler.jsonc`, add passkey registration/login routes (`@simplewebauthn/server`), and redeploy.

---

## 4. Cloudflare Workers Free-Tier Fit Check

With this trimmed single-Worker plan, your runtime stays well below every Free Plan ceiling:

- **CPU Time:** ~1–3 ms per sync or MCP tool call vs. **10 ms** Free limit (no `scrypt`, WebCrypto HMAC, single D1 row read/write).
- **Memory:** ~15–25 MB isolate footprint vs. **128 MB** limit.
- **Database (D1):** A single lifter's multi-year JSON state is typically under 1–2 MB vs. **5 GB** Free storage and **100,000 writes/day**.
- **Static Assets:** **0 files** in Phase 1–2 vs. **20,000 files** Free limit.

---

## Interactive Porting Scope & Free-Tier Budget Planner

Toggle which pieces you want to include in your Cloudflare Worker fork below to see the exact architecture topology, which clients work, and how each addition affects your Cloudflare Workers Free-tier resource headroom:
./target_architecture_on_cloudflare_workers_free_tier_visual_representation_v2.html

---

To begin executing right away, decide between **Track A** (CLI bootstrap, zero HTML, fastest path for OpenCode / Claude Code / Gemini CLI) or **Track B** (adds the ~2 KB OAuth consent UI for Claude/Gemini consumer apps).

# openGym on Cloudflare Workers Free Tier

This fork runs the full **openGym** stack—React PWA + 180 px exercise animations, Passkey Auth + Mobile App Sync API, merged Remote MCP (`/mcp` + OAuth 2.1), Admin Dashboard, AI Coach proxy, and async Webhooks—inside a **single Cloudflare Worker + D1** on the Free Plan (zero payment card required).

## Architecture Summary

- **Web PWA + 180 px Exercise Media:** Workers Static Assets (`frontend/dist`, ~13.1k files, well under the 20,000-file Free limit; `run_worker_first` ensures static files consume 0 Worker CPU/quota).
- **API + OAuth 2.1 + Merged Remote MCP (`/mcp`):** Hono Worker (`worker/src/index.ts`) using WebCrypto (`crypto.subtle`) and `@simplewebauthn/server` to stay under the 10 ms Free CPU cap.
- **Database:** Cloudflare D1 (`worker/migrations/0001_init.sql`) with atomic compare-and-swap (`WHERE uid = ? AND rev = ?`) preserving openGym's `409 Conflict` merge contract.
- **Default `*.workers.dev` Domain:** `RP_ID` and `ORIGIN` auto-derive from the request URL when left unset in `wrangler.jsonc`.

## First-Time Cloudflare Setup (3 Steps)

1. **Create the D1 database & paste its ID into `wrangler.jsonc`:**
   ```bash
   cd worker && npm install
   npx wrangler login
   npx wrangler d1 create opengym-db
   ```
   Copy the returned `database_id` into `wrangler.jsonc` (replacing `REPLACE_WITH_D1_DATABASE_ID`).

2. **Apply the schema & set your signing secret:**
   ```bash
   npm run db:migrate:remote
   openssl rand -hex 32 | npx wrangler secret put SESSION_SECRET -c ../wrangler.jsonc
   ```
   _(Optional: set `ENC_KEY` separately for AI Coach/webhook secret sealing, otherwise `SESSION_SECRET` is used.)_

3. **Build static assets & deploy:**
   ```bash
   npm run build:assets
   npm run deploy
   ```

## Automatic Deploys on Push to `main`

Add these two repository secrets in **GitHub → Settings → Secrets and variables → Actions**:
- `CLOUDFLARE_API_TOKEN` (Workers Scripts Edit + D1 Edit permissions)
- `CLOUDFLARE_ACCOUNT_ID`

Every push to `main` will automatically run `typecheck`, `vitest`, build the PWA + exercise media, apply D1 migrations, and deploy via `.github/workflows/deploy-worker.yml`.

## Connecting Clients

- **Web PWA:** Open `https://opengym.<your-subdomain>.workers.dev` and create your first passkey profile (automatically promoted to Owner/Admin via `FIRST_USER_ADMIN=1`, then locked behind `INVITE_ONLY=1`).
- **Official iOS / Android App:** In Web PWA go to **Settings → Account → Pair the mobile app**, then enter your `*.workers.dev` URL and 8-character code in the app.
- **Claude / Gemini / OpenCode MCP:**
  - **OAuth 2.1 connectors (Claude / Gemini apps):** Add `https://opengym.<your-subdomain>.workers.dev/mcp` as a custom MCP connector and approve the consent screen.
  - **CLI / IDE (OpenCode, Claude Code, Gemini CLI):** Mint a scoped token under **Settings → API Tokens** and pass `Authorization: Bearer ogt_...` to `https://opengym.<your-subdomain>.workers.dev/mcp`.

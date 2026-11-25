# openGym on Cloudflare Workers (free plan)

This fork can run openGym as one Cloudflare Worker plus a D1 database, on the free plan with no
payment card: the web app with its 180 px exercise media, the API the web and phone apps sync
with, and the remote MCP endpoint (`/mcp`, OAuth or scoped tokens) for Claude, ChatGPT, Gemini and
OpenCode. The Docker deployment in the rest of the repository is untouched.

**Staying up to date with upstream, backups and limits: [STAYING_UP_TO_DATE.md](STAYING_UP_TO_DATE.md).**

The design notes this started from are in this folder (`target_architecture_*`). What was built
differs from them in a few places, listed under "Differences from the plan" below.

## How it fits together

| Piece | Docker deployment | Cloudflare deployment |
| --- | --- | --- |
| Web app and exercise media | `web` container (nginx) | Workers Static Assets (`frontend/dist`, about 13,300 files of the 20,000 allowed) with the same security headers, generated into `_headers` |
| API | `api/server.js` | `worker/src` (Hono), same routes, bodies and status codes |
| Data | `./data/*.json` | D1 (`worker/migrations`), revision checked in SQL, so a stale device still gets its 409 to merge |
| Sync rules | `api/sync-stamps.js` | the same file, imported |
| Remote MCP | `mcp` container | upstream's own tools (`mcp/src`), run inside the Worker; their API calls go to the Worker's own router in-process |

Code reused from upstream rather than copied: `api/sync-stamps.js`, `api/nudge.js`,
`api/passkeys-store.js`, `api/verify-error.js`, `api/rate-limit.js`, `api/integrations/events.js`,
`api/integrations/calendar.js`, `api/coach/core/categories.js` and the whole of `mcp/src`. One line
of upstream changed: `mcp/src/api-client.js` takes its `fetch` from the config when one is given.

## What works, and what is off

Works: passkey sign-up and sign-in, more passkeys and device links, phone pairing, sync with
conflict merging, scoped API tokens, the remote MCP (all 15 tools, reads and writes), OAuth for
assistant connectors, the admin dashboard and invites, webhooks (with retries, drained by a cron
every 5 minutes), the calendar feed.

Off, and hidden or answered plainly in the app the way an upstream server with the feature off
does:

- **Password and provider (OIDC) sign-in.** Passkeys only. Password hashing does not fit the free
  plan's 10 ms of CPU per request.
- **The AI Coach.** Its job runner needs a filesystem, timers and long-running processes.
  `COACH_DISABLED=1`; the admin dashboard says so.
- **Web Push in the browser** (rest timer, reminders). The phone apps notify on their own. The
  Settings switch answers "Push notifications are not available on this server".
- **Photos and videos on custom exercises** (needs R2, which needs a card on file), sharing,
  trainers and gyms, the watch relay.

## First deployment

Pick the hostname first. A passkey is tied to the address it was made at, so moving to another
address later means making new passkeys. `RP_ID` and `ORIGIN` follow the address the Worker is
reached at unless you set them in `wrangler.jsonc`.

```bash
cd mcp && npm ci --ignore-scripts && cd ..      # the MCP tools the Worker bundles
cd worker && npm ci
npx wrangler login

npx wrangler d1 create opengym-db               # paste the database_id into wrangler.jsonc
npm run db:migrate:remote
openssl rand -hex 32 | npx wrangler secret put SESSION_SECRET -c ../wrangler.jsonc

npm run build:assets                            # builds the app, stages the media, writes _headers
npm run deploy
npm run invite                                  # prints an invite code for your own profile
```

`INVITE_ONLY=1` is on from the start, so nobody can sign up before you do. Open the Worker's
address, choose "Create profile", enter the code `npm run invite` printed and make your passkey.
With `FIRST_USER_ADMIN=1` that first profile is the owner and admin; invite others from the admin
dashboard.

## Deploying again

Deploys run from your own machine:

```bash
cd worker
npm run build:assets      # only when the app or the media changed
npm run db:migrate:remote # only when worker/migrations has a new file
npm run deploy
```

`.github/workflows/deploy-worker.yml` does the same on GitHub, but only when started by hand
(Actions, "Deploy openGym to Cloudflare Workers", Run workflow), and only with two repository
secrets set: `CLOUDFLARE_API_TOKEN` (Workers Scripts: Edit, D1: Edit) and `CLOUDFLARE_ACCOUNT_ID`.
Without them it stops after the build.

## Connecting

- **Phone apps:** in the web app, Settings, Account, "Pair the mobile app"; then the Worker's
  address and the 8-character code in the app.
- **Claude, ChatGPT, Gemini (connectors):** add `https://<your-address>/mcp` as a custom connector
  and approve the consent screen.
- **OpenCode, Claude Code, Gemini CLI:** make a token in Settings, API tokens, and send
  `Authorization: Bearer ogt_…` to `https://<your-address>/mcp`.

## Testing

`worker/test/e2e.mjs` drives a running Worker the way the web and phone apps do, with a software
passkey: sign-up, sign-in, sync and conflicts, pairing, tokens, MCP reads and writes, webhooks,
calendar, admin. Its first profile becomes the owner of an empty instance, so run it against
`wrangler dev` or a separate test Worker, never your real one.

```bash
cd worker
npm run db:migrate:local
npm run dev                                      # see "Local development" below
INVITE=$(npm run -s invite -- --local | awk '{print $NF}') npm run e2e
```

## Local development

- `wrangler dev` watches the assets folder, and with the 13,000 exercise files in it the local
  runtime fails to start (`spawn EBADF`). Serve the app without the media instead:
  `rsync -a --exclude exercise-media ../frontend/dist/ /tmp/og-assets/` and
  `npx wrangler dev -c ../wrangler.jsonc --assets /tmp/og-assets`.
- npm 11 skips install scripts unless approved. If `wrangler dev` cannot start the runtime, run
  `node node_modules/workerd/install.js` once inside `worker/`.

## Differences from the plan

- The MCP tools are upstream's, not a rewrite: a rewritten set had drifted (wrong record shape for
  logged workouts, a missing tool, different arguments).
- Every write is stamped by upstream's `sync-stamps.js`, as the Docker API does. The plan proposed
  skipping it for current clients; that changes merge results.
- No first-user bypass of `INVITE_ONLY`: `npm run invite` makes the first code instead.
- Coach, Web Push and media uploads are off (above).

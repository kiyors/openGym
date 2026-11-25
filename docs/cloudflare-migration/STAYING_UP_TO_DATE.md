# The Cloudflare fork: what we did, and how to stay up to date

This fork (github.com/kiyors/openGym) runs openGym on Cloudflare instead of Docker. Everything
upstream (github.com/DuarteSantos8/openGym) builds is still here and still works the Docker way.
What we added sits beside it. This page explains how the two fit together, so you can pull in
upstream's updates without breaking the web app, the phone apps or the AI connectors.

Setup and first deployment: [README.md](README.md).

## 1. What we did, in plain words

openGym has three parts. Upstream runs each as a Docker container; we run all three as one
Cloudflare Worker:

| Part | What it is | Upstream (Docker) | This fork (Cloudflare) |
| --- | --- | --- | --- |
| Web app | The React app you open in a browser, plus the exercise pictures and animations | `web` container (nginx) serving `frontend/` | Cloudflare **Static Assets**: the same `frontend/` build, uploaded as files |
| API | What the web app, the phone apps and the AI tools talk to: sign-in, sync, tokens, admin | `api` container running `api/server.js` | The **Worker**, `worker/src/`, a rewrite of `api/server.js` for Cloudflare |
| MCP | What Claude, Gemini and other assistants use to read and change your data | `mcp` container running `mcp/src/` | The same `mcp/src/` code, run **inside** the Worker |

Data moved from files in `./data` to a **D1 database** (Cloudflare's SQLite). Your whole profile
is still one JSON document, exactly as upstream stores it, just kept in a database row instead of
a file.

### Why the API had to be rewritten, and why that matters for updates

`api/server.js` is a long-running Node server: it keeps data in memory, writes files and runs
timers. A Worker lives for one request at a time and has no disk, so the server could not run
there as it is. `worker/src/` answers the same requests with the same answers, written for
Cloudflare.

That is the one thing to keep in mind about updates: **when upstream changes `api/server.js`, the
Worker does not change with it.** Someone has to carry the change over. Everything below is about
noticing those changes and carrying them over safely.

To keep that work small, the Worker reuses upstream's code wherever it can run unchanged:

- **Imported as is** (upstream updates arrive by themselves on the next deploy): the sync and
  merge rules (`api/sync-stamps.js`), the missed-workout rule (`api/nudge.js`), passkey helpers,
  sign-in error texts, rate limits, webhook events, the calendar feed, and the entire MCP server
  (`mcp/src/`, all 15 tools).
- **Mirrored** (rewritten for the Worker; upstream changes must be carried over by hand): the
  routes of `api/server.js`, scoped tokens (`api/tokens.js`), OAuth for connectors
  (`api/oauth.js`), webhooks (`api/integrations/`), and the web server's headers
  (`web/nginx.conf.template`).

`pnpm check:upstream` knows both lists and tells you which files changed (section 3).

### What is ours, and what we changed of upstream's

Ours alone, so upstream never touches it and a merge never conflicts there:

```
worker/                              the Worker (API + MCP host), its tests and scripts
wrangler.jsonc                       Cloudflare configuration (account, database, settings)
scripts/build-worker-assets.mjs      builds the web app and stages the media for Cloudflare
docs/cloudflare-migration/           these documents
.github/workflows/deploy-worker.yml  manual GitHub deploy (off unless started by hand)
```

Upstream files we changed (the only places a merge can conflict):

| File | Change |
| --- | --- |
| `mcp/src/api-client.js` | one line: the MCP tools use the Worker's own router instead of the network |
| `package.json` (repository root) | the `backup`, `check:upstream` and `deploy` scripts |
| `.gitignore` | `.dev.vars`, `backups/`, a test config |

If a merge conflicts in one of them, keep upstream's version and put our small change back on top.

### What is turned off, and why

The app hides these, or answers plainly, as an upstream server with the feature turned off would:

| Off | Why |
| --- | --- |
| Password and provider (Google, etc.) sign-in | Passkeys only. Password hashing is too slow for the free plan |
| AI Coach in the app | Its background jobs need things a Worker does not have. Claude or Gemini over MCP covers much of it |
| Browser notifications | Not needed: the phone apps notify on their own |
| Photos and videos on custom exercises | Needs Cloudflare R2, which needs a payment card |
| Sharing, community library, trainers and gyms | Multi-user features, not needed for a personal server |
| Server watch relay | The phone apps sync their watches directly |

The full list, route by route, is `worker/upstream-off.json`.

## 2. The phone apps are the part to watch

The web app is built from this repository, so it always matches the Worker you deployed. The phone
apps are not: they come from the App Store and Play Store, built by upstream, and they update on
your phone whenever upstream releases a new version, whether or not you have merged anything.

So a new phone app version can start calling an API route that your Worker does not have yet. Then
that one feature fails in the app, while everything else keeps working. Two habits prevent it:

1. **When upstream releases a new version** (a new tag on GitHub, or the app updates on your
   phone), run `pnpm check:upstream -- --ref <the new tag>`. It lists any new API route.
2. Merge and deploy the update soon after, using the steps below.

Sync itself is the safest part: the profile is one JSON document, so new fields that new app
versions add are stored and returned without the Worker needing to know about them.

## 3. Updating from upstream, step by step

Every month or so, or when upstream releases a version:

```bash
# 0. Start clean, on main
git status                     # nothing uncommitted
pnpm backup                    # a backup first, always (section 4)

# 1. See what is coming, before merging anything
pnpm check:upstream
```

The check prints three things:

- **New upstream routes the Worker does not serve.** These matter most. For each, decide: port it
  into `worker/src/routes/` (if you want the feature), or add its path to
  `worker/upstream-off.json` with a reason (if it belongs to a feature that is off here). Do this
  before deploying. The check exits with an error until every route is handled.
- **Imported upstream files that changed.** Nothing to do by hand. They come along with the merge;
  the end-to-end test (step 4) confirms nothing broke.
- **Mirrored upstream files that changed.** Read the diff it prints. If a change touches behavior
  the Worker mirrors (a new field in an answer, a new check, a fixed bug), make the same change in
  the Worker file it names. Many changes are comments or features that are off here; those need
  nothing.

```bash
# 2. Merge
git merge upstream/main
#    Conflicts can only be in the three files listed in section 1. Keep upstream's version,
#    then re-apply our small change.

# 3. Install what changed
(cd mcp && npm ci --ignore-scripts)
(cd worker && npm ci)

# 4. Check, then test against a local copy (never against the real server: the test makes
#    profiles)
(cd worker && npm run typecheck)
pnpm check:upstream -- --ref HEAD --no-fetch     # the merged code, nothing missing
(cd mcp && npx vitest run)                       # upstream's MCP tests still pass
```

Running the end-to-end test locally:

```bash
cd worker
npm run db:migrate:local
rsync -a --delete --exclude exercise-media ../frontend/dist/ /tmp/og-assets/
npx wrangler dev -c ../wrangler.jsonc --assets /tmp/og-assets &
INVITE=$(npm run -s invite -- --local | awk '{print $NF}') npm run e2e
```

It runs 20 checks the way the apps use the server: passkey sign-up and sign-in, sync and conflict
handling, phone pairing, tokens, MCP reads and writes, webhooks, calendar, admin. All 20 must pass.
(Build the web app first, step 5, if `frontend/dist` is missing or old.)

```bash
# 5. Build and deploy
cd worker
npm run build:assets           # the web app and media
npm run db:migrate:remote      # only if worker/migrations has a new file
npm run deploy

# 6. Confirm
curl https://opengym.kiyors.workers.dev/api/health
#    then open the web app, and sync once from the phone

# 7. Push
git push origin main
```

If a deploy goes wrong, `npx wrangler rollback -c ../wrangler.jsonc` (in `worker/`) puts the
previous version back within seconds. Data is untouched by a rollback.

## 4. Backups

```bash
pnpm backup
```

Saves to `backups/<date>_<time>/` in the repository (never committed: `backups/` is gitignored):

- `opengym-db.sql`: the whole database. Accounts, passkeys, tokens, invites, every profile.
- `<your name>/opengym-backup-<date>.json`: your profile in the app's own backup format.
- `manifest.json`: what was saved, with workout counts and sizes.

Run it before every update, and regularly besides (weekly is plenty). Keep a copy outside this
computer too. Cloudflare also keeps the last 7 days of database history itself on the free plan
(D1 Time Travel), for undoing a recent mistake in place:
`npx wrangler d1 time-travel restore opengym-db --timestamp <time> -c ../wrangler.jsonc` (in `worker/`).

### Restoring

- **Your training data, anywhere** (this server, a new one, a Docker server): sign in to the app,
  Settings, Import backup, and pick `opengym-backup-<date>.json`.
- **The whole server, as it was** (accounts and passkeys included): into a new, empty database.

  ```bash
  cd worker
  npx wrangler d1 create opengym-db-restored
  #   in wrangler.jsonc: database_name "opengym-db-restored" and the database_id it printed
  npx wrangler d1 execute opengym-db-restored --remote --file ../backups/<date>/opengym-db.sql -c ../wrangler.jsonc
  npm run deploy
  #   the npm scripts name the database opengym-db: rename it in worker/package.json and
  #   worker/scripts/*.mjs too, or keep using the new name with npx wrangler directly
  ```

  Passkeys only work again at the same address (opengym.kiyors.workers.dev).

## 5. Limits to know about

- **CPU time.** The free plan allows 10 ms of CPU per request. Measured on Cloudflare: syncing a
  large profile takes 10 to 40 ms, and AI tool calls 25 to 250 ms. Cloudflare has completed all of
  them so far. If it ever starts refusing them (errors in the app or the assistant during a sync
  or a tool call), the fix is Workers Paid (5 USD a month), or making those requests lighter.
- **Profile size.** D1 keeps a row under 2 MB, and a profile is one row: several years of training
  without photos is well under it (800 workouts measured 1.2 MB). `pnpm backup` shows the size and
  warns at 75 %.
- **The address.** Passkeys belong to `opengym.kiyors.workers.dev`. Moving to another address
  later means making new passkeys (data moves with a backup).

## 6. When something breaks

```bash
cd worker && npx wrangler tail opengym -c ../wrangler.jsonc
```

shows every request live, with the server's log lines. The Worker logs why it refused an
assistant's sign-in (`[oauth] ...`) or an MCP request (`[mcp] refused ...`), never tokens or
codes. Reproduce the problem while it runs.

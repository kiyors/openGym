#!/usr/bin/env node
// Before merging upstream (DuarteSantos8/openGym) into this fork: what in upstream's API does the
// Cloudflare Worker not handle yet, and which of the files it reuses or mirrors have changed?
//
//   pnpm check:upstream                      fetches `upstream`, compares with upstream/main
//   pnpm check:upstream -- --ref v1.5.0      another ref (a tag, a branch, a commit)
//   pnpm check:upstream -- --ref HEAD        the code as it is in this checkout (after a merge)
//   pnpm check:upstream -- --no-fetch        no network
//
// Exit code 1 when upstream has an API route that worker/src does not serve and
// worker/upstream-off.json does not list as deliberately off. Nothing is changed or merged.
// docs/cloudflare-migration/STAYING_UP_TO_DATE.md walks through what to do with the answer.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const UPSTREAM_URL = 'https://github.com/DuarteSantos8/openGym.git';
const args = process.argv.slice(2);
const refArg = args.includes('--ref') ? args[args.indexOf('--ref') + 1] : null;
const ref = refArg || 'upstream/main';
const git = (...a) => execFileSync('git', a, { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trim();

// Files the Worker imports from upstream as they are: an upstream change reaches the Worker on
// the next deploy, so it only needs the end-to-end test run again.
const IMPORTED = [
  'api/sync-stamps.js', 'api/nudge.js', 'api/queue.js', 'api/passkeys-store.js', 'api/verify-error.js',
  'api/rate-limit.js', 'api/integrations/events.js', 'api/integrations/calendar.js',
  'api/coach/core/categories.js', 'api/coach/core/library-data.js', 'mcp/src/', 'mcp/package-lock.json',
];
// Upstream code the Worker re-implements in worker/src: a change here may need the same change
// made by hand on the Worker side.
const MIRRORED = {
  'api/server.js': 'routes in worker/src/routes/* (auth, data, pair, meta, admin, tokens)',
  'api/tokens.js': 'worker/src/scopes.ts, worker/src/routes/tokens.ts',
  'api/oauth.js': 'worker/src/routes/oauth.ts',
  'api/device-link.js': 'worker/src/routes/auth.ts',
  'api/integrations/': 'worker/src/routes/webhooks.ts, worker/src/lib/webhook-crypto.ts',
  'api/net-guard.js': 'worker/src/lib/net-guard.ts',
  'api/coach/routes.js': 'worker/src/routes/coach.ts (Coach off: only its "off" answers)',
  'api/coach/config.js': 'worker/src/routes/coach.ts (Coach off: only its "off" answers)',
  'api/openapi.yaml': 'the route list this script compares',
  'web/nginx.conf.template': 'scripts/build-worker-assets.mjs (_headers), worker/src/routes/mcp.ts',
  'web/Dockerfile': 'scripts/build-worker-assets.mjs (Content-Security-Policy is read from it)',
};

// 1. The upstream remote, fetched.
if (!refArg || ref.startsWith('upstream/')) {
  const remotes = git('remote').split('\n');
  if (!remotes.includes('upstream')) {
    console.log(`Adding the upstream remote: ${UPSTREAM_URL}`);
    git('remote', 'add', 'upstream', UPSTREAM_URL);
  }
  if (!args.includes('--no-fetch')) {
    console.log('Fetching upstream…');
    git('fetch', '--quiet', 'upstream', '--tags');
  }
}

// 2. Upstream's routes, from its OpenAPI document (upstream's own tests keep it complete).
const norm = (p) => p.replace(/\{[^}]+\}/g, ':p').replace(/:[A-Za-z_]+/g, ':p');
const upstream = new Set();
let current = null;
for (const line of git('show', `${ref}:api/openapi.yaml`).split('\n')) {
  const p = /^  (\/\S*):\s*$/.exec(line);
  if (p) { current = p[1]; continue; }
  const m = /^    (get|post|put|delete|patch):/.exec(line);
  if (m && current) upstream.add(`${m[1].toUpperCase()} ${norm(current)}`);
}

// 3. The Worker's routes, from its source: plain registrations, and the ones registered in a loop
//    over a list (`for (const kind of ['plan', ...]) routes.post(`/api/coach/${kind}`)`).
const worker = new Set();
for (const f of fs.readdirSync(path.join(ROOT, 'worker/src/routes'))) {
  const src = fs.readFileSync(path.join(ROOT, 'worker/src/routes', f), 'utf8');
  for (const m of src.matchAll(/\.(get|post|put|delete|patch|all)\(\s*'([^']+)'/g)) worker.add(`${m[1].toUpperCase()} ${norm(m[2])}`);
  for (const loop of src.matchAll(/for \(const (\w+) of \[([^\]]+)\]\)\s*\{([\s\S]*?)\n\}/g)) {
    const values = [...loop[2].matchAll(/'([^']+)'/g)].map((v) => v[1]);
    for (const m of loop[3].matchAll(/\.(get|post|put|delete|patch|all)\(\s*`([^`]+)`/g)) {
      for (const v of values) worker.add(`${m[1].toUpperCase()} ${norm(m[2].replaceAll('${' + loop[1] + '}', v))}`);
    }
  }
}
// A Worker parameter covers a parameter with a suffix upstream (`:file` serves `{token}.ics`).
const served = (key) => {
  const [method, p] = key.split(' ');
  const segs = p.split('/');
  return [...worker].some((w) => {
    const [wm, wp] = w.split(' ');
    if (wm !== method && wm !== 'ALL') return false;
    const ws = wp.split('/');
    return ws.length === segs.length && ws.every((s, i) => s === segs[i] || (s === ':p' && segs[i].startsWith(':p')));
  });
};

const off = JSON.parse(fs.readFileSync(path.join(ROOT, 'worker/upstream-off.json'), 'utf8')).prefixes;
const offReason = (key) => {
  const p = key.split(' ')[1];
  const hit = Object.keys(off).find((prefix) => p.startsWith(prefix));
  return hit ? off[hit] : null;
};

const missing = [];
const offByReason = new Map();
for (const key of [...upstream].sort()) {
  if (served(key)) continue;
  const why = offReason(key);
  if (why) offByReason.set(why, (offByReason.get(why) || 0) + 1);
  else missing.push(key);
}
const unusedOff = Object.keys(off).filter((prefix) => ![...upstream].some((k) => k.split(' ')[1].startsWith(prefix)));

// 4. What changed upstream in the files the Worker reuses or mirrors, since this branch last had
//    them in common with `ref`.
let base = null;
try { base = git('merge-base', 'HEAD', ref); } catch { /* unrelated histories */ }
const changed = (paths) => (base ? git('diff', '--name-only', `${base}..${ref}`, '--', ...paths).split('\n').filter(Boolean) : []);
const importedChanged = changed(IMPORTED);
const mirroredChanged = changed(Object.keys(MIRRORED));
const behind = base ? Number(git('rev-list', '--count', `${base}..${ref}`)) : null;

// 5. The answer.
const head = git('rev-parse', '--short', 'HEAD');
console.log(`\nComparing this branch (${head}) with ${ref}${behind != null ? `: ${behind} upstream commit(s) not merged yet` : ''}.\n`);
console.log(`API routes upstream: ${upstream.size}. Served by the Worker: ${upstream.size - missing.length - [...offByReason.values()].reduce((a, b) => a + b, 0)}. Deliberately off: ${[...offByReason.values()].reduce((a, b) => a + b, 0)}.`);
for (const [why, n] of offByReason) console.log(`  off (${n}): ${why}`);

if (missing.length) {
  console.log(`\nNEW upstream routes the Worker does not serve (${missing.length}). Port them, or add them to worker/upstream-off.json with a reason:`);
  for (const k of missing) console.log('  ' + k);
} else {
  console.log('\nNo upstream route is missing from the Worker.');
}
if (unusedOff.length) console.log(`\nIn worker/upstream-off.json but no longer upstream (remove): ${unusedOff.join(', ')}`);

if (base) {
  console.log(importedChanged.length
    ? `\nImported upstream files changed (they come along by themselves; run the end-to-end test after merging):\n${importedChanged.map((f) => '  ' + f).join('\n')}`
    : '\nNo imported upstream file changed.');
  if (mirroredChanged.length) {
    console.log('\nMirrored upstream files changed (read the diff; the Worker side may need the same change):');
    for (const f of mirroredChanged) {
      const key = Object.keys(MIRRORED).find((k) => f === k || f.startsWith(k));
      console.log(`  ${f}  ->  ${MIRRORED[key]}`);
    }
    console.log(`  See them with: git diff ${base.slice(0, 9)}..${ref} -- ${mirroredChanged.join(' ')}`);
  } else {
    console.log('\nNo mirrored upstream file changed.');
  }
}
process.exit(missing.length ? 1 : 0);

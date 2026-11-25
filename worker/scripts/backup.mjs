#!/usr/bin/env node
// Backs up the Cloudflare deployment's data to backups/<date-time>/ in the repository (gitignored):
//
//   opengym-db.sql                         the whole D1 database (accounts, passkeys, tokens,
//                                          invites, every profile): restores this server as it was
//   <profile>/opengym-backup-<date>.json   each profile's document, in the app's own backup format:
//                                          opens with Settings → Import backup on any openGym server,
//                                          the Docker one included
//   manifest.json                          what was saved: profiles, revisions, sizes, workout counts
//
//   pnpm backup             the deployed database
//   pnpm backup -- --local  the `wrangler dev` database
//
// Restoring: docs/cloudflare-migration/STAYING_UP_TO_DATE.md, "Backups".
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const WORKER = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ROOT = path.resolve(WORKER, '..');
const DB = 'opengym-db';
const local = process.argv.includes('--local');
const where = local ? '--local' : '--remote';

const stamp = new Date().toISOString().replace(/\..*$/, '').replace(/:/g, '-').replace('T', '_');
const day = stamp.slice(0, 10);
const out = path.join(ROOT, 'backups', (local ? 'local_' : '') + stamp);
fs.mkdirSync(out, { recursive: true });

function wrangler(args, { capture = false } = {}) {
  return execFileSync('npx', ['wrangler', ...args, '-c', '../wrangler.jsonc'], {
    cwd: WORKER,
    stdio: ['ignore', capture ? 'pipe' : 'ignore', 'inherit'],
    encoding: 'utf8',
    maxBuffer: 512 * 1024 * 1024,
  });
}

// 1. The whole database, as SQL.
console.log(`Exporting ${DB} (${local ? 'local' : 'remote'})…`);
const sqlFile = path.join(out, 'opengym-db.sql');
wrangler(['d1', 'export', DB, where, '--output', sqlFile]);
const sqlBytes = fs.statSync(sqlFile).size;
if (sqlBytes < 100) {
  console.error(`ERROR: ${sqlFile} is only ${sqlBytes} bytes; the export did not work.`);
  process.exit(1);
}

// 2. Each profile's document in the app's backup format. One profile per query, so no single
//    answer grows with the number of profiles.
const list = JSON.parse(
  wrangler(['d1', 'execute', DB, where, '--json', '--command', 'SELECT u.uid, u.username, s.rev FROM users u LEFT JOIN user_states s ON s.uid = u.uid ORDER BY u.created_at'], { capture: true })
)[0].results;

const manifest = { at: new Date().toISOString(), source: local ? 'local' : 'remote', database: 'opengym-db.sql', profiles: [] };
const used = new Set();
for (const u of list) {
  const entry = { uid: u.uid, name: u.username, rev: u.rev ?? 0, file: null };
  if (u.rev != null) {
    if (!/^[A-Za-z0-9_-]+$/.test(u.uid)) throw new Error(`unexpected uid ${u.uid}`);
    const row = JSON.parse(
      wrangler(['d1', 'execute', DB, where, '--json', '--command', `SELECT state_json FROM user_states WHERE uid = '${u.uid}'`], { capture: true })
    )[0].results[0];
    const state = JSON.parse(row.state_json);
    // A folder per profile, named after it (made safe for a file name, unique).
    let folder = String(u.username || u.uid).replace(/[^\p{L}\p{N}_-]+/gu, '_').slice(0, 40) || u.uid;
    if (used.has(folder)) folder += '_' + u.uid.slice(0, 6);
    used.add(folder);
    fs.mkdirSync(path.join(out, folder));
    const file = path.join(folder, `opengym-backup-${day}.json`);
    fs.writeFileSync(path.join(out, file), JSON.stringify(state));
    Object.assign(entry, {
      file,
      bytes: row.state_json.length,
      workouts: Array.isArray(state.workouts) ? state.workouts.length : 0,
      bodyweight: Array.isArray(state.bodyweight) ? state.bodyweight.length : 0,
      routines: Array.isArray(state.routines) ? state.routines.length : 0,
    });
  }
  manifest.profiles.push(entry);
}
fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');

console.log(`\nBackup saved to ${path.relative(ROOT, out)}/`);
console.log(`  opengym-db.sql  ${(sqlBytes / 1024).toFixed(0)} KiB (the whole server)`);
// D1 keeps a row under 2 MB, and a profile is one row: past that, saving it fails.
const D1_ROW_MAX = 2_000_000;
for (const p of manifest.profiles) {
  console.log(p.file
    ? `  ${p.file}  ${p.name}: ${p.workouts} workouts, ${p.bodyweight} weigh-ins, ${p.routines} routines, ${(p.bytes / 1024).toFixed(0)} KiB, rev ${p.rev}`
    : `  ${p.name}: never synced, nothing to save`);
  if (p.bytes > D1_ROW_MAX * 0.75) {
    console.log(`  WARNING: ${p.name}'s profile is ${Math.round((p.bytes / D1_ROW_MAX) * 100)}% of D1's 2 MB row limit (docs/cloudflare-migration/STAYING_UP_TO_DATE.md, "Limits").`);
  }
}

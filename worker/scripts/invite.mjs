#!/usr/bin/env node
// Mints an invite code straight into D1, for the first profile on an INVITE_ONLY instance (with
// no profile there is no admin yet to make one in the app), or whenever the dashboard is out of
// reach. The profile made with it is the owner and admin when FIRST_USER_ADMIN is on.
//
//   pnpm invite                the deployed database
//   pnpm invite --local        the `wrangler dev` database
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const WORKER = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const local = process.argv.includes('--local');
const code = crypto.randomBytes(8).toString('hex').toUpperCase();   // the admin dashboard's format
const sql = `INSERT INTO invites (code, note, created_by, created_at) VALUES ('${code}', 'first profile (pnpm invite)', NULL, '${new Date().toISOString()}')`;
execFileSync('pnpm', ['exec', 'wrangler', 'd1', 'execute', 'opengym-db', local ? '--local' : '--remote', '-c', '../wrangler.jsonc', '--command', sql], { cwd: WORKER, stdio: ['ignore', 'ignore', 'inherit'] });
console.log(`Invite code (${local ? 'local' : 'remote'}): ${code}`);

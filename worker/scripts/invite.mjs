#!/usr/bin/env node
// Mints an invite code straight into D1, for the first profile on an INVITE_ONLY instance (with
// no profile there is no admin yet to make one in the app), or whenever the dashboard is out of
// reach. The profile made with it is the owner and admin when FIRST_USER_ADMIN is on.
//
//   npm run invite             the deployed database
//   npm run invite -- --local  the `wrangler dev` database
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';

const local = process.argv.includes('--local');
const code = crypto.randomBytes(8).toString('hex').toUpperCase();   // the admin dashboard's format
const sql = `INSERT INTO invites (code, note, created_by, created_at) VALUES ('${code}', 'first profile (npm run invite)', NULL, '${new Date().toISOString()}')`;
execFileSync('npx', ['wrangler', 'd1', 'execute', 'opengym-db', local ? '--local' : '--remote', '-c', '../wrangler.jsonc', '--command', sql], { stdio: ['ignore', 'ignore', 'inherit'] });
console.log(`Invite code (${local ? 'local' : 'remote'}): ${code}`);

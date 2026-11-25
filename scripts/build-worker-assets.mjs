#!/usr/bin/env node
/**
 * Builds the openGym React PWA and stages the 180 px exercise media into frontend/dist
 * for Cloudflare Workers Static Assets, enforcing Free Tier limits (<20,000 files, <=25 MiB/file).
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FRONTEND_DIR = path.join(ROOT, 'frontend');
const DIST_DIR = path.join(FRONTEND_DIR, 'dist');
const MAX_FILES = 20_000;
const MAX_FILE_BYTES = 25 * 1024 * 1024;

function run(cmd, args, cwd) {
  console.log(`$ ${cmd} ${args.join(' ')}`);
  execFileSync(cmd, args, { cwd, stdio: 'inherit' });
}

function walkStats(dir) {
  let count = 0;
  let maxBytes = 0;
  let largestFile = '';
  let totalBytes = 0;

  const stack = [dir];
  while (stack.length) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
      } else if (entry.isFile()) {
        const size = fs.statSync(full).size;
        count++;
        totalBytes += size;
        if (size > maxBytes) {
          maxBytes = size;
          largestFile = path.relative(DIST_DIR, full);
        }
      }
    }
  }
  return { count, maxBytes, largestFile, totalBytes };
}

const skipInstall = process.argv.includes('--skip-install');

if (!skipInstall) {
  run('npm', ['ci', '--ignore-scripts'], FRONTEND_DIR);
}
run('npm', ['run', 'build'], FRONTEND_DIR);
run('node', [path.join(ROOT, 'scripts/catalogue/stage-media.mjs'), DIST_DIR], ROOT);

const stats = walkStats(DIST_DIR);
const mb = (stats.totalBytes / (1024 * 1024)).toFixed(1);
const maxMb = (stats.maxBytes / (1024 * 1024)).toFixed(2);
console.log(
  `Workers Static Assets check: ${stats.count} files (${mb} MiB total, largest: ${largestFileOrNone(stats.largestFile)} ${maxMb} MiB)`
);

if (stats.count >= MAX_FILES) {
  console.error(
    `ERROR: frontend/dist has ${stats.count} files, exceeding Cloudflare Workers Static Assets Free limit (${MAX_FILES}). Move exercise-media to R2.`
  );
  process.exit(1);
}

if (stats.maxBytes > MAX_FILE_BYTES) {
  console.error(
    `ERROR: ${stats.largestFile} is ${maxMb} MiB, exceeding Cloudflare Workers Static Assets 25 MiB per-file limit.`
  );
  process.exit(1);
}

function largestFileOrNone(name) {
  return name || 'none';
}

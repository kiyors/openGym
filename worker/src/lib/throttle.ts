import type { Context } from 'hono';
import { createBackoff, createWindow } from '../../../api/rate-limit.js';

/* Sign-in throttle, as api/server.js (AUTH_BURST, ADDR_FAILS): 60 requests a minute per address
 * on the sign-in routes, and wrong device-link codes backed off per address (20 free, then 30 s
 * doubling to 15 min). The counters live in the isolate's memory, so they are per isolate and
 * reset when it is recycled: a best-effort brake, not a hard limit. The device-link codes are
 * 60 bits, so this only has to make guessing pointless, not impossible. */

const BURST = createWindow({ max: 60, windowMs: 60_000 });
const ADDR_FAILS = createBackoff({ free: 20, baseMs: 30_000, maxMs: 15 * 60_000, forgetMs: 3_600_000 });

// The address the counters use. Behind Cloudflare the connecting address is cf-connecting-ip; an
// IPv6 client is counted by its /64, as upstream does.
export function limitAddress(req: Request): string {
  const raw = (req.headers.get('cf-connecting-ip') || '').trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(raw)) return raw;
  if (raw.includes(':') && /^[0-9a-fA-F:.]{2,45}$/.test(raw)) {
    return raw.toLowerCase().split(':').slice(0, 4).join(':') + '::/64';
  }
  return 'unknown';
}

function tooMany(c: Context, secs: number): Response {
  c.header('Retry-After', String(secs));
  return c.json({ error: 'too many attempts, try again later', code: 'locked', retryAfter: secs }, 429);
}

/** Spends the burst budget; with `kind`, also refuses an address paused for it. Null means go on. */
export function throttle(c: Context, kind: string | null): Response | null {
  const addr = limitAddress(c.req.raw);
  const wait = BURST.take(addr) || (kind ? ADDR_FAILS.retryAfter(kind + '|' + addr) : 0);
  return wait ? tooMany(c, wait) : null;
}

/** Whether the address is paused for `kind` right now (checked again right before the guarded check). */
export function addressPaused(c: Context, kind: string): Response | null {
  const wait = ADDR_FAILS.retryAfter(kind + '|' + limitAddress(c.req.raw));
  return wait ? tooMany(c, wait) : null;
}

/** One wrong answer against the caller's address. */
export function strikeAddress(c: Context, kind: string): void {
  ADDR_FAILS.fail(kind + '|' + limitAddress(c.req.raw));
}

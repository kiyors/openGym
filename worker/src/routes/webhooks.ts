/**
 * Integrations hub for the webhook provider: a port of api/integrations/ (routes.js, index.js,
 * providers/webhook.js, outbox.js, store.js) onto D1. Event detection and payloads are the upstream
 * modules themselves (api/integrations/events.js); only storage and the transport differ.
 *
 *  - connections: `webhooks` row (url masked in `url`, sealed in `url_enc`, secret sealed in `secret_enc`)
 *  - outbox: `webhook_outbox` row per delivery owed, idempotent by `key`
 *  - retries: back-off like upstream (30 s doubling, 8 tries). With no timers on Workers, a queued
 *    retry is sent on the next state write, on the Retry button, or by `runDueWebhooks` (cron).
 */
import { Hono } from 'hono';
import { Env, webhookEnabled } from '../env';
import { openSecret, sealSecret } from '../crypto';
import { SessionInfo, getSessionFromRequest, writeAudit } from '../db';
import { outboundUrlError } from '../lib/net-guard';
import { maskUrl, newId, newSecret, signature } from '../lib/webhook-crypto';
import { EVENTS, detectEvents, envelope, eventData, testData } from '../../../api/integrations/events.js';

export const webhookRoutes = new Hono<{ Bindings: Env }>();

const VERSION = '1.4.5';
const TIMEOUT_MS = 10_000;
const MAX_WEBHOOKS = 10;
const MAX_ATTEMPTS = 8;
const BASE_MS = 30_000;
const CAP_MS = 6 * 3600_000;
const RETRY_AFTER_CAP_MS = 6 * 3600_000;
const DONE_KEEP_MS = 45 * 86400_000;
const MAX_PER_USER = 200;
const PAYLOAD_MAX = 64 * 1024;
const LOG_MAX = 50;
const RUN_LIMIT = 10;
const LEASE_MS = 90_000;
const SEALED_MSG = 'Its settings cannot be read any more. Add it again.';

interface WebhookRow {
  id: string;
  uid: string;
  label: string;
  url: string;
  url_enc: string | null;
  secret_enc: string;
  events_json: string;
  enabled: number;
  status: string | null;
  failures: number | null;
  last_ok: number | null;
  last_error: string | null;
  updated_at: number | null;
  created_at: number;
}

interface OutboxRow {
  id: string;
  key: string;
  uid: string;
  conn: string;
  ev: string;
  payload_json: string;
  state: string;
  attempts: number;
  next_at: number;
}

interface DeliverResult {
  ok: boolean;
  retry?: boolean;
  retryAfterMs?: number;
  gone?: boolean;
  status?: number;
  ms?: number;
  code?: string;
  msg?: string;
}

class HubError extends Error {
  status: number;
  code?: string;
  constructor(status: number, message: string, code?: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const sealKey = (env: Env): string => env.ENC_KEY || env.SESSION_SECRET;
const aadOf = (row: Pick<WebhookRow, 'uid' | 'id'>, name: string) => `${row.uid}:${row.id}:${name}`;
const eventsOf = (row: WebhookRow): string[] => {
  try {
    const v = JSON.parse(row.events_json);
    return Array.isArray(v) ? v.filter((e): e is string => typeof e === 'string') : [];
  } catch {
    return [];
  }
};
const lastErrorOf = (row: WebhookRow): { at: number; msg: string; code?: string } | null => {
  if (!row.last_error) return null;
  try {
    const v = JSON.parse(row.last_error);
    if (v && typeof v === 'object' && typeof v.msg === 'string') return v;
  } catch {
    /* an older plain string */
  }
  return { at: row.updated_at || row.created_at, msg: String(row.last_error).slice(0, 160) };
};

export function backoffDelay(attempt: number, random: () => number = Math.random): number {
  const raw = Math.min(CAP_MS, BASE_MS * 2 ** Math.max(0, attempt - 1));
  return Math.round(raw * (0.75 + 0.5 * random()));
}

/* ---------- transport (providers/webhook.js judge + post) ---------- */

function retryAfterMs(h: string | null): number {
  const v = String(h || '').trim();
  if (!v) return 0;
  if (/^\d+$/.test(v)) return +v * 1000;
  const t = Date.parse(v);
  return Number.isFinite(t) ? Math.max(0, t - Date.now()) : 0;
}

function judge(status: number | null, headers: Headers | null, err: unknown): DeliverResult {
  if (err) {
    const e = err as { name?: string; message?: string };
    const text = `${e.name || ''} ${e.message || ''}`;
    if (/Timeout|Abort/i.test(text)) return { ok: false, retry: true, code: 'timeout', msg: 'No answer within 10 seconds.' };
    if (/certificate|SSL|TLS|self.signed/i.test(text)) {
      return { ok: false, retry: false, code: 'tls', msg: "The receiver's HTTPS certificate is not valid." };
    }
    if (/refused/i.test(text)) return { ok: false, retry: true, code: 'refused', msg: 'The receiver refused the connection.' };
    if (/not found|resolve|dns/i.test(text)) return { ok: false, retry: true, code: 'dns', msg: 'The address could not be found.' };
    return { ok: false, retry: true, code: 'network', msg: String(e.message || 'Could not connect.').slice(0, 120) };
  }
  const s = status as number;
  if (s >= 200 && s < 300) return { ok: true, status: s };
  if (s === 410) return { ok: false, retry: false, gone: true, status: s, code: 'gone', msg: 'The receiver says this webhook is gone (410).' };
  if (s >= 300 && s < 400) {
    return { ok: false, retry: false, status: s, code: 'redirect', msg: `Answered ${s}: redirects are not followed, use the final URL.` };
  }
  if (s === 408 || s === 425 || s === 429 || s >= 500) {
    return { ok: false, retry: true, status: s, code: 'busy', msg: `The receiver answered ${s}.`, retryAfterMs: retryAfterMs(headers?.get('retry-after') ?? null) };
  }
  return { ok: false, retry: false, status: s, code: 'refused', msg: `The receiver answered ${s}.` };
}

async function deliver(env: Env, row: WebhookRow, payload: { id: string; type: string }): Promise<DeliverResult> {
  const url = row.url_enc ? await openSecret(sealKey(env), row.url_enc, aadOf(row, 'url')) : null;
  const secret = await openSecret(sealKey(env), row.secret_enc, aadOf(row, 'secret'));
  if (!url || !secret) return { ok: false, retry: false, code: 'sealed', msg: SEALED_MSG };
  const bad = outboundUrlError(url);
  if (bad) return { ok: false, retry: false, code: 'blocked', msg: bad };
  const body = JSON.stringify(payload);
  const started = Date.now();
  let status: number | null = null;
  let headers: Headers | null = null;
  let err: unknown = null;
  try {
    const res = await fetch(url, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': `openGym-Webhook/${VERSION}`,
        'X-OpenGym-Event': payload.type,
        'X-OpenGym-Delivery': payload.id,
        'X-OpenGym-Signature': await signature(secret, body),
      },
      body,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    status = res.status;
    headers = res.headers;
    try {
      await res.body?.cancel();
    } catch {
      /* the answer is not read */
    }
  } catch (e) {
    err = e;
  }
  return { ...judge(status, headers, err), ms: Date.now() - started };
}

/* ---------- settling: connection state + log (index.js settle) ---------- */

function settleStatements(env: Env, row: WebhookRow, ev: string, res: DeliverResult, final: boolean): D1PreparedStatement[] {
  const now = Date.now();
  const log = env.DB.prepare(
    `INSERT INTO webhook_logs (webhook_id, uid, event_type, status, ok, error, created_at, ms)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    row.id,
    row.uid,
    ev.slice(0, 40),
    Number.isInteger(res.status) && (res.status as number) >= 0 && (res.status as number) < 1000 ? res.status : null,
    res.ok ? 1 : 0,
    res.ok ? null : String(res.msg || '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 160) || null,
    now,
    Number.isFinite(res.ms) ? Math.min(Math.round(res.ms as number), 600000) : null
  );
  const trim = env.DB.prepare(
    `DELETE FROM webhook_logs WHERE webhook_id = ? AND id NOT IN
       (SELECT id FROM webhook_logs WHERE webhook_id = ? ORDER BY id DESC LIMIT ${LOG_MAX})`
  ).bind(row.id, row.id);
  let upd: D1PreparedStatement;
  if (res.ok) {
    upd = env.DB.prepare(
      "UPDATE webhooks SET status = 'ok', failures = 0, last_ok = ?, last_error = NULL, updated_at = ? WHERE id = ?"
    ).bind(now, now, row.id);
  } else {
    const lastError = JSON.stringify({
      at: now,
      msg: String(res.msg || 'Delivery failed.').slice(0, 160),
      ...(res.code ? { code: res.code } : {}),
    });
    upd = env.DB.prepare(
      `UPDATE webhooks SET failures = MIN(failures + 1, 1000), last_error = ?, updated_at = ?,
         status = CASE WHEN ? THEN 'attention' ELSE status END,
         enabled = CASE WHEN ? THEN 0 ELSE enabled END
       WHERE id = ?`
    ).bind(lastError, now, final || res.gone ? 1 : 0, res.gone ? 1 : 0, row.id);
  }
  return [upd, log, trim];
}

/* ---------- the outbox runner ---------- */

async function runJob(env: Env, job: OutboxRow, row: WebhookRow | null): Promise<void> {
  const now = Date.now();
  if (!row) {
    await env.DB.prepare('DELETE FROM webhook_outbox WHERE id = ?').bind(job.id).run();
    return;
  }
  if (row.enabled === 0) {
    // Paused: later, without spending an attempt.
    await env.DB.prepare('UPDATE webhook_outbox SET next_at = ? WHERE id = ?').bind(now + 3600_000, job.id).run();
    return;
  }
  // A lease, so two overlapping runs do not send the same job twice.
  const claim = await env.DB.prepare("UPDATE webhook_outbox SET next_at = ? WHERE id = ? AND state = 'queued' AND next_at <= ?")
    .bind(now + LEASE_MS, job.id, now)
    .run();
  if (!claim.meta.changes) return;

  let payload: { id: string; type: string };
  try {
    payload = JSON.parse(job.payload_json);
  } catch {
    await env.DB.prepare("UPDATE webhook_outbox SET state = 'failed', msg = 'unreadable' WHERE id = ?").bind(job.id).run();
    return;
  }
  let res: DeliverResult;
  try {
    res = await deliver(env, row, payload);
  } catch (e) {
    res = { ok: false, retry: true, msg: (e as Error)?.message || 'delivery failed' };
  }
  const attempts = job.attempts + 1;
  const done = Date.now();
  if (res.ok) {
    await env.DB.batch([
      env.DB.prepare("UPDATE webhook_outbox SET state = 'done', attempts = ?, done_at = ?, msg = NULL WHERE id = ?").bind(attempts, done, job.id),
      ...settleStatements(env, row, job.ev, res, true),
    ]);
    return;
  }
  const final = !res.retry || attempts >= MAX_ATTEMPTS;
  const stmts: D1PreparedStatement[] = [];
  if (final) {
    stmts.push(
      env.DB.prepare("UPDATE webhook_outbox SET state = 'failed', attempts = ?, msg = ? WHERE id = ?").bind(
        attempts,
        String(res.msg || '').slice(0, 160),
        job.id
      )
    );
  } else {
    const after = Math.min(RETRY_AFTER_CAP_MS, Math.max(0, res.retryAfterMs || 0));
    stmts.push(
      env.DB.prepare('UPDATE webhook_outbox SET attempts = ?, next_at = ? WHERE id = ?').bind(
        attempts,
        done + Math.max(backoffDelay(attempts), after),
        job.id
      )
    );
  }
  await env.DB.batch([...stmts, ...settleStatements(env, row, job.ev, res, final)]);
}

/** Send what is due (for one profile, or for everyone when `uid` is null). At most RUN_LIMIT jobs. */
async function runDue(env: Env, uid: string | null, conn?: string): Promise<void> {
  const now = Date.now();
  const binds: unknown[] = [now];
  let where = "state = 'queued' AND next_at <= ?";
  if (uid) {
    where += ' AND uid = ?';
    binds.push(uid);
  }
  if (conn) {
    where += ' AND conn = ?';
    binds.push(conn);
  }
  const due = await env.DB.prepare(`SELECT * FROM webhook_outbox WHERE ${where} ORDER BY next_at LIMIT ${RUN_LIMIT}`)
    .bind(...binds)
    .all<OutboxRow>();
  const jobs = due.results || [];
  if (!jobs.length) return;
  const rows = new Map<string, WebhookRow | null>();
  for (const id of new Set(jobs.map((j) => j.conn))) {
    rows.set(id, await env.DB.prepare('SELECT * FROM webhooks WHERE id = ?').bind(id).first<WebhookRow>());
  }
  for (let i = 0; i < jobs.length; i += 2) {
    await Promise.all(
      jobs.slice(i, i + 2).map((j) =>
        runJob(env, j, rows.get(j.conn) ?? null).catch((e) => console.error('webhook job', j.id, e))
      )
    );
  }
}

/** For a scheduled() handler: whatever is due, for every profile. */
export async function runDueWebhooks(env: Env): Promise<void> {
  if (!webhookEnabled(env)) return;
  try {
    await runDue(env, null);
  } catch (e) {
    console.error('webhook runDue', e);
  }
}

/**
 * After a stored PUT /api/data (call via ctx.waitUntil): queue what the profile's connections asked
 * to hear about, then send what is due (new events and earlier failures whose back-off is over).
 */
export async function dispatchWebhooks(
  env: Env,
  uid: string,
  prevState: Record<string, unknown> | null,
  nextState: Record<string, unknown>
): Promise<void> {
  if (!webhookEnabled(env)) return;
  try {
    const modules = (nextState as { modules?: { integrations?: unknown } })?.modules;
    if (modules?.integrations === false) return;
    const res = await env.DB.prepare('SELECT * FROM webhooks WHERE uid = ?').bind(uid).all<WebhookRow>();
    const all = res.results || [];
    const conns = all.filter((r) => r.enabled !== 0);
    if (!conns.length) return;

    const now = Date.now();
    const evs = detectEvents(prevState, nextState, { now }) as Array<{ type: string; entity: string; at: number; data: unknown }>;
    if (evs.length) {
      const q = await env.DB.prepare("SELECT COUNT(*) AS n FROM webhook_outbox WHERE uid = ? AND state = 'queued'")
        .bind(uid)
        .first<{ n: number }>();
      let queued = q?.n ?? 0;
      const stmts: D1PreparedStatement[] = [
        env.DB.prepare("DELETE FROM webhook_outbox WHERE state = 'done' AND done_at < ?").bind(now - DONE_KEEP_MS),
      ];
      for (const ev of evs) {
        for (const c of conns) {
          if (!eventsOf(c).includes(ev.type) || ev.at < c.created_at) continue;
          const eid = newId('evt');
          const payload = JSON.stringify(
            envelope({ id: eid, type: ev.type, data: eventData(ev, nextState), at: ev.at })
          );
          if (queued >= MAX_PER_USER || payload.length > PAYLOAD_MAX) {
            stmts.push(
              ...settleStatements(env, c, ev.type, { ok: false, msg: 'Too much waiting to be sent, this one was skipped.' }, false)
            );
            continue;
          }
          queued++;
          stmts.push(
            env.DB.prepare(
              `INSERT OR IGNORE INTO webhook_outbox (id, key, uid, conn, ev, payload_json, state, attempts, next_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 'queued', 0, ?, ?)`
            ).bind(eid, `webhook:${uid}:${c.id}:${ev.type}:${ev.entity}`, uid, c.id, ev.type, payload, now, now)
          );
        }
      }
      if (stmts.length > 1) await env.DB.batch(stmts);
    }
    await runDue(env, uid);
  } catch (e) {
    console.error('dispatchWebhooks', e);
  }
}

/* ---------- views ---------- */

async function viewOf(env: Env, row: WebhookRow, counts: { queued: number; failed: number }) {
  const paused = row.enabled === 0;
  const key = sealKey(env);
  const url = row.url_enc ? await openSecret(key, row.url_enc, aadOf(row, 'url')) : null;
  const secret = await openSecret(key, row.secret_enc, aadOf(row, 'secret'));
  const sealed = url == null || secret == null;
  return {
    id: row.id,
    provider: 'webhook',
    label: row.label,
    events: eventsOf(row),
    paused,
    status: sealed || row.status === 'attention' ? 'attention' : paused ? 'paused' : 'connected',
    info: { url: row.url },
    createdAt: row.created_at,
    lastOk: row.last_ok ?? null,
    lastError: sealed ? { at: row.updated_at || row.created_at, msg: SEALED_MSG, code: 'sealed' } : lastErrorOf(row),
    failures: row.failures || 0,
    queued: counts.queued,
    failed: counts.failed,
  };
}

async function countsOf(env: Env, uid: string, conn?: string): Promise<Map<string, { queued: number; failed: number }>> {
  const res = await env.DB.prepare(
    `SELECT conn, state, COUNT(*) AS n FROM webhook_outbox
     WHERE uid = ? ${conn ? 'AND conn = ?' : ''} AND state IN ('queued', 'failed') GROUP BY conn, state`
  )
    .bind(...(conn ? [uid, conn] : [uid]))
    .all<{ conn: string; state: string; n: number }>();
  const out = new Map<string, { queued: number; failed: number }>();
  for (const r of res.results || []) {
    const c = out.get(r.conn) || { queued: 0, failed: 0 };
    if (r.state === 'queued') c.queued = r.n;
    else c.failed = r.n;
    out.set(r.conn, c);
  }
  return out;
}

async function viewOne(env: Env, uid: string, id: string) {
  const row = await env.DB.prepare('SELECT * FROM webhooks WHERE id = ? AND uid = ?').bind(id, uid).first<WebhookRow>();
  if (!row) throw new HubError(404, 'no such connection', 'missing');
  const counts = await countsOf(env, uid, id);
  return { row, connection: await viewOf(env, row, counts.get(id) || { queued: 0, failed: 0 }) };
}

function pickEvents(raw: unknown): string[] {
  const known = EVENTS as string[];
  const want = Array.isArray(raw) ? raw.filter((e): e is string => typeof e === 'string' && known.includes(e)) : [];
  if (Array.isArray(raw) && !want.length) throw new HubError(400, 'pick at least one event', 'events');
  return want.length ? [...new Set(want)] : ['workout.finished'];
}

/* ---------- routes (integrations/routes.js) ---------- */

type Ctx = { env: Env; req: { raw: Request }; json: (o: object, status?: number) => Response };

async function guarded(c: Ctx, fn: (s: SessionInfo) => Promise<object>): Promise<Response> {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  try {
    return c.json(await fn(s), 200);
  } catch (e) {
    if (!(e instanceof HubError)) throw e;
    return c.json({ error: e.message, ...(e.code ? { code: e.code } : {}) }, e.status);
  }
}

const bodyOf = async (req: Request): Promise<Record<string, unknown>> => {
  const b = await req.json().catch(() => ({}));
  return b && typeof b === 'object' && !Array.isArray(b) ? (b as Record<string, unknown>) : {};
};
const idOf = (b: Record<string, unknown>): string => (typeof b.id === 'string' ? b.id.slice(0, 40) : '');
const needOn = (env: Env) => {
  if (!webhookEnabled(env)) throw new HubError(404, 'integrations are off on this server', 'off');
};

webhookRoutes.get('/api/integrations', (c) =>
  guarded(c, async (s) => {
    if (!webhookEnabled(c.env)) return { providers: [], connections: [] };
    const res = await c.env.DB.prepare('SELECT * FROM webhooks WHERE uid = ? ORDER BY created_at').bind(s.user.uid).all<WebhookRow>();
    const counts = await countsOf(c.env, s.user.uid);
    return {
      providers: [{ id: 'webhook', kind: 'webhook', category: 'automation', events: EVENTS, max: MAX_WEBHOOKS }],
      connections: await Promise.all((res.results || []).map((r) => viewOf(c.env, r, counts.get(r.id) || { queued: 0, failed: 0 }))),
    };
  })
);

webhookRoutes.post('/api/integrations/connect', (c) =>
  guarded(c, async (s) => {
    needOn(c.env);
    const body = await bodyOf(c.req.raw);
    const provider = typeof body.provider === 'string' ? body.provider.slice(0, 40) : '';
    if (provider !== 'webhook') throw new HubError(404, 'no such integration', 'missing');
    const n = await c.env.DB.prepare('SELECT COUNT(*) AS n FROM webhooks WHERE uid = ?').bind(s.user.uid).first<{ n: number }>();
    if ((n?.n ?? 0) >= MAX_WEBHOOKS) throw new HubError(409, `at most ${MAX_WEBHOOKS} of these per profile`, 'too-many');

    const url = String(body.url || '').trim();
    const bad = outboundUrlError(url);
    if (bad) throw new HubError(400, bad, 'url');
    const events = pickEvents(body.events);
    const secret = newSecret();
    let host = '';
    try {
      host = new URL(url).host;
    } catch {
      /* checked above */
    }
    const label = String(body.label || '').trim().slice(0, 60) || host;
    const id = newId('c');
    const now = Date.now();
    const key = sealKey(c.env);
    const urlEnc = await sealSecret(key, url, `${s.user.uid}:${id}:url`);
    const secretEnc = await sealSecret(key, secret, `${s.user.uid}:${id}:secret`);
    await c.env.DB.batch([
      c.env.DB.prepare(
        `INSERT INTO webhooks (id, uid, label, url, url_enc, secret_enc, events_json, enabled, status, failures, updated_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'ok', 0, ?, ?)`
      ).bind(id, s.user.uid, label, maskUrl(url), urlEnc, secretEnc, JSON.stringify(events), now, now),
      c.env.DB.prepare(
        "INSERT INTO webhook_logs (webhook_id, uid, event_type, status, ok, error, created_at, ms) VALUES (?, ?, 'connected', NULL, 1, NULL, ?, NULL)"
      ).bind(id, s.user.uid, now),
    ]);
    await writeAudit(c.env, c.req.raw, 'integration.connect', { user: s.user, msg: `webhook: ${label}` });
    const { connection } = await viewOne(c.env, s.user.uid, id);
    return { connection, reveal: { secret } };
  })
);

webhookRoutes.post('/api/integrations/update', (c) =>
  guarded(c, async (s) => {
    needOn(c.env);
    const body = await bodyOf(c.req.raw);
    const { row } = await viewOne(c.env, s.user.uid, idOf(body));
    const sets: string[] = [];
    const binds: unknown[] = [];
    if (body.label != null) {
      sets.push('label = ?');
      binds.push(String(body.label).trim().slice(0, 60));
    }
    if (body.events != null) {
      sets.push('events_json = ?');
      binds.push(JSON.stringify(pickEvents(body.events)));
    }
    if (body.paused != null) {
      const paused = body.paused === true;
      sets.push('enabled = ?');
      binds.push(paused ? 0 : 1);
      // Switching a paused one back on is also the user saying "I fixed it".
      if (!paused) sets.push("status = 'ok'", 'failures = 0');
    }
    sets.push('updated_at = ?');
    binds.push(Date.now());
    await c.env.DB.prepare(`UPDATE webhooks SET ${sets.join(', ')} WHERE id = ? AND uid = ?`)
      .bind(...binds, row.id, s.user.uid)
      .run();
    return { connection: (await viewOne(c.env, s.user.uid, row.id)).connection };
  })
);

webhookRoutes.post('/api/integrations/disconnect', (c) =>
  guarded(c, async (s) => {
    needOn(c.env);
    const body = await bodyOf(c.req.raw);
    const { row } = await viewOne(c.env, s.user.uid, idOf(body));
    await c.env.DB.prepare('DELETE FROM webhooks WHERE id = ? AND uid = ?').bind(row.id, s.user.uid).run();
    await writeAudit(c.env, c.req.raw, 'integration.disconnect', { user: s.user, msg: `webhook: ${row.label}` });
    return { ok: true };
  })
);

/** "Send test event": straight to the receiver, not through the outbox, answered at once. */
webhookRoutes.post('/api/integrations/test', (c) =>
  guarded(c, async (s) => {
    needOn(c.env);
    const body = await bodyOf(c.req.raw);
    const { row } = await viewOne(c.env, s.user.uid, idOf(body));
    const known = EVENTS as string[];
    const type = typeof body.type === 'string' ? body.type : null;
    const ev = type && known.includes(type) ? type : eventsOf(row)[0] || 'workout.finished';
    const now = Date.now();
    const payload = envelope({ id: newId('evt'), type: ev, data: testData(ev, now), at: now, test: true });
    const res = await deliver(c.env, row, payload);
    await c.env.DB.batch(settleStatements(c.env, row, 'test', res, !res.ok && !res.retry));
    return {
      ok: !!res.ok,
      status: res.status ?? null,
      ms: res.ms ?? null,
      msg: res.ok ? null : res.msg,
      connection: (await viewOne(c.env, s.user.uid, row.id)).connection,
    };
  })
);

/** The Retry button: failed deliveries go back into the queue and are sent now. */
webhookRoutes.post('/api/integrations/retry', (c) =>
  guarded(c, async (s) => {
    needOn(c.env);
    const body = await bodyOf(c.req.raw);
    const { row } = await viewOne(c.env, s.user.uid, idOf(body));
    const now = Date.now();
    const [back] = await c.env.DB.batch([
      c.env.DB.prepare(
        "UPDATE webhook_outbox SET state = 'queued', attempts = 0, next_at = ?, msg = NULL WHERE uid = ? AND conn = ? AND state = 'failed'"
      ).bind(now, s.user.uid, row.id),
      c.env.DB.prepare("UPDATE webhooks SET status = 'ok', failures = 0, updated_at = ? WHERE id = ? AND status = 'attention'").bind(
        now,
        row.id
      ),
    ]);
    await runDue(c.env, s.user.uid, row.id);
    return { requeued: back.meta.changes ?? 0, connection: (await viewOne(c.env, s.user.uid, row.id)).connection };
  })
);

webhookRoutes.get('/api/integrations/log', (c) =>
  guarded(c, async (s) => {
    needOn(c.env);
    const id = (c.req.query('id') || '').slice(0, 40);
    const { row } = await viewOne(c.env, s.user.uid, id);
    const logs = await c.env.DB.prepare(
      `SELECT event_type, status, ok, error, created_at, ms FROM webhook_logs
       WHERE webhook_id = ? AND uid = ? ORDER BY id DESC LIMIT ${LOG_MAX}`
    )
      .bind(row.id, s.user.uid)
      .all<{ event_type: string; status: number | null; ok: number; error: string | null; created_at: number; ms: number | null }>();
    const counts = (await countsOf(c.env, s.user.uid, row.id)).get(row.id) || { queued: 0, failed: 0 };
    return {
      log: (logs.results || []).map((l) => ({
        at: l.created_at,
        ev: l.event_type,
        ok: l.ok === 1,
        ...(l.status != null ? { status: l.status } : {}),
        ...(l.ms != null ? { ms: l.ms } : {}),
        ...(l.error ? { msg: l.error } : {}),
      })),
      ...counts,
    };
  })
);

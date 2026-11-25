import { Hono } from 'hono';
import { Env, webhookEnabled } from '../env';
import { hmacSha256Hex, openSecret, randomHex, sealSecret } from '../crypto';
import { getSessionFromRequest, textField, writeAudit } from '../db';

export const webhookRoutes = new Hono<{ Bindings: Env }>();

const ALLOWED_EVENTS = ['workout.logged', 'bodyweight.logged'] as const;

interface WebhookRow {
  id: string;
  uid: string;
  label: string;
  url: string;
  secret_enc: string;
  events_json: string;
  enabled: number;
  last_status: number | null;
  last_error: string | null;
  last_at: number | null;
  created_at: number;
}

function sealKey(env: Env): string {
  return env.ENC_KEY || env.SESSION_SECRET;
}

function validWebhookUrl(raw: string): boolean {
  try {
    const u = new URL(raw);
    if (u.protocol !== 'https:') return false;
    if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0)/i.test(u.hostname)) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

async function deliverSingleWebhook(
  env: Env,
  wh: WebhookRow,
  eventType: string,
  payload: Record<string, unknown>
): Promise<{ ok: boolean; status: number | null; error: string | null }> {
  const secret = await openSecret(sealKey(env), wh.secret_enc, `wh:${wh.id}`);
  const body = JSON.stringify({ event: eventType, ts: Date.now(), data: payload });
  const sig = secret ? await hmacSha256Hex(secret, body) : '';

  let status: number | null = null;
  let ok = false;
  let error: string | null = null;

  try {
    const res = await fetch(wh.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'openGym-Worker/1.0',
        'X-OpenGym-Event': eventType,
        ...(sig ? { 'X-OpenGym-Signature': `sha256=${sig}` } : {}),
      },
      body,
      signal: AbortSignal.timeout(8000),
    });
    status = res.status;
    ok = res.ok;
    if (!ok) error = `HTTP ${res.status}`;
  } catch (e) {
    error = (e as Error).message || 'network error';
  }

  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare('UPDATE webhooks SET last_status = ?, last_error = ?, last_at = ? WHERE id = ?').bind(
      status,
      error,
      now,
      wh.id
    ),
    env.DB.prepare(
      `INSERT INTO webhook_logs (webhook_id, uid, event_type, status, ok, error, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(wh.id, wh.uid, eventType, status, ok ? 1 : 0, error, now),
  ]);

  return { ok, status, error };
}

/**
 * Called via ctx.waitUntil() after PUT /api/data so API responses stay fast and under 10 ms CPU.
 */
export async function dispatchWebhooks(
  env: Env,
  uid: string,
  prevState: Record<string, unknown> | null,
  nextState: Record<string, unknown>
): Promise<void> {
  if (!webhookEnabled(env)) return;

  const prevWorkouts = Array.isArray(prevState?.workouts) ? prevState.workouts.length : 0;
  const nextWorkouts = Array.isArray(nextState.workouts) ? nextState.workouts : [];
  const prevBw = Array.isArray(prevState?.bodyweight) ? prevState.bodyweight.length : 0;
  const nextBw = Array.isArray(nextState.bodyweight) ? nextState.bodyweight : [];

  const events: Array<{ type: string; payload: Record<string, unknown> }> = [];
  if (nextWorkouts.length > prevWorkouts) {
    const latest = nextWorkouts[nextWorkouts.length - 1] as Record<string, unknown>;
    events.push({ type: 'workout.logged', payload: { workout: latest } });
  }
  if (nextBw.length > prevBw) {
    const latest = nextBw[nextBw.length - 1] as Record<string, unknown>;
    events.push({ type: 'bodyweight.logged', payload: { entry: latest } });
  }
  if (!events.length) return;

  const rows = await env.DB.prepare('SELECT * FROM webhooks WHERE uid = ? AND enabled = 1')
    .bind(uid)
    .all<WebhookRow>();
  for (const wh of rows.results || []) {
    const subscribed = JSON.parse(wh.events_json || '[]') as string[];
    for (const ev of events) {
      if (subscribed.includes(ev.type)) {
        await deliverSingleWebhook(env, wh, ev.type, ev.payload);
      }
    }
  }
}

/* ---------- User Integration Routes ---------- */

webhookRoutes.get('/api/integrations', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  if (!webhookEnabled(c.env)) return c.json({ providers: [], connections: [] });

  const res = await c.env.DB.prepare('SELECT * FROM webhooks WHERE uid = ? ORDER BY created_at DESC')
    .bind(s.user.uid)
    .all<WebhookRow>();

  return c.json({
    providers: [{ id: 'webhook', label: 'Webhook', events: ALLOWED_EVENTS }],
    connections: (res.results || []).map((w) => ({
      id: w.id,
      provider: 'webhook',
      label: w.label,
      url: w.url,
      events: JSON.parse(w.events_json),
      enabled: w.enabled === 1,
      lastStatus: w.last_status,
      lastError: w.last_error,
      lastAt: w.last_at,
      created: w.created_at,
    })),
  });
});

webhookRoutes.post('/api/integrations/connect', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  if (!webhookEnabled(c.env)) return c.json({ error: 'integrations off' }, 404);

  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const url = textField(body.url).trim();
  if (!validWebhookUrl(url)) {
    return c.json({ error: 'webhook url must be a public https:// address' }, 400);
  }
  const label = textField(body.label).trim().slice(0, 60) || new URL(url).hostname;
  const events = Array.isArray(body.events)
    ? body.events.filter((e): e is string => typeof e === 'string' && (ALLOWED_EVENTS as readonly string[]).includes(e))
    : [...ALLOWED_EVENTS];

  const id = 'wh_' + randomHex(8);
  const rawSecret = textField(body.secret).trim() || randomHex(24);
  const sealed = await sealSecret(sealKey(c.env), rawSecret, `wh:${id}`);
  const now = Date.now();

  await c.env.DB.prepare(
    `INSERT INTO webhooks (id, uid, label, url, secret_enc, events_json, enabled, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 1, ?)`
  )
    .bind(id, s.user.uid, label, url, sealed, JSON.stringify(events), now)
    .run();

  await writeAudit(c.env, c.req.raw, 'integration.connect', { user: s.user, msg: `webhook: ${label}` });
  return c.json({
    connection: { id, provider: 'webhook', label, url, events, enabled: true, created: now },
    secret: rawSecret,
  });
});

webhookRoutes.post('/api/integrations/update', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const id = textField(body.id);
  const wh = await c.env.DB.prepare('SELECT * FROM webhooks WHERE id = ? AND uid = ?')
    .bind(id, s.user.uid)
    .first<WebhookRow>();
  if (!wh) return c.json({ error: 'no such connection' }, 404);

  const enabled = body.enabled !== undefined ? (body.enabled ? 1 : 0) : wh.enabled;
  const label = typeof body.label === 'string' ? body.label.trim().slice(0, 60) || wh.label : wh.label;
  const eventsJson = Array.isArray(body.events)
    ? JSON.stringify(
        body.events.filter((e): e is string => typeof e === 'string' && (ALLOWED_EVENTS as readonly string[]).includes(e))
      )
    : wh.events_json;

  await c.env.DB.prepare('UPDATE webhooks SET label = ?, events_json = ?, enabled = ? WHERE id = ?')
    .bind(label, eventsJson, enabled, wh.id)
    .run();
  return c.json({ ok: true });
});

webhookRoutes.post('/api/integrations/disconnect', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const id = textField(body.id);
  const res = await c.env.DB.prepare('DELETE FROM webhooks WHERE id = ? AND uid = ?')
    .bind(id, s.user.uid)
    .run();
  if (!res.meta.changes) return c.json({ error: 'no such connection' }, 404);
  await writeAudit(c.env, c.req.raw, 'integration.disconnect', { user: s.user, msg: id });
  return c.json({ ok: true });
});

webhookRoutes.post('/api/integrations/test', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const wh = await c.env.DB.prepare('SELECT * FROM webhooks WHERE id = ? AND uid = ?')
    .bind(textField(body.id), s.user.uid)
    .first<WebhookRow>();
  if (!wh) return c.json({ error: 'no such connection' }, 404);
  const result = await deliverSingleWebhook(c.env, wh, 'test.ping', { message: 'openGym webhook test' });
  return c.json(result);
});

webhookRoutes.get('/api/integrations/log', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const id = c.req.query('id');
  const res = id
    ? await c.env.DB.prepare(
        'SELECT * FROM webhook_logs WHERE uid = ? AND webhook_id = ? ORDER BY created_at DESC LIMIT 50'
      )
        .bind(s.user.uid, id)
        .all()
    : await c.env.DB.prepare('SELECT * FROM webhook_logs WHERE uid = ? ORDER BY created_at DESC LIMIT 50')
        .bind(s.user.uid)
        .all();
  return c.json({ entries: res.results || [] });
});

import { Hono } from 'hono';
import { Env, flagOn, resolveSessionDays, webhookEnabled } from '../env';
import { getSessionFromRequest, makeBearerSessionToken, publicUser } from '../db';
// Upstream's nudge rule, imported as-is (pure ESM): the same answer a Docker server gives.
import { excusedOn, nudgeFor } from '../../../api/nudge.js';

export const metaRoutes = new Hono<{ Bindings: Env }>();

metaRoutes.get('/api/health', async (c) => {
  try {
    const row = await c.env.DB.prepare('SELECT COUNT(*) AS cnt FROM users').first<{ cnt: number }>();
    return c.json({ ok: true, users: row?.cnt ?? 0, writable: true });
  } catch (e) {
    console.error('health check failed', e);
    return c.json({ ok: false, writable: false }, 503);
  }
});

metaRoutes.get('/api/config', async (c) => {
  const session = await getSessionFromRequest(c.env, c.req.raw);
  const signedIn = !!session;
  const inviteOnly = flagOn(c.env.INVITE_ONLY, false);
  const allowGuest = flagOn(c.env.ALLOW_GUEST, true);
  const apiTokens = flagOn(c.env.API_TOKENS, true);
  const mcpOn = flagOn(c.env.MCP, true);
  const defaultLang = (c.env.DEFAULT_LANG || '').trim();

  // The Coach's job runner needs a filesystem, timers and long-lived processes, so it is not
  // offered here: a session gets `coach: null`, what upstream's publicConfig() answers with the
  // Coach off, and the app hides it (frontend lib/coach.js coachAvailable).
  const coachPublic = null;

  return c.json({
    invite_only: inviteOnly,
    allow_guest: allowGuest,
    signed_in: signedIn,
    ...(apiTokens && signedIn ? { api_tokens: true, ...(mcpOn ? { mcp: true } : {}) } : {}),
    ...(defaultLang ? { default_lang: defaultLang } : {}),
    ...(signedIn ? { coach: coachPublic } : {}),
    ...(signedIn && webhookEnabled(c.env)
      ? { integrations: { providers: ['webhook'] } }
      : {}),
  });
});

metaRoutes.get('/api/me', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const days = resolveSessionDays(c.env);
  const shouldRenew = s.bearer && s.kind !== 'c' && s.exp - Date.now() < (days * 86_400_000) / 2;
  const token = shouldRenew ? await makeBearerSessionToken(c.env, s.user) : undefined;
  return c.json({
    user: publicUser(c.env, s.user),
    ...(token ? { token } : {}),
  });
});

metaRoutes.get('/api/nudge-check', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const date = c.req.query('date') || '';
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(Date.parse(`${date}T00:00:00Z`))) {
    return c.json({ error: 'date must be YYYY-MM-DD', code: 'date-invalid' }, 400);
  }
  const row = await c.env.DB.prepare('SELECT rev, state_json FROM user_states WHERE uid = ?')
    .bind(s.user.uid)
    .first<{ rev: number; state_json: string }>();
  const doc = row ? (JSON.parse(row.state_json) as Record<string, unknown>) : {};
  const workouts = Array.isArray(doc.workouts) ? (doc.workouts as Array<{ d?: string }>) : [];
  const done = workouts.some((w) => w && w.d === date) || !!excusedOn(doc, date);
  let nudge = false;
  try {
    nudge = !done && !!nudgeFor(doc, date);
  } catch {
    nudge = true; // unreadable: keep what the phone planned
  }
  return c.json({ date, done, nudge, rev: row?.rev ?? 0 });
});

metaRoutes.post('/api/activity', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  return c.json({ ok: true });
});

// Web Push (rest-timer and reminder notifications in the browser) is not offered on this
// deployment yet; the phone apps notify on their own. Settings → Notifications asks for the key
// first, so that is where the answer has to be human rather than "not found".
metaRoutes.get('/api/push/public-key', (c) =>
  c.json({ error: 'Push notifications are not available on this server' }, 503)
);

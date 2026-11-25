import { Hono } from 'hono';
import { Env, flagOn, resolveSessionDays, webhookEnabled } from '../env';
import { getSessionFromRequest, makeBearerSessionToken, publicUser } from '../db';

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

  let coachPublic: Record<string, unknown> | null = null;
  if (signedIn) {
    try {
      const cfg = await c.env.DB.prepare(
        'SELECT enabled, active_provider, config_json, providers_enc_json FROM coach_settings WHERE id = 1'
      ).first<{
        enabled: number;
        active_provider: string;
        config_json: string;
        providers_enc_json: string;
      }>();
      if (cfg && cfg.enabled === 1) {
        const enc = JSON.parse(cfg.providers_enc_json || '{}') as Record<string, unknown>;
        if (enc[cfg.active_provider]) {
          const parsedCfg = JSON.parse(cfg.config_json || '{}') as Record<string, unknown>;
          coachPublic = {
            enabled: true,
            provider: cfg.active_provider,
            model: (parsedCfg.models as Record<string, string> | undefined)?.[cfg.active_provider] || null,
          };
        }
      }
    } catch {
      coachPublic = null;
    }
  }

  return c.json({
    invite_only: inviteOnly,
    allow_guest: allowGuest,
    signed_in: signedIn,
    ...(apiTokens && signedIn ? { api_tokens: true, ...(mcpOn ? { mcp: true } : {}) } : {}),
    ...(defaultLang ? { default_lang: defaultLang } : {}),
    ...(signedIn ? { coach: coachPublic } : {}),
    ...(signedIn && webhookEnabled(c.env)
      ? { integrations: { providers: [{ id: 'webhook', label: 'Webhook' }] } }
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
  const done = workouts.some((w) => w && w.d === date);
  return c.json({ date, done, nudge: !done, rev: row?.rev ?? 0 });
});

metaRoutes.post('/api/activity', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  return c.json({ ok: true });
});

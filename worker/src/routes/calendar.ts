/**
 * The calendar feed (api/server.js 'GET /api/calendar' and nearby, api/integrations/calendar.js).
 * One private ICS address per profile: a `calendar`-kind token in its path, sealed in its api_tokens
 * row (`seal_enc`) so Settings can show the address again. A new address ends the old one.
 */
import { Hono } from 'hono';
import { Env, flagOn, resolveOrigin } from '../env';
import { hashApiToken, openSecret, sealSecret } from '../crypto';
import { UserRow, getSessionFromRequest, getUserById, writeAudit } from '../db';
import { ScopeError, TOKEN_PREFIX, TokenScopes, scopedState } from '../scopes';
import { ApiTokenRow, createScopedToken } from './tokens';
import { readUserState } from './data';
import { buildIcs } from '../../../api/integrations/calendar.js';

export const calendarRoutes = new Hono<{ Bindings: Env }>();

const FEED_RE = /^(ogt_[A-Za-z0-9_-]{43})\.ics$/;
const sealKey = (env: Env): string => env.ENC_KEY || env.SESSION_SECRET;
const aadOf = (id: string) => 'calendar:' + id;

async function calRow(env: Env, user: UserRow): Promise<ApiTokenRow | null> {
  const row = await env.DB.prepare(
    `SELECT * FROM api_tokens WHERE uid = ? AND kind = 'calendar' AND (expires_at IS NULL OR expires_at > ?)
     ORDER BY created_at DESC LIMIT 1`
  )
    .bind(user.uid, Date.now())
    .first<ApiTokenRow>();
  return row && row.session_version === user.session_version ? row : null;
}

async function calView(env: Env, req: Request, user: UserRow) {
  const r = await calRow(env, user);
  if (!r) return { on: false };
  const sealed = (r as ApiTokenRow & { seal_enc?: string | null }).seal_enc;
  const token = sealed ? await openSecret(sealKey(env), sealed, aadOf(r.id)) : null;
  let scopes: Partial<TokenScopes> = {};
  try {
    scopes = JSON.parse(r.scopes_json);
  } catch {
    /* none */
  }
  return {
    on: true,
    id: r.id,
    done: scopes.workouts === 'view',
    created: r.created_at,
    used: r.last_used_at || null,
    ...(token ? { url: resolveOrigin(env, req) + '/api/calendar/' + token + '.ics' } : {}),
  };
}

const notFound = { error: 'not found' };
const off = (env: Env) => !flagOn(env.API_TOKENS, true);

calendarRoutes.get('/api/calendar', async (c) => {
  if (off(c.env)) return c.json(notFound, 404);
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  return c.json(await calView(c.env, c.req.raw, s.user));
});

// { done: bool } with the feed on changes what it shows and keeps the address; `renew: true`
// (or no feed yet) makes a new address and ends the old.
calendarRoutes.post('/api/calendar', async (c) => {
  if (off(c.env)) return c.json(notFound, 404);
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const done = body.done === true;
  const scopes = { plans: 'view', workouts: done ? 'view' : 'off' };
  const cur = await calRow(c.env, s.user);
  if (cur && body.renew !== true) {
    await c.env.DB.prepare('UPDATE api_tokens SET scopes_json = ? WHERE id = ?')
      .bind(JSON.stringify({ ...JSON.parse(cur.scopes_json), ...scopes }), cur.id)
      .run();
    return c.json(await calView(c.env, c.req.raw, s.user));
  }
  if (!sealKey(c.env)) return c.json({ error: 'the server secret is missing' }, 503);
  await c.env.DB.prepare("DELETE FROM api_tokens WHERE uid = ? AND kind = 'calendar'").bind(s.user.uid).run();
  let made;
  try {
    made = await createScopedToken(c.env, s.user, { name: 'Calendar feed', scopes, days: 0, kind: 'calendar' });
  } catch (e) {
    if (e instanceof ScopeError) return c.json({ error: e.message, code: e.code }, e.status as 400 | 409);
    throw e;
  }
  const sealed = await sealSecret(sealKey(c.env), made.token, aadOf(made.row.id));
  await c.env.DB.prepare('UPDATE api_tokens SET seal_enc = ? WHERE id = ?').bind(sealed, made.row.id).run();
  await writeAudit(c.env, c.req.raw, 'auth.token.create', { user: s.user, msg: made.row.label });
  return c.json(await calView(c.env, c.req.raw, s.user));
});

calendarRoutes.post('/api/calendar/revoke', async (c) => {
  if (off(c.env)) return c.json(notFound, 404);
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const r = await calRow(c.env, s.user);
  if (r) {
    await c.env.DB.prepare('DELETE FROM api_tokens WHERE id = ?').bind(r.id).run();
    await writeAudit(c.env, c.req.raw, 'auth.token.revoke', { user: s.user, msg: r.label });
  }
  return c.json({ on: false });
});

// The feed itself, for a calendar app: no cookie, no header, the token in the path.
calendarRoutes.get('/api/calendar/:file', async (c) => {
  if (off(c.env)) return c.json(notFound, 404);
  const m = FEED_RE.exec(c.req.param('file'));
  const fail = async () => {
    await writeAudit(c.env, c.req.raw, 'auth.token.fail', { ok: false, msg: 'token-invalid' });
    return c.json(notFound, 404);
  };
  if (!m || !m[1].startsWith(TOKEN_PREFIX)) return fail();
  const row = await c.env.DB.prepare("SELECT * FROM api_tokens WHERE token_sha256 = ? AND kind = 'calendar'")
    .bind(await hashApiToken(m[1]))
    .first<ApiTokenRow>();
  const now = Date.now();
  if (!row || (row.expires_at && row.expires_at <= now)) return fail();
  const user = await getUserById(c.env, row.uid);
  if (!user || user.disabled === 1 || user.session_version !== row.session_version) return fail();
  if (!row.last_used_at || now - row.last_used_at >= 60_000) {
    c.executionCtx.waitUntil(
      c.env.DB.prepare('UPDATE api_tokens SET last_used_at = ? WHERE id = ?').bind(now, row.id).run().then(() => undefined)
    );
  }
  const scopes = JSON.parse(row.scopes_json) as TokenScopes;
  const cur = await readUserState(c.env, user.uid);
  const state = cur.state;
  const ics = buildIcs(state ? scopedState(state, scopes) : {}, {
    uid: user.uid,
    done: scopes.workouts === 'view',
    tz: (state as { reminder?: { tz?: string } } | null)?.reminder?.tz,
    name: user.username || '',
  });
  return new Response(ics, {
    status: 200,
    headers: {
      'Content-Type': 'text/calendar; charset=utf-8',
      'Cache-Control': 'private, max-age=900',
      'Content-Disposition': 'inline; filename="opengym.ics"',
      'X-Content-Type-Options': 'nosniff',
    },
  });
});

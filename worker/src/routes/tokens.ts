import { Hono } from 'hono';
import { Env, flagOn } from '../env';
import { hashApiToken, randomBase64Url, randomHex } from '../crypto';
import { UserRow, getSessionFromRequest, getUserById, textField, writeAudit } from '../db';
import {
  DEFAULT_DAYS,
  ScopeError,
  TOKEN_CATEGORIES,
  TOKEN_DAYS,
  TOKEN_PREFIX,
  TOKENS_MAX,
  TokenScopes,
  cleanTokenScopes,
  grantsNothing,
  mergeScoped,
  scopedState,
} from '../scopes';
import { commitUserState, readUserState, sanitizeRecords } from './data';

export const tokenRoutes = new Hono<{ Bindings: Env }>();

export interface ApiTokenRow {
  id: string;
  token_sha256: string;
  uid: string;
  session_version: number;
  hint: string;
  label: string;
  scopes_json: string;
  kind: string | null;
  connector_json: string | null;
  refresh_sha256: string | null;
  prev_refresh_sha256: string | null;
  rotated_at: number | null;
  access_expires_at: number | null;
  expires_at: number | null;
  created_at: number;
  last_used_at: number | null;
}

export interface AuthenticatedApiToken {
  row: ApiTokenRow;
  user: UserRow;
  scopes: TokenScopes;
}

function cleanLabel(raw: unknown): string {
  return String(raw || '')
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .trim()
    .slice(0, 40) || 'API token';
}

export async function listUserTokens(env: Env, user: UserRow) {
  const now = Date.now();
  const res = await env.DB.prepare(
    `SELECT * FROM api_tokens
     WHERE uid = ? AND session_version = ? AND (expires_at IS NULL OR expires_at > ?)
     ORDER BY created_at DESC`
  )
    .bind(user.uid, user.session_version, now)
    .all<ApiTokenRow>();

  return (res.results || []).map((r) => {
    const connector = r.connector_json ? (JSON.parse(r.connector_json) as { assistant?: string; name?: string }) : null;
    return {
      id: r.id,
      name: r.label,
      hint: r.hint,
      scopes: JSON.parse(r.scopes_json) as TokenScopes,
      created: r.created_at,
      exp: r.expires_at,
      used: r.last_used_at,
      ...(r.kind ? { kind: r.kind } : {}),
      ...(connector ? { connector: { assistant: connector.assistant || 'other', client: connector.name || '' } } : {}),
    };
  });
}

export async function createScopedToken(
  env: Env,
  user: UserRow,
  opts: {
    name?: string;
    scopes: unknown;
    days?: number;
    kind?: string | null;
    connector?: { assistant: string; client: string; name: string } | null;
    refreshSha256?: string | null;
    accessExpiresAt?: number | null;
    evictConnector?: boolean;
  }
): Promise<{ token: string; row: ApiTokenRow; scopes: TokenScopes }> {
  const now = Date.now();
  const scopes = cleanTokenScopes(opts.scopes);
  if (grantsNothing(scopes)) {
    throw new ScopeError(400, 'nothing-granted', 'a token needs at least one thing it may see');
  }

  // Prune expired or old-session-version tokens for this user
  await env.DB.prepare(
    'DELETE FROM api_tokens WHERE uid = ? AND (session_version != ? OR (expires_at IS NOT NULL AND expires_at <= ?))'
  )
    .bind(user.uid, user.session_version, now)
    .run();

  const existing = await env.DB.prepare(
    'SELECT id, connector_json, last_used_at, created_at FROM api_tokens WHERE uid = ? ORDER BY COALESCE(last_used_at, created_at) ASC'
  )
    .bind(user.uid)
    .all<{ id: string; connector_json: string | null; last_used_at: number | null; created_at: number }>();

  const rows = existing.results || [];
  if (rows.length >= TOKENS_MAX && opts.evictConnector) {
    const oldConn = rows.find((r) => !!r.connector_json);
    if (oldConn) {
      await env.DB.prepare('DELETE FROM api_tokens WHERE id = ?').bind(oldConn.id).run();
    }
  }

  const countRow = await env.DB.prepare('SELECT COUNT(*) AS cnt FROM api_tokens WHERE uid = ?')
    .bind(user.uid)
    .first<{ cnt: number }>();
  if ((countRow?.cnt ?? 0) >= TOKENS_MAX) {
    throw new ScopeError(409, 'too-many', `at most ${TOKENS_MAX} tokens per profile: revoke one first`);
  }

  const days = opts.days == null ? DEFAULT_DAYS : Number(opts.days);
  if (!TOKEN_DAYS.includes(days as (typeof TOKEN_DAYS)[number])) {
    throw new ScopeError(400, 'bad-days', 'days must be one of ' + TOKEN_DAYS.join(', '));
  }

  const token = TOKEN_PREFIX + randomBase64Url(32);
  const hash = await hashApiToken(token);
  const id = 't_' + randomHex(6);
  const hint = token.slice(TOKEN_PREFIX.length, TOKEN_PREFIX.length + 6);
  const label = cleanLabel(opts.name);
  const expiresAt = days ? now + days * 86_400_000 : null;

  await env.DB.prepare(
    `INSERT INTO api_tokens (
       id, token_sha256, uid, session_version, hint, label, scopes_json, kind,
       connector_json, refresh_sha256, access_expires_at, expires_at, created_at, last_used_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`
  )
    .bind(
      id,
      hash,
      user.uid,
      user.session_version,
      hint,
      label,
      JSON.stringify(scopes),
      opts.kind || null,
      opts.connector ? JSON.stringify(opts.connector) : null,
      opts.refreshSha256 || null,
      opts.accessExpiresAt ?? null,
      expiresAt,
      now
    )
    .run();

  const row = (await env.DB.prepare('SELECT * FROM api_tokens WHERE id = ?').bind(id).first<ApiTokenRow>())!;
  return { token, row, scopes };
}

export async function authenticateApiToken(
  env: Env,
  ctx: { waitUntil(promise: Promise<unknown>): void },
  rawToken: string
): Promise<AuthenticatedApiToken | null> {
  if (!rawToken || !rawToken.startsWith(TOKEN_PREFIX) || rawToken.length !== TOKEN_PREFIX.length + 43) {
    return null;
  }
  const hash = await hashApiToken(rawToken);
  const row = await env.DB.prepare('SELECT * FROM api_tokens WHERE token_sha256 = ?')
    .bind(hash)
    .first<ApiTokenRow>();
  if (!row || row.kind) return null;
  const now = Date.now();
  if ((row.expires_at && row.expires_at <= now) || (row.access_expires_at && row.access_expires_at <= now)) {
    return null;
  }
  const user = await getUserById(env, row.uid);
  if (!user || user.disabled === 1 || user.session_version !== row.session_version) {
    return null;
  }
  if (!row.last_used_at || now - row.last_used_at >= 60_000) {
    ctx.waitUntil(env.DB.prepare('UPDATE api_tokens SET last_used_at = ? WHERE id = ?').bind(now, row.id).run());
  }
  return { row, user, scopes: JSON.parse(row.scopes_json) as TokenScopes };
}

function bearerTokenFromRequest(req: Request): string {
  const auth = req.headers.get('authorization') || '';
  return auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
}

/* ---------- User Session Routes (Settings -> API Tokens) ---------- */

tokenRoutes.get('/api/tokens', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  return c.json({
    tokens: await listUserTokens(c.env, s.user),
    categories: TOKEN_CATEGORIES,
    days: TOKEN_DAYS,
    defaultDays: DEFAULT_DAYS,
    mcp: flagOn(c.env.MCP, true),
  });
});

tokenRoutes.post('/api/tokens', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  try {
    const made = await createScopedToken(c.env, s.user, {
      name: textField(body.name),
      scopes: body.scopes,
      days: body.days as number | undefined,
    });
    await writeAudit(c.env, c.req.raw, 'auth.token.create', { user: s.user, msg: made.row.label });
    return c.json({
      token: made.token,
      tokens: await listUserTokens(c.env, s.user),
      id: made.row.id,
    });
  } catch (e) {
    if (e instanceof ScopeError) return c.json({ error: e.message, code: e.code }, e.status as 400 | 403 | 409);
    throw e;
  }
});

tokenRoutes.post('/api/tokens/revoke', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const id = textField(body.id) || null;
  const res = id
    ? await c.env.DB.prepare('DELETE FROM api_tokens WHERE uid = ? AND id = ?').bind(s.user.uid, id).run()
    : await c.env.DB.prepare('DELETE FROM api_tokens WHERE uid = ?').bind(s.user.uid).run();
  const revoked = res.meta.changes ?? 0;
  if (revoked > 0) {
    await writeAudit(c.env, c.req.raw, 'auth.token.revoke', {
      user: s.user,
      msg: id || `${revoked} tokens`,
    });
  }
  return c.json({ ok: true, revoked, tokens: await listUserTokens(c.env, s.user) });
});

/* ---------- Scoped Token Data Routes (/api/token/*) ---------- */

tokenRoutes.get('/api/token/me', async (c) => {
  const auth = await authenticateApiToken(c.env, c.executionCtx, bearerTokenFromRequest(c.req.raw));
  if (!auth) {
    return c.json(
      { error: 'token not accepted', code: 'token-invalid' },
      401,
      { 'WWW-Authenticate': 'Bearer error="invalid_token"' }
    );
  }
  return c.json({
    user: { id: auth.user.uid, name: auth.user.username },
    token: { id: auth.row.id, name: auth.row.label, scopes: auth.scopes, exp: auth.row.expires_at },
  });
});

tokenRoutes.get('/api/token/data', async (c) => {
  const auth = await authenticateApiToken(c.env, c.executionCtx, bearerTokenFromRequest(c.req.raw));
  if (!auth) {
    return c.json(
      { error: 'token not accepted', code: 'token-invalid' },
      401,
      { 'WWW-Authenticate': 'Bearer error="invalid_token"' }
    );
  }
  const cur = await readUserState(c.env, auth.user.uid);
  return c.json({
    state: cur.state ? scopedState(cur.state, auth.scopes) : null,
    rev: cur.rev,
    ...(cur.wid ? { wid: cur.wid } : {}),
  });
});

tokenRoutes.get('/api/token/data/rev', async (c) => {
  const auth = await authenticateApiToken(c.env, c.executionCtx, bearerTokenFromRequest(c.req.raw));
  if (!auth) {
    return c.json(
      { error: 'token not accepted', code: 'token-invalid' },
      401,
      { 'WWW-Authenticate': 'Bearer error="invalid_token"' }
    );
  }
  const row = await c.env.DB.prepare('SELECT rev, wid FROM user_states WHERE uid = ?')
    .bind(auth.user.uid)
    .first<{ rev: number; wid: string | null }>();
  return c.json({ rev: row?.rev ?? 0, ...(row?.wid ? { wid: row.wid } : {}) });
});

tokenRoutes.put('/api/token/data', async (c) => {
  const auth = await authenticateApiToken(c.env, c.executionCtx, bearerTokenFromRequest(c.req.raw));
  if (!auth) {
    return c.json(
      { error: 'token not accepted', code: 'token-invalid' },
      401,
      { 'WWW-Authenticate': 'Bearer error="invalid_token"' }
    );
  }
  const body = (await c.req.json().catch(() => null)) as Record<string, unknown> | null;
  if (!body || !body.state || typeof body.state !== 'object' || Array.isArray(body.state)) {
    return c.json({ error: 'state required' }, 400);
  }
  if (!Number.isInteger(body.baseRev)) {
    return c.json({ error: 'baseRev required: write over the revision you read', code: 'base-rev' }, 400);
  }

  const cur = await readUserState(c.env, auth.user.uid);
  if (!cur.state) {
    return c.json({ error: 'this profile has not synced from a device yet', code: 'not-synced' }, 409);
  }
  if (body.baseRev !== cur.rev || (typeof body.baseWid === 'string' && cur.wid && body.baseWid !== cur.wid)) {
    return c.json(
      {
        error: 'conflict',
        rev: cur.rev,
        state: scopedState(cur.state, auth.scopes),
        ...(cur.wid ? { wid: cur.wid } : {}),
      },
      409
    );
  }

  let merged;
  try {
    merged = mergeScoped(cur.state, body.state as Record<string, unknown>, auth.scopes);
  } catch (e) {
    if (e instanceof ScopeError) {
      return c.json({ error: e.message, code: e.code }, e.status as 400 | 403);
    }
    throw e;
  }

  if (!merged.touched.length) {
    return c.json({ ok: true, unchanged: true, rev: cur.rev, ...(cur.wid ? { wid: cur.wid } : {}) });
  }

  const next = merged.next;
  const validList = (v: unknown) => v == null || Array.isArray(v);
  if (!validList(next.workouts) || !validList(next.routines)) return c.json({ error: 'invalid state' }, 400);
  if (Array.isArray(next.workouts)) next.workouts = sanitizeRecords(next.workouts);
  if (Array.isArray(next.routines)) next.routines = sanitizeRecords(next.routines);

  // Stamped like any writer that does not stamp its own changes, over the revision it read
  // (api/server.js PUT /api/token/data: overRead true, stamped false).
  const done = await commitUserState(c.env, c.executionCtx, auth.user.uid, cur, next, {
    baseRev: body.baseRev as number,
    baseWid: typeof body.baseWid === 'string' ? body.baseWid : null,
    stamped: false,
  });
  // Another device wrote between the read above and this write: the 409 carries the current
  // document as this token may see it, never the whole profile.
  if (done.status === 409) {
    const fresh = await readUserState(c.env, auth.user.uid);
    return c.json(
      {
        error: 'conflict',
        rev: fresh.rev,
        state: fresh.state ? scopedState(fresh.state, auth.scopes) : null,
        ...(fresh.wid ? { wid: fresh.wid } : {}),
      },
      409
    );
  }
  if (done.status === 200) {
    await writeAudit(c.env, c.req.raw, 'token.write', {
      user: auth.user,
      msg: `${auth.row.label}: ${merged.touched.join(', ')}`,
    });
  }
  return c.json(done.body, done.status);
});

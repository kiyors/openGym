import { Hono } from 'hono';
import { Env, resolveOrigin } from '../env';
import {
  hashApiToken,
  hashRefreshToken,
  randomBase64Url,
  sha256Base64Url,
  timingSafeEqualStr,
} from '../crypto';
import {
  getSessionFromRequest,
  getUserById,
  peekEphemeral,
  putEphemeral,
  takeEphemeral,
  textField,
  writeAudit,
} from '../db';
import {
  OAUTH_SCOPES,
  ScopeError,
  TOKEN_CATEGORIES,
  TOKEN_DAYS,
  TOKEN_PREFIX,
  TokenScopes,
  scopeString,
  scopesFromString,
} from '../scopes';
import { ApiTokenRow, createScopedToken } from './tokens';

export const oauthRoutes = new Hono<{ Bindings: Env }>();

const REQUEST_TTL_MS = 10 * 60_000;
const CODE_TTL_MS = 10 * 60_000;
const ACCESS_TTL_MS = 24 * 3_600_000;
const REFRESH_GRACE_MS = 60_000;
const REFRESH_PREFIX = 'ogr_';
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);
const GRANTS = ['authorization_code', 'refresh_token'];
const MAX_REDIRECTS = 20;

function redirectOk(raw: string): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.hash || u.username || u.password || raw.length > 500) return false;
  if (u.protocol === 'https:') return true;
  return u.protocol === 'http:' && LOOPBACK.has(u.hostname);
}

function sameRedirect(registered: string, asked: string): boolean {
  if (registered === asked) return true;
  try {
    const a = new URL(registered);
    const b = new URL(asked);
    return (
      a.protocol === 'http:' &&
      b.protocol === 'http:' &&
      LOOPBACK.has(a.hostname) &&
      a.hostname === b.hostname &&
      a.pathname === b.pathname &&
      a.search === b.search
    );
  } catch {
    return false;
  }
}

function assistantOf(redirect: string, name = ''): string {
  let host = '';
  try {
    host = new URL(redirect).hostname.toLowerCase();
  } catch {
    // ignore
  }
  const under = (d: string) => host === d || host.endsWith('.' + d);
  if (under('claude.ai') || under('claude.com') || under('anthropic.com')) return 'claude';
  if (under('chatgpt.com') || under('openai.com')) return 'chatgpt';
  if (under('gemini.google.com') || under('google.com') || under('googleusercontent.com')) return 'gemini';
  if (LOOPBACK.has(host) || LOOPBACK.has('[' + host + ']')) {
    if (/claude/i.test(name)) return 'claude';
    if (/chatgpt|codex|openai/i.test(name)) return 'chatgpt';
    if (/gemini/i.test(name)) return 'gemini';
  }
  return 'other';
}

function isCimdId(id: string | null): id is string {
  if (!id || id.length > 500 || !id.startsWith('https://')) return false;
  try {
    const u = new URL(id);
    return (
      u.protocol === 'https:' &&
      u.pathname.length > 1 &&
      !u.hash &&
      !u.username &&
      !u.password &&
      !u.hostname.startsWith('[') &&
      !/^\d+\.\d+\.\d+\.\d+$/.test(u.hostname) &&
      !/(^|\.)localhost$/i.test(u.hostname)
    );
  } catch {
    return false;
  }
}

async function resolveCimdClient(
  id: string
): Promise<{ ok: true; client: { id: string; name: string; redirects: string[]; grants: string[]; cimd: true } } | { ok: false; error: string }> {
  try {
    const res = await fetch(id, {
      headers: { Accept: 'application/json', 'User-Agent': 'openGym' },
      signal: AbortSignal.timeout(5000),
      redirect: 'manual',
    });
    if (res.status !== 200) return { ok: false, error: `HTTP ${res.status}` };
    const text = await res.text();
    if (text.length > 8192) return { ok: false, error: 'client metadata document too large' };
    const doc = JSON.parse(text) as Record<string, unknown>;
    if (doc.client_id !== id) {
      return { ok: false, error: 'client metadata document does not match client_id' };
    }
    const uris = Array.isArray(doc.redirect_uris)
      ? doc.redirect_uris.filter((u): u is string => typeof u === 'string')
      : [];
    if (!uris.length || uris.length > MAX_REDIRECTS || !uris.every(redirectOk)) {
      return { ok: false, error: 'no usable redirect_uris in client metadata document' };
    }
    if ((doc.token_endpoint_auth_method || 'none') !== 'none') {
      return { ok: false, error: 'only public clients are supported' };
    }
    const grants = Array.isArray(doc.grant_types)
      ? GRANTS.filter((g) => (doc.grant_types as string[]).includes(g))
      : ['authorization_code'];
    const name = String(doc.client_name || new URL(id).hostname).trim().slice(0, 60) || 'MCP client';
    return { ok: true, client: { id, name, redirects: uris, grants, cimd: true } };
  } catch (e) {
    return { ok: false, error: `could not fetch client metadata document: ${(e as Error).message}` };
  }
}

function withQuery(base: string, params: Record<string, string | undefined | null>): string {
  const u = new URL(base);
  for (const [k, v] of Object.entries(params)) {
    if (v != null && v !== '') u.searchParams.set(k, v);
  }
  return u.toString();
}

function basicClientId(header: string | null): string | null {
  const m = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(String(header || '').trim());
  if (!m) return null;
  try {
    const decoded = atob(m[1]);
    const idx = decoded.indexOf(':');
    return decodeURIComponent(idx < 0 ? decoded : decoded.slice(0, idx)) || null;
  } catch {
    return null;
  }
}

async function readFormOrJson(req: Request): Promise<URLSearchParams> {
  const ct = req.headers.get('content-type') || '';
  const raw = await req.text();
  if (/json/i.test(ct)) {
    try {
      const obj = JSON.parse(raw || '{}') as Record<string, unknown>;
      return new URLSearchParams(Object.entries(obj).map(([k, v]) => [k, String(v ?? '')]));
    } catch {
      return new URLSearchParams();
    }
  }
  return new URLSearchParams(raw);
}

/* ---------- Discovery (RFC 8414 & RFC 9728) ---------- */

function authServerMetadata(issuer: string) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/api/oauth/authorize`,
    token_endpoint: `${issuer}/api/oauth/token`,
    registration_endpoint: `${issuer}/api/oauth/register`,
    revocation_endpoint: `${issuer}/api/oauth/revoke`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    revocation_endpoint_auth_methods_supported: ['none'],
    scopes_supported: [...OAUTH_SCOPES, 'offline_access'],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
  };
}

function protectedResourceMetadata(issuer: string) {
  return {
    resource: `${issuer}/mcp`,
    authorization_servers: [issuer],
    scopes_supported: OAUTH_SCOPES,
    bearer_methods_supported: ['header'],
    resource_name: 'openGym',
  };
}

oauthRoutes.get('/.well-known/oauth-authorization-server', (c) =>
  c.json(authServerMetadata(resolveOrigin(c.env, c.req.raw)))
);
oauthRoutes.get('/.well-known/openid-configuration', (c) =>
  c.json(authServerMetadata(resolveOrigin(c.env, c.req.raw)))
);
oauthRoutes.get('/.well-known/oauth-protected-resource', (c) =>
  c.json(protectedResourceMetadata(resolveOrigin(c.env, c.req.raw)))
);
oauthRoutes.get('/.well-known/oauth-protected-resource/mcp', (c) =>
  c.json(protectedResourceMetadata(resolveOrigin(c.env, c.req.raw)))
);

/* ---------- Dynamic Client Registration (RFC 7591) ---------- */

oauthRoutes.post('/api/oauth/register', async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const uris = Array.isArray(body.redirect_uris)
    ? body.redirect_uris.filter((u): u is string => typeof u === 'string')
    : [];
  // Up to 20: Google's connector registers six or more at once (sandbox, test and production
  // hosts, each with two paths); upstream's 5 refuses it.
  if (!uris.length || uris.length > MAX_REDIRECTS || !uris.every(redirectOk)) {
    // Public client metadata only: which addresses a connector asked for, so a refusal can be
    // understood from the Worker's logs (wrangler tail).
    console.warn('[oauth] register refused', JSON.stringify({ client_name: body.client_name, redirect_uris: body.redirect_uris }).slice(0, 1000));
    return c.json(
      {
        error: 'invalid_redirect_uri',
        error_description: `redirect_uris: 1-${MAX_REDIRECTS} https addresses (or http on localhost)`,
      },
      400
    );
  }
  const name = String(body.client_name || 'MCP client').trim().slice(0, 60) || 'MCP client';
  const grants = Array.isArray(body.grant_types)
    ? GRANTS.filter((g) => (body.grant_types as string[]).includes(g))
    : ['authorization_code'];
  if (!grants.includes('authorization_code')) grants.unshift('authorization_code');

  const id = 'ogc_' + randomBase64Url(18);
  const now = Date.now();
  await c.env.DB.prepare(
    `INSERT INTO oauth_clients (client_id, name, redirects_json, grants_json, created_at, last_used_at)
     VALUES (?, ?, ?, ?, ?, NULL)`
  )
    .bind(id, name, JSON.stringify(uris), JSON.stringify(grants), now)
    .run();

  return c.json(
    {
      client_id: id,
      client_id_issued_at: Math.floor(now / 1000),
      client_name: name,
      redirect_uris: uris,
      token_endpoint_auth_method: 'none',
      grant_types: grants,
      response_types: ['code'],
    },
    201
  );
});

/* ---------- Authorize & Consent ---------- */

interface PendingOAuthRequest {
  id: string;
  clientId: string;
  clientName: string;
  redirect: string;
  challenge: string;
  state: string | null;
  scopes: TokenScopes;
  refresh: boolean;
  issuer: string;
  assistant: string;
}

oauthRoutes.get('/api/oauth/authorize', async (c) => {
  const issuer = resolveOrigin(c.env, c.req.raw);
  const resourceExpected = `${issuer}/mcp`;
  const url = new URL(c.req.url);
  const q = url.searchParams;
  const clientId = q.get('client_id') || '';

  let client: { id: string; name: string; redirects: string[]; grants: string[]; cimd?: boolean } | null = null;
  if (isCimdId(clientId)) {
    const resolved = await resolveCimdClient(clientId);
    if (!resolved.ok) {
      console.warn('[oauth] client metadata refused', clientId.slice(0, 300), resolved.error);
      return c.text(`openGym could not start this sign-in: ${resolved.error}`, 400);
    }
    client = resolved.client;
  } else {
    const row = await c.env.DB.prepare('SELECT * FROM oauth_clients WHERE client_id = ?')
      .bind(clientId)
      .first<{ client_id: string; name: string; redirects_json: string; grants_json: string }>();
    if (row) {
      client = {
        id: row.client_id,
        name: row.name,
        redirects: JSON.parse(row.redirects_json) as string[],
        grants: JSON.parse(row.grants_json) as string[],
      };
    }
  }

  if (!client) {
    console.warn('[oauth] authorize unknown client', clientId.slice(0, 300));
    return c.text('openGym could not start this sign-in: unknown client_id', 400);
  }
  const redirect = q.get('redirect_uri') || (client.redirects.length === 1 ? client.redirects[0] : '');
  if (!client.redirects.some((r) => sameRedirect(r, redirect))) {
    console.warn('[oauth] authorize redirect refused', JSON.stringify({ client: client.name, asked: redirect.slice(0, 300), registered: client.redirects }).slice(0, 1000));
    return c.text('openGym could not start this sign-in: redirect_uri is not registered', 400);
  }

  const backErr = (error: string, desc: string) =>
    c.redirect(
      withQuery(redirect, { error, error_description: desc, state: q.get('state'), iss: issuer }),
      302
    );

  if (q.get('response_type') !== 'code') return backErr('unsupported_response_type', 'response_type must be code');
  const challenge = q.get('code_challenge') || '';
  if (q.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43,128}$/.test(challenge)) {
    return backErr('invalid_request', 'PKCE with code_challenge_method S256 is required');
  }
  const askedResource = q.get('resource');
  if (
    askedResource &&
    askedResource.replace(/\/+$/, '').toLowerCase() !== resourceExpected.replace(/\/+$/, '').toLowerCase()
  ) {
    return backErr('invalid_target', 'resource does not match this openGym MCP endpoint');
  }

  const reqId = randomBase64Url(18);
  const words = String(q.get('scope') || '').split(/\s+/);
  const refresh = words.includes('offline_access') || client.grants.includes('refresh_token');
  const pending: PendingOAuthRequest = {
    id: reqId,
    clientId: client.id,
    clientName: client.name,
    redirect,
    challenge,
    state: q.get('state'),
    scopes: scopesFromString(q.get('scope')),
    refresh,
    issuer,
    assistant: assistantOf(client.cimd ? client.id : redirect, client.name),
  };

  await putEphemeral(c.env, `oar:${reqId}`, 'oauth_req', pending, REQUEST_TTL_MS);
  return c.redirect(`${issuer}/#/connect/${reqId}`, 302);
});

oauthRoutes.get('/api/oauth/request', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const id = c.req.query('id') || '';
  const entry = await peekEphemeral<PendingOAuthRequest>(c.env, `oar:${id}`, 'oauth_req');
  if (!entry) {
    return c.json({ error: 'this sign-in has expired; start it again from the assistant', code: 'expired' }, 404);
  }
  const r = entry.payload;
  let host = '';
  let loopback = false;
  try {
    const u = new URL(r.redirect);
    host = u.host;
    loopback = LOOPBACK.has(u.hostname);
  } catch {
    // ignore
  }
  return c.json({
    id: r.id,
    client: r.clientName,
    assistant: r.assistant,
    redirectHost: host,
    loopback,
    scopes: r.scopes,
    categories: TOKEN_CATEGORIES,
    days: TOKEN_DAYS,
  });
});

oauthRoutes.post('/api/oauth/approve', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const reqId = textField(body.id);
  const entry = await takeEphemeral<PendingOAuthRequest>(c.env, `oar:${reqId}`, 'oauth_req');
  if (!entry) {
    return c.json({ error: 'this sign-in has expired; start it again from the assistant', code: 'expired' }, 400);
  }
  const r = entry.payload;

  try {
    const now = Date.now();
    const refreshToken = r.refresh ? REFRESH_PREFIX + randomBase64Url(32) : null;
    const refreshSha = refreshToken ? await hashRefreshToken(refreshToken) : null;
    const days = body.days as number | undefined;
    const accessExpiresAt = refreshToken ? now + ACCESS_TTL_MS : null;

    const made = await createScopedToken(c.env, s.user, {
      name: `${r.clientName} (connector)`,
      scopes: body.scopes,
      days,
      connector: { assistant: r.assistant, client: r.clientId, name: r.clientName },
      refreshSha256: refreshSha,
      accessExpiresAt,
      evictConnector: true,
    });

    const effectiveExp = accessExpiresAt
      ? Math.min(accessExpiresAt, made.row.expires_at ?? Infinity)
      : made.row.expires_at;
    const expiresIn = effectiveExp ? Math.max(60, Math.round((effectiveExp - now) / 1000)) : null;

    const code = randomBase64Url(32);
    await putEphemeral(
      c.env,
      `oac:${code}`,
      'oauth_code',
      {
        token: made.token,
        refresh: refreshToken,
        scope: scopeString(made.scopes),
        expiresIn,
        clientId: r.clientId,
        redirect: r.redirect,
        challenge: r.challenge,
      },
      CODE_TTL_MS,
      s.user.uid
    );

    await writeAudit(c.env, c.req.raw, 'auth.token.create', { user: s.user, msg: made.row.label });
    return c.json({
      redirect: withQuery(r.redirect, { code, state: r.state, iss: r.issuer }),
    });
  } catch (e) {
    if (e instanceof ScopeError) return c.json({ error: e.message, code: e.code }, e.status as 400 | 409);
    throw e;
  }
});

oauthRoutes.post('/api/oauth/deny', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const entry = await takeEphemeral<PendingOAuthRequest>(c.env, `oar:${textField(body.id)}`, 'oauth_req');
  if (!entry) return c.json({ error: 'this sign-in has expired', code: 'expired' }, 400);
  return c.json({
    redirect: withQuery(entry.payload.redirect, {
      error: 'access_denied',
      state: entry.payload.state,
      iss: entry.payload.issuer,
    }),
  });
});

/* ---------- Token Exchange & Refresh ---------- */

oauthRoutes.post('/api/oauth/token', async (c) => {
  const form = await readFormOrJson(c.req.raw);
  if (!form.get('client_id')) {
    const basic = basicClientId(c.req.header('authorization') || null);
    if (basic) form.set('client_id', basic);
  }
  const grantType = form.get('grant_type');
  const headers = { 'Cache-Control': 'no-store', Pragma: 'no-cache' };

  if (grantType === 'authorization_code') {
    const code = form.get('code') || '';
    const entry = await takeEphemeral<{
      token: string;
      refresh: string | null;
      scope: string;
      expiresIn: number | null;
      clientId: string;
      redirect: string;
      challenge: string;
    }>(c.env, `oac:${code}`, 'oauth_code');
    if (!entry) {
      return c.json({ error: 'invalid_grant', error_description: 'the code is unknown, used or expired' }, 400, headers);
    }
    const p = entry.payload;
    const reqClientId = form.get('client_id');
    if (reqClientId && reqClientId !== p.clientId) {
      return c.json({ error: 'invalid_grant', error_description: 'code issued to another client' }, 400, headers);
    }
    const reqRedirect = form.get('redirect_uri');
    if (reqRedirect && !sameRedirect(p.redirect, reqRedirect)) {
      return c.json({ error: 'invalid_grant', error_description: 'redirect_uri does not match' }, 400, headers);
    }
    const verifier = form.get('code_verifier') || '';
    const computedChallenge = await sha256Base64Url(verifier);
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) || !timingSafeEqualStr(computedChallenge, p.challenge)) {
      return c.json({ error: 'invalid_grant', error_description: 'code_verifier does not match challenge' }, 400, headers);
    }
    c.executionCtx.waitUntil(
      c.env.DB.prepare('UPDATE oauth_clients SET last_used_at = ? WHERE client_id = ?')
        .bind(Date.now(), p.clientId)
        .run()
    );
    return c.json(
      {
        access_token: p.token,
        token_type: 'Bearer',
        scope: p.scope,
        ...(p.expiresIn ? { expires_in: p.expiresIn } : {}),
        ...(p.refresh ? { refresh_token: p.refresh } : {}),
      },
      200,
      headers
    );
  }

  if (grantType === 'refresh_token') {
    const val = form.get('refresh_token') || '';
    if (!val.startsWith(REFRESH_PREFIX) || val.length !== REFRESH_PREFIX.length + 43) {
      return c.json({ error: 'invalid_grant', error_description: 'unknown refresh token' }, 400, headers);
    }
    const rhash = await hashRefreshToken(val);
    const row = await c.env.DB.prepare(
      'SELECT * FROM api_tokens WHERE refresh_sha256 = ? OR prev_refresh_sha256 = ?'
    )
      .bind(rhash, rhash)
      .first<ApiTokenRow>();
    if (!row || !row.connector_json) {
      return c.json({ error: 'invalid_grant', error_description: 'refresh token unknown or revoked' }, 400, headers);
    }
    const connector = JSON.parse(row.connector_json) as { client?: string };
    const reqClientId = form.get('client_id');
    if (reqClientId && connector.client && reqClientId !== connector.client) {
      return c.json({ error: 'invalid_grant', error_description: 'refresh token belongs to another client' }, 400, headers);
    }
    const now = Date.now();
    const user = await getUserById(c.env, row.uid);
    if ((row.expires_at && row.expires_at <= now) || !user || user.disabled === 1 || user.session_version !== row.session_version) {
      return c.json({ error: 'invalid_grant', error_description: 'connection ended; reconnect assistant' }, 400, headers);
    }

    const isStale = row.prev_refresh_sha256 === rhash && row.refresh_sha256 !== rhash;
    if (isStale && now - (row.rotated_at || 0) > REFRESH_GRACE_MS) {
      await c.env.DB.prepare('DELETE FROM api_tokens WHERE id = ?').bind(row.id).run();
      return c.json(
        { error: 'invalid_grant', error_description: 'refresh token reuse detected; connection revoked' },
        400,
        headers
      );
    }

    const nextAccess = TOKEN_PREFIX + randomBase64Url(32);
    const nextRefresh = REFRESH_PREFIX + randomBase64Url(32);
    const nextAccessHash = await hashApiToken(nextAccess);
    const nextRefreshHash = await hashRefreshToken(nextRefresh);
    const nextAccessExp = Math.min(now + ACCESS_TTL_MS, row.expires_at ?? Infinity);

    const rotated = await c.env.DB.prepare(
      `UPDATE api_tokens
       SET token_sha256 = ?, hint = ?, refresh_sha256 = ?, prev_refresh_sha256 = ?, rotated_at = ?, access_expires_at = ?, last_used_at = ?
       WHERE id = ? AND refresh_sha256 = ?`
    )
      .bind(
        nextAccessHash,
        nextAccess.slice(TOKEN_PREFIX.length, TOKEN_PREFIX.length + 6),
        nextRefreshHash,
        isStale ? row.prev_refresh_sha256 : row.refresh_sha256,
        now,
        nextAccessExp,
        now,
        row.id,
        row.refresh_sha256
      )
      .run();
    // Another refresh of this connection rotated it in between: this answer would hand out a
    // pair that no longer exists.
    if (!rotated.meta.changes) {
      return c.json({ error: 'invalid_grant', error_description: 'the refresh token is unknown, used or revoked' }, 400, headers);
    }

    return c.json(
      {
        access_token: nextAccess,
        token_type: 'Bearer',
        scope: scopeString(JSON.parse(row.scopes_json) as TokenScopes),
        expires_in: Math.max(60, Math.round((nextAccessExp - now) / 1000)),
        refresh_token: nextRefresh,
      },
      200,
      headers
    );
  }

  return c.json(
    { error: 'unsupported_grant_type', error_description: 'only authorization_code and refresh_token' },
    400,
    headers
  );
});

oauthRoutes.post('/api/oauth/revoke', async (c) => {
  const form = await readFormOrJson(c.req.raw);
  const token = form.get('token') || '';
  if (token.startsWith(REFRESH_PREFIX)) {
    const rhash = await hashRefreshToken(token);
    await c.env.DB.prepare(
      'DELETE FROM api_tokens WHERE connector_json IS NOT NULL AND (refresh_sha256 = ? OR prev_refresh_sha256 = ?)'
    )
      .bind(rhash, rhash)
      .run();
  } else if (token.startsWith(TOKEN_PREFIX)) {
    const thash = await hashApiToken(token);
    // Only a connector's own token (api/oauth.js revocable): a token made in Settings is ended
    // there, never by whoever holds it.
    await c.env.DB.prepare('DELETE FROM api_tokens WHERE connector_json IS NOT NULL AND token_sha256 = ?').bind(thash).run();
  }
  return c.body(null, 200, { 'Cache-Control': 'no-store' });
});

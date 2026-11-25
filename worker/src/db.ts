import { Env, adminUidSet, flagOn, resolveOrigin, resolveSessionDays } from './env';
import { signSessionToken, verifySessionToken } from './crypto';

export interface UserRow {
  uid: string;
  username: string;
  email: string | null;
  session_version: number;
  is_admin: number;
  is_owner: number;
  disabled: number;
  invited_by: string | null;
  last_pull: number | null;
  created_at: string;
}

export interface PasskeyRow {
  credential_id: string;
  uid: string;
  public_key: string;
  counter: number;
  device_type: string | null;
  backed_up: number;
  transports_json: string | null;
  label: string | null;
  created_at: string;
  last_used_at: string | null;
}

export interface SessionInfo {
  user: UserRow;
  exp: number;
  kind: string | null;
  bearer: boolean;
}

export const APP_ORIGINS = new Set(['https://localhost', 'capacitor://localhost', 'http://localhost']);

export function isAdmin(env: Env, user: UserRow | null): boolean {
  if (!user) return false;
  return user.is_admin === 1 || adminUidSet(env).has(user.uid);
}

export function isOwner(env: Env, user: UserRow | null): boolean {
  if (!user) return false;
  return isAdmin(env, user) && user.is_owner === 1;
}

export function publicUser(env: Env, user: UserRow) {
  return {
    id: user.uid,
    name: user.username,
    admin: isAdmin(env, user),
    ...(isOwner(env, user) ? { owner: true } : {}),
  };
}

export function textField(v: unknown): string {
  return typeof v === 'string' ? v : typeof v === 'number' ? String(v) : '';
}

export function isHttpsOrigin(origin: string): boolean {
  return /^https:/i.test(origin);
}

export function cookieName(origin: string): string {
  return isHttpsOrigin(origin) ? '__Host-gymsid' : 'gymsid';
}

function cookieValues(req: Request, name: string): string[] {
  const out: string[] = [];
  const header = req.headers.get('cookie') || '';
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) out.push(part.slice(eq + 1).trim());
  }
  return out;
}

export function extractCookieToken(req: Request, origin: string): string | null {
  const primary = cookieName(origin);
  const names = primary === 'gymsid' ? ['gymsid'] : [primary, 'gymsid'];
  for (const name of names) {
    const vals = cookieValues(req, name);
    if (!vals.length) continue;
    if (vals.some((v) => v !== vals[0])) return null;
    return vals[0];
  }
  return null;
}

export async function makeSessionCookieHeaders(
  env: Env,
  req: Request,
  user: UserRow
): Promise<string[]> {
  const origin = resolveOrigin(env, req);
  const secure = isHttpsOrigin(origin) ? ' Secure;' : '';
  const sameSite = /^strict$/i.test(env.SESSION_SAMESITE || '') ? 'Strict' : 'Lax';
  const days = resolveSessionDays(env);
  const exp = Date.now() + days * 86_400_000;
  const tok = await signSessionToken(env.SESSION_SECRET, user.uid, exp, user.session_version, 'c');
  const primary = cookieName(origin);
  const fresh = `${primary}=${tok}; Path=/; Max-Age=${days * 86_400}; HttpOnly;${secure} SameSite=${sameSite}`;
  if (primary === 'gymsid') return [fresh];
  const expireLegacy = `gymsid=; Path=/; Max-Age=0; HttpOnly;${secure} SameSite=${sameSite}`;
  return [fresh, expireLegacy];
}

export function clearSessionCookieHeaders(env: Env, req: Request): string[] {
  const origin = resolveOrigin(env, req);
  const secure = isHttpsOrigin(origin) ? ' Secure;' : '';
  const sameSite = /^strict$/i.test(env.SESSION_SAMESITE || '') ? 'Strict' : 'Lax';
  const expire = (name: string) => `${name}=; Path=/; Max-Age=0; HttpOnly;${secure} SameSite=${sameSite}`;
  const primary = cookieName(origin);
  return primary === 'gymsid' ? [expire('gymsid')] : [expire(primary), expire('gymsid')];
}

export async function getUserById(env: Env, uid: string): Promise<UserRow | null> {
  const row = await env.DB.prepare('SELECT * FROM users WHERE uid = ?').bind(uid).first<UserRow>();
  return row || null;
}

export async function getSessionFromRequest(env: Env, req: Request): Promise<SessionInfo | null> {
  if (!env.SESSION_SECRET) return null;
  const origin = resolveOrigin(env, req);
  const cookie = extractCookieToken(req, origin);
  const auth = req.headers.get('authorization') || '';
  const tok = cookie || (auth.startsWith('Bearer ') ? auth.slice(7).trim() : null);
  if (!tok) return null;
  const parsed = await verifySessionToken(env.SESSION_SECRET, tok);
  if (!parsed) return null;
  const user = await getUserById(env, parsed.uid);
  if (!user || user.disabled === 1) return null;
  if (parsed.sv !== user.session_version) return null;
  return { user, exp: parsed.exp, kind: parsed.kind, bearer: !cookie };
}

export async function makeBearerSessionToken(env: Env, user: UserRow): Promise<string> {
  const days = resolveSessionDays(env);
  const exp = Date.now() + days * 86_400_000;
  return signSessionToken(env.SESSION_SECRET, user.uid, exp, user.session_version, 'b');
}

export async function putEphemeral(
  env: Env,
  code: string,
  kind: string,
  payload: unknown,
  ttlMs: number,
  uid: string | null = null
): Promise<void> {
  const exp = Date.now() + ttlMs;
  await env.DB.prepare(
    `INSERT OR REPLACE INTO ephemeral_codes (code, kind, uid, payload_json, expires_at)
     VALUES (?, ?, ?, ?, ?)`
  )
    .bind(code, kind, uid, JSON.stringify(payload), exp)
    .run();
}

export async function peekEphemeral<T = Record<string, unknown>>(
  env: Env,
  code: string,
  kind: string
): Promise<{ code: string; uid: string | null; payload: T; expires_at: number } | null> {
  const row = await env.DB.prepare(
    'SELECT code, kind, uid, payload_json, expires_at FROM ephemeral_codes WHERE code = ? AND kind = ?'
  )
    .bind(code, kind)
    .first<{ code: string; kind: string; uid: string | null; payload_json: string; expires_at: number }>();
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    await env.DB.prepare('DELETE FROM ephemeral_codes WHERE code = ?').bind(code).run();
    return null;
  }
  return {
    code: row.code,
    uid: row.uid,
    payload: JSON.parse(row.payload_json) as T,
    expires_at: row.expires_at,
  };
}

export async function takeEphemeral<T = Record<string, unknown>>(
  env: Env,
  code: string,
  kind: string
): Promise<{ code: string; uid: string | null; payload: T; expires_at: number } | null> {
  const row = await peekEphemeral<T>(env, code, kind);
  if (!row) return null;
  await env.DB.prepare('DELETE FROM ephemeral_codes WHERE code = ?').bind(code).run();
  return row;
}

export async function pruneExpiredEphemeral(env: Env): Promise<void> {
  await env.DB.prepare('DELETE FROM ephemeral_codes WHERE expires_at < ?').bind(Date.now()).run();
}

export function clientIpForAudit(env: Env, req: Request): string | null {
  const mode = (env.AUDIT_IP || 'off').toLowerCase();
  if (mode === 'off' || mode === '0' || mode === 'false') return null;
  const raw = (req.headers.get('cf-connecting-ip') || '').trim().slice(0, 45);
  if (!raw || !/^[0-9a-fA-F:.]{3,45}$/.test(raw)) return null;
  if (mode === 'full') return raw;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(raw)) return raw.replace(/\.\d{1,3}$/, '.0/24');
  const g = raw.split(':').filter(Boolean).slice(0, 3).join(':');
  return g ? `${g}::/48` : null;
}

export async function writeAudit(
  env: Env,
  req: Request,
  action: string,
  opts: {
    user?: UserRow | null;
    uid?: string | null;
    name?: string | null;
    target?: UserRow | null;
    ok?: boolean;
    msg?: string | null;
  } = {}
): Promise<void> {
  if (!flagOn(env.AUDIT_LOG, true)) return;
  try {
    await env.DB.prepare(
      `INSERT INTO audit_log (ts, uid, name, tgt, tname, action, ok, msg, ip)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        Date.now(),
        opts.user?.uid ?? opts.uid ?? null,
        (opts.user?.username ?? opts.name ?? null)?.slice(0, 40) ?? null,
        opts.target?.uid ?? null,
        opts.target?.username?.slice(0, 40) ?? null,
        action,
        opts.ok === false ? 0 : 1,
        opts.msg ? String(opts.msg).slice(0, 120) : null,
        clientIpForAudit(env, req)
      )
      .run();
  } catch (e) {
    console.error('audit write failed', e);
  }
}

export function corsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get('origin');
  const headers: Record<string, string> = {};
  if (origin) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Vary'] = 'Origin';
  }
  return headers;
}

const CSRF_EXEMPT = new Set([
  'POST /api/oauth/register',
  'POST /api/oauth/token',
  'POST /api/oauth/revoke',
  'POST /api/pair/redeem',
  'PUT /api/token/data',
]);

const SIGN_IN_ROUTES = new Set([
  'POST /api/register/options',
  'POST /api/register/verify',
  'POST /api/login/options',
  'POST /api/login/verify',
  'POST /api/device-link/options',
  'POST /api/device-link/verify',
]);

export async function checkCsrf(
  env: Env,
  req: Request,
  routeKey: string
): Promise<{ ok: true } | { ok: false; status: 401 | 403; body: Record<string, unknown> }> {
  const method = req.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return { ok: true };
  if (CSRF_EXEMPT.has(routeKey)) return { ok: true };

  const origin = resolveOrigin(env, req);
  const auth = req.headers.get('authorization') || '';
  const hasCookie = !!extractCookieToken(req, origin);

  if (!SIGN_IN_ROUTES.has(routeKey) && auth.startsWith('Bearer ') && !hasCookie) {
    const sess = await getSessionFromRequest(env, req);
    if (sess) return { ok: true };
    return { ok: false, status: 401, body: { error: 'not signed in' } };
  }

  const site = req.headers.get('sec-fetch-site');
  if (site) {
    if (site === 'same-origin' || site === 'none') return { ok: true };
    return {
      ok: false,
      status: 403,
      body: { error: 'cross-origin request refused', code: 'origin-mismatch', expected: origin },
    };
  }

  const reqOrigin = req.headers.get('origin');
  if (!reqOrigin) return { ok: true };
  if (reqOrigin.replace(/\/+$/, '') === origin.replace(/\/+$/, '')) return { ok: true };

  return {
    ok: false,
    status: 403,
    body: { error: 'cross-origin request refused', code: 'origin-mismatch', expected: origin },
  };
}

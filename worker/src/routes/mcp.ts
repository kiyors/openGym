// POST /mcp: the remote MCP endpoint, answering like the self-hosted `mcp` container behind nginx
// (mcp/src/http.js, web/nginx.conf.template). The checks in front (origin, method, token) are
// that file's; the tools themselves are upstream's own code, run by ../mcp-bridge.ts.
import { Hono } from 'hono';
import { Env, flagOn, resolveOrigin } from '../env';
import { authenticateApiToken } from './tokens';
import type { SelfFetch } from '../mcp-bridge';

export const mcpRoutes = new Hono<{ Bindings: Env }>();

const MCP_VERSION = '0.2.0'; // mcp/src/server.js VERSION
const MAX_BODY = 1024 * 1024; // mcp/src/http.js MAX_BODY
const DEFAULT_SCOPE = 'workouts:view plans:apply bodyweight:view offline_access';
const TOKEN_RE = /^ogt_[A-Za-z0-9_-]{43}$/;

// The Worker's own router, registered by index.ts: the MCP tools' API requests go straight to it
// instead of out to the Worker's public hostname and back.
// eslint-disable-next-line
type AppFetch = (req: Request, env: Env, ctx: any) => Response | Promise<Response>;
let appFetch: AppFetch | null = null;
export function registerAppFetch(fn: AppFetch) {
  appFetch = fn;
}

const rpcError = (status: number, message: string, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message }, id: null }), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers },
  });

function unauthorized(origin: string, why: string) {
  return rpcError(401, why, {
    'WWW-Authenticate':
      'Bearer realm="openGym", error="invalid_token", error_description="sign in with openGym, or make a token in Settings, API tokens"' +
      `, resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp", scope="${DEFAULT_SCOPE}"`,
  });
}

mcpRoutes.get('/mcp/health', (c) => c.json({ ok: true, version: MCP_VERSION }));

mcpRoutes.all('/mcp', async (c) => {
  // MCP off: what nginx answers when the mcp container is not running (@mcp_off).
  if (!flagOn(c.env.MCP, true) || !flagOn(c.env.API_TOKENS, true)) {
    return rpcError(503, 'MCP is not running on this openGym server (docs/MCP_REMOTE.md)');
  }
  const origin = resolveOrigin(c.env, c.req.raw);
  // DNS rebinding (the MCP spec's own rule): a browser page on another origin is turned away.
  // Clients that are not browsers send no Origin.
  const reqOrigin = c.req.header('origin');
  if (reqOrigin && reqOrigin.replace(/\/+$/, '') !== origin) return rpcError(403, 'origin not allowed');
  if (c.req.method !== 'POST') {
    return rpcError(405, 'POST only: this endpoint is stateless (no GET stream, no session to delete)', { Allow: 'POST' });
  }

  const authHeader = c.req.header('authorization') || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  if (!TOKEN_RE.test(token)) {
    return unauthorized(
      origin,
      token
        ? 'that is not an openGym API token (ogt_…); a paired session is not taken here'
        : 'an openGym API token is needed (Authorization: Bearer ogt_…)'
    );
  }
  const auth = await authenticateApiToken(c.env, c.executionCtx, token);
  if (!auth) return unauthorized(origin, 'openGym did not accept this token: revoked, expired, or the profile signed out everywhere');

  const len = Number(c.req.header('content-length') || 0);
  if (len > MAX_BODY) return rpcError(413, 'body too large');
  const body = await c.req.raw.arrayBuffer();
  if (body.byteLength > MAX_BODY) return rpcError(413, 'body too large');

  if (!appFetch) return rpcError(500, 'internal error');
  const app = appFetch;
  const env = c.env;
  const ctx = c.executionCtx;
  const selfFetch: SelfFetch = async (url, init) => app(new Request(url, init), env, ctx);

  // The transport reads the body itself; it gets a fresh copy of the request.
  const req = new Request(c.req.raw.url, { method: 'POST', headers: c.req.raw.headers, body });
  try {
    const { handleMcp } = await import('../mcp-bridge');
    const res = await handleMcp(req, { base: origin, token, selfFetch });
    const out = new Response(res.body, res);
    out.headers.set('Cache-Control', 'no-store');
    return out;
  } catch (e) {
    const err = e as { code?: string; message?: string };
    if (err.code === 'EAUTH') return unauthorized(origin, 'openGym did not accept this token: revoked, expired, or the profile signed out everywhere');
    if (err.code === 'ERATE') return rpcError(429, err.message || 'too many requests', { 'Retry-After': '60' });
    console.error('[opengym-mcp] request failed:', err.message || e);
    return rpcError(500, 'internal error');
  }
});

import { Hono } from 'hono';
import { Env, flagOn } from './env';
import { APP_ORIGINS, checkCsrf, corsHeaders } from './db';
import { metaRoutes } from './routes/meta';
import { authRoutes } from './routes/auth';
import { pairRoutes } from './routes/pair';
import { dataRoutes } from './routes/data';
import { tokenRoutes } from './routes/tokens';
import { oauthRoutes } from './routes/oauth';
import { mcpRoutes } from './routes/mcp';
import { adminRoutes } from './routes/admin';
import { coachRoutes } from './routes/coach';
import { webhookRoutes } from './routes/webhooks';

const app = new Hono<{ Bindings: Env }>();

// 1. CORS reflection for Capacitor iOS/Android mobile apps (never sets Allow-Credentials)
app.use('*', async (c, next) => {
  const reqOrigin = c.req.header('origin');
  if (c.req.method === 'OPTIONS') {
    const pna =
      (c.req.header('access-control-request-private-network') || '').toLowerCase() === 'true' &&
      !!reqOrigin &&
      APP_ORIGINS.has(reqOrigin);

    const headers: Record<string, string> = {
      ...corsHeaders(c.req.raw),
      'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
      'Access-Control-Allow-Headers':
        'Content-Type, Authorization, CF-Access-Client-Id, CF-Access-Client-Secret, X-OpenGym-Account, If-Match',
      'Access-Control-Max-Age': '86400',
      ...(pna ? { 'Access-Control-Allow-Private-Network': 'true' } : {}),
    };
    return c.body(null, 204, headers);
  }

  await next();

  const ch = corsHeaders(c.req.raw);
  for (const [k, v] of Object.entries(ch)) {
    c.res.headers.set(k, v);
  }
  if (c.req.path.startsWith('/api/') || c.req.path.startsWith('/mcp')) {
    if (!c.res.headers.has('Cache-Control')) {
      c.res.headers.set('Cache-Control', 'no-store');
    }
  }
});

// 2. CSRF protection on state-changing /api/* routes (exempts mobile pair/redeem, OAuth token/register/revoke, and token writes)
app.use('/api/*', async (c, next) => {
  const routeKey = `${c.req.method.toUpperCase()} ${c.req.path}`;
  const res = await checkCsrf(c.env, c.req.raw, routeKey);
  if (!res.ok) {
    return c.json(res.body, res.status);
  }
  await next();
});

// 3. Mount all openGym API, OAuth 2.1, and Remote MCP routes
app.route('/', metaRoutes);
app.route('/', authRoutes);
app.route('/', pairRoutes);
app.route('/', dataRoutes);
app.route('/', tokenRoutes);
app.route('/', oauthRoutes);
app.route('/', mcpRoutes);
app.route('/', adminRoutes);
app.route('/', coachRoutes);
app.route('/', webhookRoutes);

// 4. Explicit 404 for unknown /api/* routes
app.all('/api/*', (c) => c.json({ error: 'not found' }, 404));

// 5. Fallback to Workers Static Assets (React PWA + 180 px exercise media)
app.all('*', async (c) => {
  if (c.env.ASSETS) {
    return c.env.ASSETS.fetch(c.req.raw);
  }
  return c.json({ ok: true, service: 'opengym-worker', mcp: flagOn(c.env.MCP, true) });
});

app.onError((err, c) => {
  console.error('Worker unhandled error:', err);
  return c.json({ error: 'server error' }, 500);
});

export default app;

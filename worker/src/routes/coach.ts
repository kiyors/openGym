import { Hono } from 'hono';
import { Env } from '../env';
import { getSessionFromRequest, isAdmin } from '../db';
import { DATA_CATEGORIES } from '../../../api/coach/core/categories.js';

/**
 * The AI Coach is not offered on the Workers build: upstream's job runner needs the filesystem,
 * timers, undici and the Claude SDK. So every route here answers exactly like an upstream server
 * where the Coach is switched off (COACH_DISABLED): GET /api/config carries `coach: null` for a
 * signed-in caller, the user routes refuse with 503 `code: 'off'`, and the admin card shows its
 * "force-disabled" notice (`disabledByEnv`). See api/coach/routes.js.
 */
export const coachRoutes = new Hono<{ Bindings: Env }>();

const OFF = 'the Coach is not set up on this instance';
const UNAVAILABLE = 'the Coach is not available on this server';

const notSignedIn = () => Response.json({ error: 'not signed in' }, { status: 401 });
const off = () => Response.json({ error: OFF, code: 'off' }, { status: 503 });

/** Upstream's `guard`: signed in first, then "feature on" (never, here). */
async function guard(env: Env, req: Request): Promise<Response> {
  const s = await getSessionFromRequest(env, req);
  return s ? off() : notSignedIn();
}

/* ------------------------------ user ------------------------------ */

// Answers with the default (fixture) config, as upstream does for any signed-in caller.
coachRoutes.get('/api/coach/disclosure', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return notSignedIn();
  return c.json({
    provider: 'fixture',
    providerLabel: 'Fixture (testing)',
    host: null,
    categories: DATA_CATEGORIES,
    version: 1,
  });
});

coachRoutes.get('/api/coach/status', (c) => guard(c.env, c.req.raw));
for (const kind of ['plan', 'review', 'debrief', 'ask', 'adapt']) {
  coachRoutes.post(`/api/coach/${kind}`, (c) => guard(c.env, c.req.raw));
}
coachRoutes.get('/api/coach/cohort', (c) => guard(c.env, c.req.raw));
coachRoutes.post('/api/coach/cohort/share', (c) => guard(c.env, c.req.raw));
coachRoutes.post('/api/coach/pending/resolve', (c) => guard(c.env, c.req.raw));

// Nothing is ever held server-side, so forgetting is a no-op (upstream: 401, else ok).
coachRoutes.post('/api/coach/forget', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return notSignedIn();
  return c.json({ ok: true });
});

coachRoutes.get('/api/coach/account', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return notSignedIn();
  return c.json({
    mode: 'instance',
    provider: 'fixture',
    providerLabel: 'Fixture (testing)',
    account: null,
    connected: true,
    reason: null,
    message: null,
  });
});

/* ------------------------------ admin ------------------------------ */

async function requireAdmin(env: Env, req: Request): Promise<Response | null> {
  const s = await getSessionFromRequest(env, req);
  if (!s) return notSignedIn();
  if (!isAdmin(env, s.user)) return Response.json({ error: 'forbidden' }, { status: 403 });
  return null;
}

// `disabledByEnv` makes the admin card render its "force-disabled" notice and nothing else.
coachRoutes.get('/api/admin/coach', async (c) => {
  const denied = await requireAdmin(c.env, c.req.raw);
  if (denied) return denied;
  return c.json({ disabledByEnv: true, enabled: false });
});

// Anything that would configure or connect the Coach answers an honest error.
for (const route of ['config', 'test', 'connect', 'disconnect']) {
  coachRoutes.post(`/api/admin/coach/${route}`, async (c) => {
    const denied = await requireAdmin(c.env, c.req.raw);
    if (denied) return denied;
    return c.json({ error: UNAVAILABLE }, 409);
  });
}

coachRoutes.post('/api/admin/coach/models', async (c) => {
  const denied = await requireAdmin(c.env, c.req.raw);
  if (denied) return denied;
  return c.json({ ok: false, error: 'this provider does not list models', models: [] });
});

coachRoutes.post('/api/admin/coach/discover', async (c) => {
  const denied = await requireAdmin(c.env, c.req.raw);
  if (denied) return denied;
  return c.json({ ok: true, found: [] });
});

// Upstream answers 404 for these unless COACH_CHATGPT_PLAN is on.
for (const route of ['start', 'finish']) {
  coachRoutes.post(`/api/admin/coach/chatgpt/${route}`, async (c) => {
    const denied = await requireAdmin(c.env, c.req.raw);
    if (denied) return denied;
    return c.json({ error: 'not found' }, 404);
  });
}

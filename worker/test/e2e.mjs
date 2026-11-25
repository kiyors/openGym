#!/usr/bin/env node
// End-to-end check of a running openGym Worker, driven the way the unmodified web app and phone
// apps drive it (frontend/src/lib/api.js): passkey sign-up and sign-in with a software
// authenticator, sync with revisions and 409s, phone pairing, scoped tokens and the remote MCP.
//
//   node worker/test/e2e.mjs                      against `wrangler dev` on http://localhost:8787
//   BASE=https://opengym.example.workers.dev node worker/test/e2e.mjs
//
// It creates a profile on the target. Against a fresh local D1 that profile is the owner.
import assert from 'node:assert/strict';
import { SoftAuthenticator } from './softauthn.mjs';

const BASE = (process.env.BASE || 'http://localhost:8787').replace(/\/+$/, '');
const ORIGIN = new URL(BASE).origin;
const APP_ORIGIN = 'https://localhost'; // the Android app's WebView

let cookie = '';
const jar = new Map();
let passed = 0;

async function call(path, { method = 'GET', body, headers = {}, auth = 'cookie', origin = ORIGIN } = {}) {
  const h = { ...headers };
  if (body !== undefined) h['Content-Type'] = 'application/json';
  if (origin) h.Origin = origin;
  if (auth === 'cookie' && cookie) h.Cookie = cookie;
  if (auth && auth !== 'cookie') h.Authorization = 'Bearer ' + auth;
  const r = await fetch(BASE + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' });
  // A cookie jar by name: an answer may set one cookie and clear another.
  if (auth === 'cookie') {
    for (const c of r.headers.getSetCookie?.() || []) {
      const pair = c.split(';')[0];
      const name = pair.split('=')[0];
      if (/=$/.test(pair) || /max-age=0/i.test(c)) jar.delete(name);
      else jar.set(name, pair);
    }
    cookie = [...jar.values()].join('; ');
  }
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: r.status, json, text, headers: r.headers };
}

async function step(name, fn) {
  try {
    await fn();
    passed++;
    console.log('  ok  ' + name);
  } catch (e) {
    console.error('  FAIL ' + name);
    console.error(e);
    process.exit(1);
  }
}

const auth = new SoftAuthenticator(ORIGIN);
const name = 'e2e-' + Math.random().toString(36).slice(2, 8);
let pairToken = '';
let apiToken = '';

console.log('openGym worker e2e against ' + BASE);

await step('GET /api/health', async () => {
  const r = await call('/api/health');
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.ok, true);
});

await step('GET /api/config signed out', async () => {
  const r = await call('/api/config');
  assert.equal(r.status, 200);
  assert.equal(r.json.signed_in, false);
  assert.equal(typeof r.json.invite_only, 'boolean');
  assert.ok(!('password_login' in r.json), 'password login must stay off');
});

await step('static app is served', async () => {
  const r = await call('/', { origin: null });
  assert.equal(r.status, 200);
  assert.match(r.text, /<div id="root"|<!doctype html/i);
  const h = await call('/manifest.json', { origin: null });
  assert.equal(h.status, 200);
});

await step('unknown /api route is a JSON 404', async () => {
  const r = await call('/api/definitely-not-a-route');
  assert.equal(r.status, 404);
  assert.ok(r.json && r.json.error);
});

await step('cross-site write is refused (CSRF)', async () => {
  const r = await call('/api/register/options', { method: 'POST', body: { name: 'x' }, origin: 'https://evil.example' });
  assert.equal(r.status, 403, r.text);
});

await step('passkey registration', async () => {
  const o = await call('/api/register/options', { method: 'POST', body: { name, code: process.env.INVITE || '' } });
  assert.equal(o.status, 200, o.text);
  assert.ok(o.json.cid && o.json.options?.challenge);
  const credential = await auth.create(o.json.options);
  const v = await call('/api/register/verify', { method: 'POST', body: { cid: o.json.cid, credential } });
  assert.equal(v.status, 200, v.text);
  assert.equal(v.json.user.name, name);
  assert.ok(cookie, 'a session cookie is set');
});

await step('GET /api/me and /api/config signed in', async () => {
  const me = await call('/api/me');
  assert.equal(me.status, 200, me.text);
  assert.equal(me.json.user.name, name);
  const cfg = await call('/api/config');
  assert.equal(cfg.json.signed_in, true);
  assert.ok('coach' in cfg.json, 'a session always gets the coach key');
});

await step('sync: empty profile, first write, conflict, stamped write', async () => {
  const g = await call('/api/data');
  assert.equal(g.status, 200, g.text);
  assert.equal(g.json.rev, 0);
  assert.equal(g.json.state, null);

  const bad = await call('/api/data', { method: 'PUT', body: { state: {} } });
  assert.equal(bad.status, 400);

  const state = { _ts: Date.now(), workouts: [], routines: [], bw: [], settings: { unit: 'kg' }, active: { x: 1 } };
  const p1 = await call('/api/data', { method: 'PUT', body: { state, stamped: true } });
  assert.equal(p1.status, 200, p1.text);
  assert.equal(p1.json.ok, true);
  assert.equal(p1.json.rev, 1);
  assert.ok(p1.json.wid);

  const stale = await call('/api/data', { method: 'PUT', body: { state, baseRev: 0, stamped: true } });
  assert.equal(stale.status, 409, stale.text);
  assert.equal(stale.json.error, 'conflict');
  assert.equal(stale.json.rev, 1);
  assert.ok(stale.json.state && !('active' in stale.json.state), 'in-progress workout stays device-local');

  const w = { id: 'w1', d: '2026-11-20', name: 'Push', start: Date.parse('2026-11-20T18:00:00Z'), end: Date.parse('2026-11-20T19:00:00Z'), entries: [], _ts: Date.now() };
  const p2 = await call('/api/data', { method: 'PUT', body: { state: { ...state, workouts: [w] }, baseRev: 1, baseWid: p1.json.wid, stamped: true } });
  assert.equal(p2.status, 200, p2.text);
  assert.equal(p2.json.rev, 2);

  const rev = await call('/api/data/rev');
  assert.equal(rev.json.rev, 2);
  assert.equal(rev.json.wid, p2.json.wid);

  const back = await call('/api/data');
  assert.equal(back.json.state.workouts.length, 1);
  assert.equal(back.json.state._rev, 2);
});

await step('nudge-check', async () => {
  const r = await call('/api/nudge-check?date=2026-11-20');
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.done, true);
  const bad = await call('/api/nudge-check?date=nope');
  assert.equal(bad.status, 400);
});

await step('phone pairing (create with passkey proof, redeem from the app origin)', async () => {
  const lo = await call('/api/login/options', { method: 'POST', body: {} });
  assert.equal(lo.status, 200, lo.text);
  const credential = await auth.get(lo.json.options);
  const c = await call('/api/pair/create', { method: 'POST', body: { cid: lo.json.cid, credential } });
  assert.equal(c.status, 200, c.text);
  assert.match(c.json.code, /^[A-Z0-9]{8}$/);

  const pre = await fetch(BASE + '/api/pair/redeem', {
    method: 'OPTIONS',
    headers: { Origin: APP_ORIGIN, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' },
  });
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get('access-control-allow-origin'), APP_ORIGIN);
  assert.equal(pre.headers.get('access-control-allow-credentials'), null);

  const r = await call('/api/pair/redeem', { method: 'POST', body: { code: c.json.code }, auth: null, origin: APP_ORIGIN });
  assert.equal(r.status, 200, r.text);
  assert.ok(r.json.token && r.json.user);
  pairToken = r.json.token;

  const again = await call('/api/pair/redeem', { method: 'POST', body: { code: c.json.code }, auth: null, origin: APP_ORIGIN });
  assert.equal(again.status, 400, 'a code works once');

  const me = await call('/api/me', { auth: pairToken, origin: APP_ORIGIN });
  assert.equal(me.status, 200, me.text);
  assert.equal(me.json.user.name, name);
  const d = await call('/api/data', { auth: pairToken, origin: APP_ORIGIN });
  assert.equal(d.json.rev, 2);
});

await step('scoped API token', async () => {
  const r = await call('/api/tokens', { method: 'POST', body: { name: 'e2e', scopes: { workouts: 'apply', plans: 'apply', bodyweight: 'view' }, days: 7 } });
  assert.equal(r.status, 200, r.text);
  assert.match(r.json.token, /^ogt_[A-Za-z0-9_-]{43}$/);
  assert.ok(Array.isArray(r.json.tokens));
  apiToken = r.json.token;

  const sess = await call('/api/me', { auth: apiToken, origin: null });
  assert.equal(sess.status, 401, 'a scoped token is never a session');
  const d = await call('/api/token/data', { auth: apiToken, origin: null });
  assert.equal(d.status, 200, d.text);
  assert.equal(d.json.rev, 2);
  assert.ok(Array.isArray(d.json.state.workouts));
});

await step('remote MCP: 401 points at OAuth discovery', async () => {
  const r = await fetch(BASE + '/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }) });
  assert.equal(r.status, 401);
  assert.match(r.headers.get('www-authenticate') || '', /resource_metadata=/);
  const prm = await call('/.well-known/oauth-protected-resource/mcp', { origin: null });
  assert.equal(prm.status, 200, prm.text);
  assert.ok(prm.json.authorization_servers?.length);
  const as = await call('/.well-known/oauth-authorization-server', { origin: null });
  assert.equal(as.status, 200, as.text);
  assert.ok(as.json.token_endpoint && as.json.authorization_endpoint);
  assert.ok(as.json.code_challenge_methods_supported.includes('S256'));
});

let tools = [];
await step('remote MCP: initialize, tools/list, tools/call', async () => {
  const rpc = async (id, method, params) => {
    const r = await fetch(BASE + '/mcp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', Authorization: 'Bearer ' + apiToken },
      body: JSON.stringify({ jsonrpc: '2.0', ...(id != null ? { id } : {}), method, params }),
    });
    const text = await r.text();
    const json = text ? JSON.parse(text.replace(/^event: message\ndata: /, '')) : null;
    return { status: r.status, json, text };
  };
  const init = await rpc(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'e2e', version: '1' } });
  assert.equal(init.status, 200, init.text);
  assert.ok(init.json.result.serverInfo);
  const n = await rpc(null, 'notifications/initialized', {});
  assert.ok(n.status === 202 || n.status === 200, 'notification accepted: ' + n.status);
  const list = await rpc(2, 'tools/list', {});
  assert.equal(list.status, 200, list.text);
  tools = list.json.result.tools.map((t) => t.name);
  assert.ok(tools.length > 0);
  const recent = tools.find((t) => /recent|workouts/.test(t)) || tools[0];
  const call1 = await rpc(3, 'tools/call', { name: recent, arguments: {} });
  assert.equal(call1.status, 200, call1.text);
  assert.ok(call1.json.result && !call1.json.result.isError, call1.text);
});

await step('remote MCP write: log_workout lands in the app\'s own shape', async () => {
  const body = { jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'log_workout', arguments: {
    date: '2026-11-21', name: 'Arms', exercises: [{ exercise: 'barbell curl', sets: [{ reps: 10, weight: 30 }, { reps: 8, weight: 32.5 }] }],
  } } };
  const r = await fetch(BASE + '/mcp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', Authorization: 'Bearer ' + apiToken },
    body: JSON.stringify(body),
  });
  const json = await r.json();
  assert.equal(r.status, 200);
  assert.ok(!json.result.isError, json.result.content?.[0]?.text);
  const d = await call('/api/data');
  const w = d.json.state.workouts.find((x) => x.d === '2026-11-21');
  assert.ok(w, 'the logged session is in the profile');
  assert.ok(Array.isArray(w.entries) && w.entries.length === 1, 'sessions keep exercises in `entries`');
  assert.equal(w.entries[0].sets.length, 2);
  assert.ok(d.json.rev >= 3, 'the write moved the revision');
});

await step('remote MCP sees a change made in the app right after (no stale cached profile)', async () => {
  const listDates = async () => {
    const r = await fetch(BASE + '/mcp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', Authorization: 'Bearer ' + apiToken },
      body: JSON.stringify({ jsonrpc: '2.0', id: 11, method: 'tools/call', params: { name: 'list_workouts', arguments: {} } }),
    });
    return (await r.json()).result.content[0].text;
  };
  assert.ok(!(await listDates()).includes('2026-11-23'));
  const d = await call('/api/data');
  const state = d.json.state;
  // A real app record: the session log_workout saved above, as a new one on another day.
  const model = state.workouts.find((w) => w.d === '2026-11-21');
  const day = Date.parse('2026-11-23T18:00:00Z') - Date.parse(model.d + 'T18:00:00Z');
  state.workouts.push({ ...structuredClone(model), id: 'w-app-' + Date.now(), d: '2026-11-23', start: model.start + day, end: model.end + day, _ts: Date.now() });
  const p = await call('/api/data', { method: 'PUT', body: { state, baseRev: d.json.rev, baseWid: d.json.state._wid, stamped: true } });
  assert.equal(p.status, 200, p.text);
  const after = await listDates();
  assert.ok(after.includes('2026-11-23'), 'the MCP answer includes the workout the app just saved: ' + after.slice(0, 600));
});

await step('webhooks: connect reveals the secret once, list and log shapes', async () => {
  const cfg = await call('/api/config');
  assert.deepEqual(cfg.json.integrations, { providers: ['webhook'] });
  const r = await call('/api/integrations/connect', { method: 'POST', body: { provider: 'webhook', url: 'https://example.com/hooks/s3cr3t-0123456789abcdef', label: 'e2e', events: ['workout.finished'] } });
  assert.equal(r.status, 200, r.text);
  assert.match(r.json.reveal.secret, /^ogwh_/);
  assert.ok(r.json.connection.id);
  assert.ok(!JSON.stringify(r.json.connection).includes('s3cr3t-0123456789'), 'the full address never comes back');
  const bad = await call('/api/integrations/connect', { method: 'POST', body: { provider: 'webhook', url: 'https://127.0.0.1/x', events: ['workout.finished'] } });
  assert.ok(bad.status >= 400, 'a private address is refused');
  const list = await call('/api/integrations');
  assert.equal(list.status, 200, list.text);
  const log = await call('/api/integrations/log?id=' + encodeURIComponent(r.json.connection.id));
  assert.equal(log.status, 200, log.text);
  assert.ok(Array.isArray(log.json.log));
  const off = await call('/api/integrations/disconnect', { method: 'POST', body: { id: r.json.connection.id } });
  assert.equal(off.status, 200, off.text);
});

await step('calendar feed', async () => {
  const on = await call('/api/calendar', { method: 'POST', body: { done: true } });
  assert.equal(on.status, 200, on.text);
  const g = await call('/api/calendar');
  assert.equal(g.status, 200, g.text);
  const url = JSON.stringify(g.json).match(/\/api\/calendar\/ogt_[A-Za-z0-9_-]{43}\.ics/)?.[0];
  assert.ok(url, 'the feed address is listed: ' + g.text);
  const ics = await fetch(BASE + url);
  assert.equal(ics.status, 200);
  assert.match(await ics.text(), /BEGIN:VCALENDAR/);
  const off = await call('/api/calendar/revoke', { method: 'POST', body: {} });
  assert.equal(off.status, 200, off.text);
  assert.equal((await fetch(BASE + url)).status >= 400, true, 'a revoked feed is gone');
});

await step('admin: the first profile owns the instance', async () => {
  const me = await call('/api/me');
  if (!me.json.user.admin) { console.log('       (not the first profile here, admin checks skipped)'); return; }
  const users = await call('/api/admin/users');
  assert.equal(users.status, 200, users.text);
  const inv = await call('/api/admin/invites/new', { method: 'POST', body: {} });
  assert.equal(inv.status, 200, inv.text);
  assert.ok(inv.json.invite.code);
  const coach = await call('/api/admin/coach');
  assert.equal(coach.status, 200, coach.text);
  const audit = await call('/api/admin/audit');
  assert.equal(audit.status, 200, audit.text);
});

await step('push answers in words, not "not found"', async () => {
  const r = await call('/api/push/public-key');
  assert.equal(r.status, 503);
  assert.match(r.json.error, /not available/);
});

await step('sign out, then passkey sign-in', async () => {
  const o = await call('/api/logout', { method: 'POST', body: {} });
  assert.equal(o.status, 200, o.text);
  jar.clear();
  cookie = '';
  const me = await call('/api/me');
  assert.equal(me.status, 401);
  const lo = await call('/api/login/options', { method: 'POST', body: {} });
  const credential = await auth.get(lo.json.options);
  const v = await call('/api/login/verify', { method: 'POST', body: { cid: lo.json.cid, credential } });
  assert.equal(v.status, 200, v.text);
  assert.equal(v.json.user.name, name);
  const me2 = await call('/api/me');
  assert.equal(me2.status, 200);
});

await step('sign out everywhere ends the paired phone too', async () => {
  const r = await call('/api/logout/all', { method: 'POST', body: {} });
  assert.equal(r.status, 200, r.text);
  const me = await call('/api/me', { auth: pairToken, origin: APP_ORIGIN });
  assert.equal(me.status, 401);
});

console.log(`\n${passed} checks passed. MCP tools: ${tools.join(', ')}`);

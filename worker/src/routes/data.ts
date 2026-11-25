import { Hono } from 'hono';
import { Env } from '../env';
import { randomHex } from '../crypto';
import { getSessionFromRequest } from '../db';
import { dispatchWebhooks } from './webhooks';

export const dataRoutes = new Hono<{ Bindings: Env }>();

const WID_KEEP = 50;

export function sanitizeRecords(list: unknown): Record<string, unknown>[] {
  if (!Array.isArray(list)) return [];
  return list.filter((x): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x));
}

export function stripServerNotes(state: Record<string, unknown> | null): Record<string, unknown> | null {
  if (!state || typeof state !== 'object') return state;
  if (!('_unstamped' in state) && !('_prior' in state)) return state;
  const { _unstamped: _u, _prior: _p, ...rest } = state;
  return rest;
}

export async function readUserState(
  env: Env,
  uid: string
): Promise<{ rev: number; wid: string | null; state: Record<string, unknown> | null }> {
  const row = await env.DB.prepare('SELECT rev, wid, state_json FROM user_states WHERE uid = ?')
    .bind(uid)
    .first<{ rev: number; wid: string | null; state_json: string }>();
  if (!row) return { rev: 0, wid: null, state: null };
  return {
    rev: row.rev,
    wid: row.wid,
    state: JSON.parse(row.state_json) as Record<string, unknown>,
  };
}

/**
 * Atomic compare-and-swap state write in D1.
 * Keeps CPU well under Cloudflare Workers Free 10 ms limit.
 */
export async function commitUserState(
  env: Env,
  ctx: ExecutionContext,
  uid: string,
  cur: { rev: number; wid: string | null; state: Record<string, unknown> | null },
  nextState: Record<string, unknown>,
  opts: { baseRev?: number | null; baseWid?: string | null } = {}
): Promise<
  | { status: 200; body: { ok: true; ts: number | null; rev: number; wid: string } }
  | { status: 409; body: { error: 'conflict'; rev: number; state: Record<string, unknown> | null; wid?: string } }
> {
  const curRev = cur.rev || 0;
  if (
    (opts.baseRev != null && opts.baseRev !== curRev) ||
    (opts.baseRev != null && typeof opts.baseWid === 'string' && cur.wid && opts.baseWid !== cur.wid)
  ) {
    return {
      status: 409,
      body: {
        error: 'conflict',
        rev: curRev,
        state: stripServerNotes(cur.state),
        ...(cur.wid ? { wid: cur.wid } : {}),
      },
    };
  }

  const state = { ...nextState };
  delete state.active;

  // Preserve monotonic resetAt
  const storedReset = Number(cur.state?.resetAt) || 0;
  if (storedReset > (Number(state.resetAt) || 0)) {
    state.resetAt = cur.state?.resetAt;
    if (cur.state?.resetIds && typeof cur.state.resetIds === 'object') {
      state.resetIds = cur.state.resetIds;
    } else {
      delete state.resetIds;
    }
  }

  const nextRev = curRev + 1;
  const wid = randomHex(8);
  const prevWids = Array.isArray(cur.state?._wids) ? (cur.state?._wids as unknown[]) : [];
  const wids = [...prevWids, ...(cur.wid ? [cur.wid] : [])]
    .filter((x): x is string => typeof x === 'string')
    .slice(-WID_KEEP);

  state._rev = nextRev;
  state._wid = wid;
  state._wids = wids;
  if (!state._ts) state._ts = Date.now();

  const serialized = JSON.stringify(state);
  const now = Date.now();

  if (cur.state === null && curRev === 0) {
    const ins = await env.DB.prepare(
      `INSERT OR IGNORE INTO user_states (uid, rev, wid, state_json, updated_at)
       VALUES (?, ?, ?, ?, ?)`
    )
      .bind(uid, nextRev, wid, serialized, now)
      .run();

    if (!ins.meta.changes) {
      const fresh = await readUserState(env, uid);
      return {
        status: 409,
        body: {
          error: 'conflict',
          rev: fresh.rev,
          state: stripServerNotes(fresh.state),
          ...(fresh.wid ? { wid: fresh.wid } : {}),
        },
      };
    }
  } else {
    const upd = await env.DB.prepare(
      `UPDATE user_states
       SET rev = ?, wid = ?, state_json = ?, updated_at = ?
       WHERE uid = ? AND rev = ?`
    )
      .bind(nextRev, wid, serialized, now, uid, curRev)
      .run();

    if (!upd.meta.changes) {
      const fresh = await readUserState(env, uid);
      return {
        status: 409,
        body: {
          error: 'conflict',
          rev: fresh.rev,
          state: stripServerNotes(fresh.state),
          ...(fresh.wid ? { wid: fresh.wid } : {}),
        },
      };
    }
  }

  ctx.waitUntil(dispatchWebhooks(env, uid, cur.state, state));
  return { status: 200, body: { ok: true, ts: (state._ts as number) || null, rev: nextRev, wid } };
}

dataRoutes.get('/api/data', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const cur = await readUserState(c.env, s.user.uid);
  // Update last_pull asynchronously (throttled to 10 min)
  const now = Date.now();
  if (!s.user.last_pull || now - s.user.last_pull > 10 * 60_000) {
    c.executionCtx.waitUntil(
      c.env.DB.prepare('UPDATE users SET last_pull = ? WHERE uid = ?').bind(now, s.user.uid).run()
    );
  }
  return c.json({ state: stripServerNotes(cur.state), rev: cur.rev });
});

dataRoutes.get('/api/data/rev', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const row = await c.env.DB.prepare('SELECT rev, wid FROM user_states WHERE uid = ?')
    .bind(s.user.uid)
    .first<{ rev: number; wid: string | null }>();
  return c.json({ rev: row?.rev ?? 0, ...(row?.wid ? { wid: row.wid } : {}) });
});

dataRoutes.put('/api/data', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const body = (await c.req.json().catch(() => null)) as Record<string, unknown> | null;
  if (!body || !body.state || typeof body.state !== 'object' || Array.isArray(body.state)) {
    return c.json({ error: 'state required' }, 400);
  }
  const incoming = body.state as Record<string, unknown>;
  if (!Object.keys(incoming).some((k) => k !== '_rev' && k !== '_ts')) {
    return c.json({ error: 'state required' }, 400);
  }
  const validList = (v: unknown) => v == null || Array.isArray(v);
  if (!validList(incoming.workouts) || !validList(incoming.routines)) {
    return c.json({ error: 'invalid state' }, 400);
  }
  if (Array.isArray(incoming.workouts)) incoming.workouts = sanitizeRecords(incoming.workouts);
  if (Array.isArray(incoming.routines)) incoming.routines = sanitizeRecords(incoming.routines);

  const cur = await readUserState(c.env, s.user.uid);
  const res = await commitUserState(c.env, c.executionCtx, s.user.uid, cur, incoming, {
    baseRev: typeof body.baseRev === 'number' ? body.baseRev : null,
    baseWid: typeof body.baseWid === 'string' ? body.baseWid : null,
  });
  return c.json(res.body, res.status);
});

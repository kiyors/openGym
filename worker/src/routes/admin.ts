import { Hono } from 'hono';
import { Env, adminUidSet, flagOn } from '../env';
import { randomCode, randomHex, sha256Hex } from '../crypto';
import {
  UserRow,
  getSessionFromRequest,
  getUserById,
  isAdmin,
  isOwner,
  putEphemeral,
  textField,
  writeAudit,
} from '../db';
import { readUserState, sanitizeRecords } from './data';
import { auditRetention, pruneAudit } from '../lib/audit-retention';

export const adminRoutes = new Hono<{ Bindings: Env }>();

const RECOVERY_TTL_MS = 24 * 3_600_000;

async function requireAdmin(env: Env, req: Request): Promise<UserRow | Response> {
  const s = await getSessionFromRequest(env, req);
  if (!s) return Response.json({ error: 'not signed in' }, { status: 401 });
  if (!isAdmin(env, s.user)) {
    await writeAudit(env, req, 'admin.denied', { ok: false, user: s.user });
    return Response.json({ error: 'forbidden' }, { status: 403 });
  }
  return s.user;
}

/** Admins on the instance: the flagged users plus the ADMIN_UIDS that exist (upstream filters db.users by isAdmin). */
async function adminCount(env: Env): Promise<number> {
  const ids = [...adminUidSet(env)];
  const marks = ids.map(() => '?').join(',');
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS cnt FROM users WHERE is_admin = 1${ids.length ? ` OR uid IN (${marks})` : ''}`
  )
    .bind(...ids)
    .first<{ cnt: number }>();
  return row?.cnt ?? 0;
}

async function requireOwner(env: Env, req: Request): Promise<UserRow | Response> {
  const admin = await requireAdmin(env, req);
  if (admin instanceof Response) return admin;
  if (!isOwner(env, admin)) {
    await writeAudit(env, req, 'admin.denied', { ok: false, user: admin });
    return Response.json({ error: 'only the owner can do this' }, { status: 403 });
  }
  return admin;
}

adminRoutes.get('/api/admin/users', async (c) => {
  const admin = await requireAdmin(c.env, c.req.raw);
  if (admin instanceof Response) return admin;

  const view = flagOn(c.env.ADMIN_DATA_VIEW, false);
  // The workout count, last workout and _ts are read by SQLite (JSON1) so the Worker never parses
  // any user's state blob: that was the one request that would blow the 10 ms CPU budget.
  const res = await c.env.DB.prepare(
    `SELECT u.*, s.updated_at AS state_updated_at,
       json_extract(s.state_json, '$._ts') AS state_ts,
       CASE WHEN json_type(s.state_json, '$.workouts') = 'array' THEN
         (SELECT COUNT(*) FROM json_each(s.state_json, '$.workouts') j WHERE j.type = 'object')
       ELSE 0 END AS workouts_count,
       CASE WHEN json_type(s.state_json, '$.workouts') = 'array' THEN
         (SELECT json_extract(j.value, '$.d') FROM json_each(s.state_json, '$.workouts') j
           WHERE j.type = 'object' ORDER BY j.id DESC LIMIT 1)
       ELSE NULL END AS last_workout
     FROM users u
     LEFT JOIN user_states s ON s.uid = u.uid
     ORDER BY u.created_at ASC`
  ).all<
    UserRow & {
      state_updated_at: number | null;
      state_ts: unknown;
      workouts_count: number | null;
      last_workout: unknown;
    }
  >();

  const users = (res.results || []).map((u) => {
    const lastSync = Math.max(Number(u.state_ts) || 0, u.last_pull || 0, u.state_updated_at || 0) || null;
    return {
      id: u.uid,
      name: u.username,
      created: u.created_at,
      disabled: u.disabled === 1,
      admin: isAdmin(c.env, u),
      owner: isOwner(c.env, u),
      invitedBy: u.invited_by,
      workouts: u.workouts_count || 0,
      ...(view ? { lastWorkout: u.last_workout ?? null } : {}),
      lastSync,
      hasPush: false,
      live: null,
    };
  });

  if (view) await writeAudit(c.env, c.req.raw, 'admin.data-view', { user: admin, msg: 'user list' });
  return c.json({
    users,
    invite_only: flagOn(c.env.INVITE_ONLY, false),
    data_view: view,
    now: Date.now(),
  });
});

adminRoutes.get('/api/admin/user', async (c) => {
  const admin = await requireAdmin(c.env, c.req.raw);
  if (admin instanceof Response) return admin;

  const id = c.req.query('id') || '';
  const u = await getUserById(c.env, id);
  if (!u) return c.json({ error: 'no such user' }, 404);

  const cur = await readUserState(c.env, u.uid);
  const st = cur.state || {};
  const bytes = cur.state ? JSON.stringify(cur.state).length : 0;
  const view = flagOn(c.env.ADMIN_DATA_VIEW, false);

  // Until when an unused recovery code is good (the live device link made by an admin).
  const links = await c.env.DB.prepare(
    "SELECT payload_json, expires_at FROM ephemeral_codes WHERE kind = 'device_link' AND uid = ? AND expires_at > ?"
  )
    .bind(u.uid, Date.now())
    .all<{ payload_json: string; expires_at: number }>();
  let recoveryUntil: number | null = null;
  for (const l of links.results || []) {
    try {
      if ((JSON.parse(l.payload_json) as { kind?: string }).kind === 'recovery') recoveryUntil = l.expires_at;
    } catch {
      /* not ours */
    }
  }

  const base = {
    user: {
      id: u.uid,
      name: u.username,
      created: u.created_at,
      disabled: u.disabled === 1,
      admin: isAdmin(c.env, u),
      owner: isOwner(c.env, u),
      invitedBy: u.invited_by,
      recoveryUntil,
    },
    unit: (st.unit as string) || 'kg',
    lastSync: Math.max(Number(st._ts) || 0, u.last_pull || 0) || null,
    hasPush: false,
    bytes,
    counts: {
      workouts: sanitizeRecords(st.workouts).length,
      bodyweight: sanitizeRecords(st.bodyweight).length,
      measurements: sanitizeRecords(st.measurements).length,
      routines: sanitizeRecords(st.routines).length,
    },
    data_view: view,
  };

  if (!view) return c.json(base);

  await writeAudit(c.env, c.req.raw, 'admin.data-view', { user: admin, target: u });

  return c.json({
    ...base,
    routines: sanitizeRecords(st.routines).map((r) => ({
      id: r.id,
      name: r.name,
      emoji: r.emoji,
      count: sanitizeRecords(r.ex).length,
    })),
    bodyweight: sanitizeRecords(st.bodyweight),
    // A workout's photos and videos are the owner's own: the admin view gets no refs to them.
    workouts: sanitizeRecords(st.workouts)
      .reverse()
      .map(({ media: _media, ...w }) => w),
  });
});

adminRoutes.post('/api/admin/user/disable', async (c) => {
  const admin = await requireAdmin(c.env, c.req.raw);
  if (admin instanceof Response) return admin;
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const u = await getUserById(c.env, textField(body.id));
  if (!u) return c.json({ error: 'no such user' }, 404);
  if (isAdmin(c.env, u)) return c.json({ error: 'cannot disable an admin' }, 400);

  const disabled = body.disabled ? 1 : 0;
  await c.env.DB.prepare('UPDATE users SET disabled = ? WHERE uid = ?').bind(disabled, u.uid).run();
  // A device link made before the lock would otherwise still be waiting when it is lifted.
  if (disabled) {
    await c.env.DB.prepare("DELETE FROM ephemeral_codes WHERE kind = 'device_link' AND uid = ?").bind(u.uid).run();
  }
  await writeAudit(c.env, c.req.raw, disabled ? 'admin.user.disable' : 'admin.user.enable', {
    user: admin,
    target: u,
  });
  return c.json({ ok: true, id: u.uid, disabled: disabled === 1 });
});

adminRoutes.post('/api/admin/user/delete', async (c) => {
  const admin = await requireAdmin(c.env, c.req.raw);
  if (admin instanceof Response) return admin;
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const u = await getUserById(c.env, textField(body.id));
  if (!u) return c.json({ error: 'no such user' }, 404);
  if (u.uid === admin.uid) return c.json({ error: 'you cannot delete your own account' }, 400);
  if (isAdmin(c.env, u) && (await adminCount(c.env)) <= 1) {
    return c.json({ error: 'cannot delete the last admin' }, 400);
  }
  if (isOwner(c.env, u)) {
    return c.json({ error: 'the owner cannot be deleted; hand the role to another admin first' }, 400);
  }
  if (isAdmin(c.env, u) && !isOwner(c.env, admin)) {
    await writeAudit(c.env, c.req.raw, 'admin.denied', { ok: false, user: admin, target: u });
    return c.json({ error: 'only the owner can delete an admin' }, 403);
  }
  await c.env.DB.prepare('DELETE FROM users WHERE uid = ?').bind(u.uid).run();
  await writeAudit(c.env, c.req.raw, 'admin.user.delete', { user: admin, msg: u.username });
  return c.json({ ok: true, id: u.uid });
});

adminRoutes.post('/api/admin/user/role', async (c) => {
  const owner = await requireOwner(c.env, c.req.raw);
  if (owner instanceof Response) return owner;
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const u = await getUserById(c.env, textField(body.id));
  if (!u) return c.json({ error: 'no such user' }, 404);
  if (u.uid === owner.uid) return c.json({ error: 'the owner stays an admin' }, 400);
  if (typeof body.admin !== 'boolean') return c.json({ error: 'admin must be true or false' }, 400);
  if (adminUidSet(c.env).has(u.uid)) {
    return c.json({ error: 'this admin is set in ADMIN_UIDS on the server' }, 400);
  }
  if (body.admin && u.disabled === 1) return c.json({ error: 'enable the account first' }, 400);

  await c.env.DB.prepare('UPDATE users SET is_admin = ?, is_owner = 0 WHERE uid = ?')
    .bind(body.admin ? 1 : 0, u.uid)
    .run();
  await writeAudit(c.env, c.req.raw, body.admin ? 'admin.role.grant' : 'admin.role.revoke', {
    user: owner,
    target: u,
  });
  return c.json({ ok: true, id: u.uid, admin: body.admin });
});

adminRoutes.post('/api/admin/owner', async (c) => {
  const owner = await requireOwner(c.env, c.req.raw);
  if (owner instanceof Response) return owner;
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const u = await getUserById(c.env, textField(body.id));
  if (!u) return c.json({ error: 'no such user' }, 404);
  if (u.uid === owner.uid) return c.json({ error: 'you already are the owner' }, 400);
  if (!isAdmin(c.env, u) || u.disabled === 1) return c.json({ error: 'make them an admin first' }, 400);

  await c.env.DB.batch([
    c.env.DB.prepare('UPDATE users SET is_owner = 0'),
    c.env.DB.prepare('UPDATE users SET is_owner = 1 WHERE uid = ?').bind(u.uid),
  ]);
  await writeAudit(c.env, c.req.raw, 'admin.owner.transfer', { user: owner, target: u });
  return c.json({ ok: true, id: u.uid });
});

adminRoutes.post('/api/admin/user/recovery', async (c) => {
  const admin = await requireAdmin(c.env, c.req.raw);
  if (admin instanceof Response) return admin;
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const u = await getUserById(c.env, textField(body.id));
  if (!u) return c.json({ error: 'no such user' }, 404);
  if (u.uid === admin.uid) return c.json({ error: 'add a passkey in Settings instead', code: 'self' }, 400);
  if (isOwner(c.env, u)) return c.json({ error: 'owner cannot be recovered via admin route', code: 'owner' }, 403);
  if (isAdmin(c.env, u) && !isOwner(c.env, admin)) {
    return c.json({ error: 'only the owner can make a recovery code for an admin' }, 403);
  }
  if (u.disabled === 1) return c.json({ error: 'enable the account first', code: 'disabled' }, 400);

  const rawCode = `${randomCode(4)}-${randomCode(4)}-${randomCode(4)}`;
  const hash = await sha256Hex('opengym-link:' + rawCode.replace(/-/g, '').toUpperCase());
  const expires = Date.now() + RECOVERY_TTL_MS;

  await c.env.DB.batch([
    c.env.DB.prepare('UPDATE users SET session_version = session_version + 1 WHERE uid = ?').bind(u.uid),
    c.env.DB.prepare("DELETE FROM ephemeral_codes WHERE kind IN ('pair', 'device_link') AND uid = ?").bind(u.uid),
  ]);
  await putEphemeral(c.env, `dl:${hash}`, 'device_link', { uid: u.uid, kind: 'recovery' }, RECOVERY_TTL_MS, u.uid);
  await writeAudit(c.env, c.req.raw, 'admin.recovery.create', { user: admin, target: u });
  return c.json({ ok: true, name: u.username, code: rawCode, expires });
});

/* ---------- Invites ---------- */

adminRoutes.get('/api/admin/invites', async (c) => {
  const admin = await requireAdmin(c.env, c.req.raw);
  if (admin instanceof Response) return admin;
  const res = await c.env.DB.prepare(
    `SELECT i.*, u.username AS used_by_name
     FROM invites i
     LEFT JOIN users u ON u.uid = i.used_by
     ORDER BY i.created_at DESC`
  ).all<{
    code: string;
    note: string;
    created_by: string | null;
    used_by: string | null;
    used_at: string | null;
    revoked: number;
    created_at: string;
    used_by_name: string | null;
  }>();

  const invites = (res.results || []).map((i) => ({
    code: i.code,
    note: i.note,
    createdBy: i.created_by,
    created: i.created_at,
    usedBy: i.used_by,
    usedAt: i.used_at,
    usedByName: i.used_by_name,
    revoked: i.revoked === 1,
  }));
  return c.json({ invites, invite_only: flagOn(c.env.INVITE_ONLY, false) });
});

adminRoutes.post('/api/admin/invites/new', async (c) => {
  const admin = await requireAdmin(c.env, c.req.raw);
  if (admin instanceof Response) return admin;
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const code = randomHex(8).toUpperCase();
  const note = textField(body.note).slice(0, 60);
  const created = new Date().toISOString();

  await c.env.DB.prepare(
    'INSERT INTO invites (code, note, created_by, created_at) VALUES (?, ?, ?, ?)'
  )
    .bind(code, note, admin.uid, created)
    .run();
  await writeAudit(c.env, c.req.raw, 'admin.invite.create', { user: admin, msg: code });
  return c.json({ invite: { code, note, createdBy: admin.uid, created } });
});

adminRoutes.post('/api/admin/invites/revoke', async (c) => {
  const admin = await requireAdmin(c.env, c.req.raw);
  if (admin instanceof Response) return admin;
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const code = textField(body.code).toUpperCase();
  const inv = await c.env.DB.prepare('SELECT code, used_by FROM invites WHERE code = ?')
    .bind(code)
    .first<{ code: string; used_by: string | null }>();
  if (!inv) return c.json({ error: 'no such code' }, 404);
  if (inv.used_by) return c.json({ error: 'already used, cannot revoke' }, 400);

  await c.env.DB.prepare('DELETE FROM invites WHERE code = ?').bind(code).run();
  await writeAudit(c.env, c.req.raw, 'admin.invite.revoke', { user: admin, msg: code });
  return c.json({ ok: true });
});

/* ---------- Audit Log ---------- */

adminRoutes.get('/api/admin/audit', async (c) => {
  const admin = await requireAdmin(c.env, c.req.raw);
  if (admin instanceof Response) return admin;

  // Nothing past its retention is ever served (upstream prunes on read as well).
  await pruneAudit(c.env);

  const limit = Math.max(1, Math.min(200, Number(c.req.query('limit')) || 100));
  const before = Number(c.req.query('before')) || Number.MAX_SAFE_INTEGER;
  const cat = c.req.query('cat') || '';

  // The count and the rows share one filter; `before` only pages the rows.
  let where = '1 = 1';
  const fbinds: unknown[] = [];
  if (cat === 'fail') {
    where += ' AND ok = 0';
  } else if (cat) {
    where += " AND action LIKE ? ESCAPE '\\'";
    fbinds.push(`${cat.replace(/[\\%_]/g, '\\$&')}.%`);
  }
  const sql = `SELECT * FROM audit_log WHERE ${where} AND id < ? ORDER BY id DESC LIMIT ?`;
  const binds: unknown[] = [...fbinds, before, limit];

  const res = await c.env.DB.prepare(sql).bind(...binds).all<{
    id: number;
    ts: number;
    uid: string | null;
    name: string | null;
    tgt: string | null;
    tname: string | null;
    action: string;
    ok: number;
    msg: string | null;
    ip: string | null;
  }>();

  const totalRow = await c.env.DB.prepare(`SELECT COUNT(*) AS cnt FROM audit_log WHERE ${where}`)
    .bind(...fbinds)
    .first<{ cnt: number }>();
  const events = (res.results || []).map((r) => ({
    id: r.id,
    ts: r.ts,
    ev: r.action,
    ok: r.ok === 1,
    ...(r.uid ? { uid: r.uid } : {}),
    ...(r.name ? { name: r.name } : {}),
    ...(r.tgt ? { tgt: r.tgt } : {}),
    ...(r.tname ? { tname: r.tname } : {}),
    ...(r.msg ? { msg: r.msg } : {}),
    ...(r.ip ? { ip: r.ip } : {}),
  }));

  return c.json({
    events,
    total: totalRow?.cnt ?? 0,
    nextBefore: events.length === limit ? events[events.length - 1].id : null,
    enabled: flagOn(c.env.AUDIT_LOG, true),
    ip_mode: (c.env.AUDIT_IP || 'off').toLowerCase(),
    retention: auditRetention(c.env),
    now: Date.now(),
  });
});

adminRoutes.post('/api/admin/audit/clear', async (c) => {
  const owner = await requireOwner(c.env, c.req.raw);
  if (owner instanceof Response) return owner;
  await c.env.DB.prepare('DELETE FROM audit_log').run();
  await writeAudit(c.env, c.req.raw, 'admin.audit.clear', { user: owner });
  return c.json({ ok: true });
});

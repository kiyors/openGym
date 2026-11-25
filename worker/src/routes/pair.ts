import { Hono } from 'hono';
import { Env } from '../env';
import { randomCode } from '../crypto';
import {
  getSessionFromRequest,
  getUserById,
  makeBearerSessionToken,
  publicUser,
  putEphemeral,
  takeEphemeral,
  textField,
  writeAudit,
} from '../db';
import { proveOwnerPasskey } from './auth';

export const pairRoutes = new Hono<{ Bindings: Env }>();

const PAIR_TTL_MS = 5 * 60_000;

pairRoutes.post('/api/pair/create', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const proof = await proveOwnerPasskey(c.env, c.req.raw, s.user, body);
  if (!proof.ok) return c.json(proof.body, proof.status);

  // One live pairing code per user
  await c.env.DB.prepare("DELETE FROM ephemeral_codes WHERE kind = 'pair' AND uid = ?")
    .bind(s.user.uid)
    .run();

  const code = randomCode(8);
  await putEphemeral(c.env, `pair:${code}`, 'pair', { uid: s.user.uid }, PAIR_TTL_MS, s.user.uid);
  await writeAudit(c.env, c.req.raw, 'auth.pair.create', { user: s.user, msg: proof.proof });
  return c.json({ code });
});

pairRoutes.post('/api/pair/redeem', async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const code = textField(body.code).trim().toUpperCase();
  const entry = await takeEphemeral<{ uid: string }>(c.env, `pair:${code}`, 'pair');
  if (!entry) {
    await writeAudit(c.env, c.req.raw, 'auth.pair.fail', { ok: false, msg: 'code-invalid' });
    return c.json({ error: 'invalid or expired code', code: 'pair-invalid' }, 400);
  }
  const user = await getUserById(c.env, entry.payload.uid);
  if (!user || user.disabled === 1) {
    await writeAudit(c.env, c.req.raw, 'auth.pair.fail', {
      ok: false,
      uid: entry.payload.uid,
      msg: 'user-unavailable',
    });
    return c.json({ error: 'invalid or expired code', code: 'pair-invalid' }, 400);
  }
  const token = await makeBearerSessionToken(c.env, user);
  await writeAudit(c.env, c.req.raw, 'auth.pair.ok', { user });
  return c.json({ token, user: publicUser(c.env, user) });
});

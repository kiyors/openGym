import { Hono } from 'hono';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { Env, adminUidSet, flagOn, resolveOrigin, resolveRpId, resolveRpName } from '../env';
import { MAX_PASSKEYS, passkeyName, transportsOf } from '../../../api/passkeys-store.js';
import { isMisconfigured, verifyError } from '../../../api/verify-error.js';
import { addressPaused, strikeAddress, throttle } from '../lib/throttle';
import { base64UrlToBytes, bytesToBase64Url, randomBase64Url, randomCode, sha256Hex } from '../crypto';
import {
  PasskeyRow,
  UserRow,
  clearSessionCookieHeaders,
  getSessionFromRequest,
  getUserById,
  isAdmin,
  makeSessionCookieHeaders,
  peekEphemeral,
  pruneExpiredEphemeral,
  publicUser,
  putEphemeral,
  takeEphemeral,
  textField,
  writeAudit,
} from '../db';

export const authRoutes = new Hono<{ Bindings: Env }>();

const CHALLENGE_TTL_MS = 5 * 60_000;
const DEVICE_LINK_TTL_MS = 10 * 60_000;

function setCookies(headers: Headers, cookies: string[]) {
  for (const c of cookies) headers.append('Set-Cookie', c);
}

async function listUserPasskeys(env: Env, uid: string): Promise<PasskeyRow[]> {
  const res = await env.DB.prepare(
    'SELECT * FROM passkeys WHERE uid = ? ORDER BY created_at ASC'
  )
    .bind(uid)
    .all<PasskeyRow>();
  return res.results || [];
}

const SIGNED_OUT = { error: 'not signed in' };
const LAST_ADMIN = { error: 'the last admin cannot leave while other profiles remain', code: 'last-admin' };

function parseTransports(json: string | null): string[] {
  if (!json) return [];
  try {
    return transportsOf(JSON.parse(json));
  } catch {
    return [];
  }
}

// A failed verification as the answer's body. Never e.message: it can echo attacker-supplied
// response fields. A wrong address gets the same code as the origin check's 403.
function verifyAnswer(env: Env, req: Request, e: unknown) {
  const origin = resolveOrigin(env, req);
  return {
    error: verifyError(e, { rpId: resolveRpId(env, req), origin }) as string,
    ...(isMisconfigured(e) ? { code: 'origin-mismatch', expected: origin } : {}),
  };
}

// As upstream: the admin counts every profile through isAdmin, so ADMIN_UIDS counts too.
async function lastAdminLeaving(env: Env, user: UserRow): Promise<boolean> {
  if (!isAdmin(env, user)) return false;
  const res = await env.DB.prepare('SELECT uid, is_admin FROM users').all<{ uid: string; is_admin: number }>();
  const rows = res.results || [];
  if (rows.length <= 1) return false;
  const ids = adminUidSet(env);
  return rows.filter((r) => r.is_admin === 1 || ids.has(r.uid)).length <= 1;
}

// Whether the session is still the one that started the request: a sign-out everywhere or a
// disable can land while a passkey proof is being verified.
async function stillSignedIn(env: Env, req: Request, uid: string): Promise<boolean> {
  const again = await getSessionFromRequest(env, req);
  return !!again && again.user.uid === uid;
}

const PASSKEY_LIMIT = { error: `a profile can have at most ${MAX_PASSKEYS} passkeys`, code: 'passkey-limit' };

const CREDENTIAL_EXISTS = { error: 'credential already registered', code: 'credential-exists' };

interface NewPasskey {
  credentialId: string;
  uid: string;
  publicKey: Uint8Array;
  counter: number;
  deviceType: string | null;
  backedUp: boolean;
  transports: unknown;
  label: string | null;
  now: string;
}

// An INSERT that lands only while `guard` holds, so the check and the write are one statement.
function insertPasskey(env: Env, k: NewPasskey, guard = '1', guardBinds: unknown[] = []) {
  return env.DB.prepare(
    `INSERT INTO passkeys (credential_id, uid, public_key, counter, device_type, backed_up, transports_json, label, created_at, last_used_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE ${guard}`
  ).bind(
    k.credentialId,
    k.uid,
    bytesToBase64Url(k.publicKey),
    k.counter || 0,
    k.deviceType || null,
    k.backedUp ? 1 : 0,
    JSON.stringify(transportsOf(k.transports)),
    k.label,
    k.now,
    k.now,
    ...guardBinds
  );
}

function formatPasskeys(rows: PasskeyRow[]) {
  return rows.map((r) => ({
    id: r.credential_id,
    name: r.label || null,
    created: r.created_at,
    lastUsed: r.last_used_at,
    transports: parseTransports(r.transports_json),
  }));
}

async function passkeyStatePayload(env: Env, user: UserRow) {
  const rows = await listUserPasskeys(env, user.uid);
  return {
    passkeys: formatPasskeys(rows),
    password: false,
    lastWayIn: rows.length <= 1,
  };
}

export async function proveOwnerPasskey(
  env: Env,
  req: Request,
  user: UserRow,
  body: Record<string, unknown>
): Promise<{ ok: true; proof: 'passkey' } | { ok: false; status: 403; body: Record<string, unknown> }> {
  const credential = body.credential as AuthenticationResponseJSON | undefined;
  const cid = textField(body.cid);
  if (!credential || !cid) {
    return { ok: false, status: 403, body: { error: 'confirm with your passkey first', code: 'passkey-required' } };
  }
  const ch = await takeEphemeral<{ challenge: string }>(env, `ch:${cid}`, 'challenge_login');
  if (!ch) {
    return { ok: false, status: 403, body: { error: 'the passkey could not be verified', code: 'passkey' } };
  }
  const cred = await env.DB.prepare('SELECT * FROM passkeys WHERE credential_id = ? AND uid = ?')
    .bind(credential.id, user.uid)
    .first<PasskeyRow>();
  if (!cred) {
    return { ok: false, status: 403, body: { error: 'the passkey could not be verified', code: 'passkey' } };
  }
  try {
    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: ch.payload.challenge,
      expectedOrigin: resolveOrigin(env, req),
      expectedRPID: resolveRpId(env, req),
      requireUserVerification: false,
      credential: {
        id: cred.credential_id,
        publicKey: base64UrlToBytes(cred.public_key),
        counter: cred.counter,
        transports: cred.transports_json
          ? (parseTransports(cred.transports_json) as AuthenticatorTransportFuture[])
          : undefined,
      },
    });
    if (!verification.verified) {
      return { ok: false, status: 403, body: { error: 'the passkey could not be verified', code: 'passkey' } };
    }
    await env.DB.prepare('UPDATE passkeys SET counter = ?, last_used_at = ? WHERE credential_id = ?')
      .bind(verification.authenticationInfo.newCounter, new Date().toISOString(), cred.credential_id)
      .run();
    return { ok: true, proof: 'passkey' };
  } catch {
    return { ok: false, status: 403, body: { error: 'the passkey could not be verified', code: 'passkey' } };
  }
}

/* ---------- Registration ---------- */

authRoutes.post('/api/register/options', async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const name = textField(body.name).trim().slice(0, 40);
  if (!name) return c.json({ error: 'name required' }, 400);

  const inviteOnly = flagOn(c.env.INVITE_ONLY, false);
  const code = textField(body.code).trim().toUpperCase();

  if (inviteOnly) {
    const inv = await c.env.DB.prepare(
      'SELECT code FROM invites WHERE code = ? AND used_by IS NULL AND revoked = 0'
    )
      .bind(code)
      .first();
    if (!inv) {
      await writeAudit(c.env, c.req.raw, 'auth.register.denied', { ok: false, name, msg: 'invite-rejected' });
      return c.json({ error: 'a valid invite code is required', code: 'invite' }, 403);
    }
  }

  const uid = randomBase64Url(12);
  const options = await generateRegistrationOptions({
    rpName: resolveRpName(c.env),
    rpID: resolveRpId(c.env, c.req.raw),
    userID: new Uint8Array(new TextEncoder().encode(uid)),
    userName: name,
    userDisplayName: name,
    attestationType: 'none',
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    excludeCredentials: [],
  });

  const cid = randomBase64Url(16);
  await putEphemeral(
    c.env,
    `ch:${cid}`,
    'challenge_register',
    { challenge: options.challenge, name, uid, code },
    CHALLENGE_TTL_MS
  );
  c.executionCtx.waitUntil(pruneExpiredEphemeral(c.env));
  return c.json({ cid, options });
});

authRoutes.post('/api/register/verify', async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const cid = textField(body.cid);
  const ch = await takeEphemeral<{ challenge: string; name: string; uid: string; code: string }>(
    c.env,
    `ch:${cid}`,
    'challenge_register'
  );
  if (!ch) {
    return c.json({ error: 'challenge expired, try again', code: 'challenge-expired' }, 400);
  }

  const origin = resolveOrigin(c.env, c.req.raw);
  const rpID = resolveRpId(c.env, c.req.raw);
  const credentialResp = body.credential as RegistrationResponseJSON;

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: credentialResp,
      expectedChallenge: ch.payload.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: false,
    });
  } catch (e) {
    await writeAudit(c.env, c.req.raw, 'auth.register.fail', {
      ok: false,
      name: ch.payload.name,
      msg: 'verify-error',
    });
    return c.json(verifyAnswer(c.env, c.req.raw, e), 400);
  }

  if (!verification.verified || !verification.registrationInfo) {
    return c.json({ error: 'not verified' }, 400);
  }

  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
  const existingCred = await c.env.DB.prepare('SELECT credential_id FROM passkeys WHERE credential_id = ?')
    .bind(credential.id)
    .first();
  if (existingCred) {
    return c.json(CREDENTIAL_EXISTS, 409);
  }

  const firstUserAdmin = flagOn(c.env.FIRST_USER_ADMIN, false);
  const inviteOnly = flagOn(c.env.INVITE_ONLY, false);

  let usedInvite: string | null = null;
  if (inviteOnly) {
    const inv = await c.env.DB.prepare(
      'SELECT code FROM invites WHERE code = ? AND used_by IS NULL AND revoked = 0'
    )
      .bind(ch.payload.code)
      .first<{ code: string }>();
    if (!inv) {
      return c.json({ error: 'invite code is no longer valid, ask for a new one', code: 'invite' }, 403);
    }
    usedInvite = inv.code;
  }

  const nowIso = new Date().toISOString();

  // One batch, and every statement guards itself: the user lands only while the invite is still
  // unused (so two verifies with one code cannot both succeed) and is the admin only while the
  // table is empty (so two first registrations cannot both be). SQLite serialises the batch.
  let results;
  try {
    results = await c.env.DB.batch([
      c.env.DB.prepare(
        `INSERT INTO users (uid, username, session_version, is_admin, is_owner, disabled, invited_by, created_at)
         SELECT ?, ?, 1, a.v, a.v, 0, ?, ?
         FROM (SELECT CASE WHEN ? = 1 AND NOT EXISTS (SELECT 1 FROM users) THEN 1 ELSE 0 END AS v) a
         WHERE (? IS NULL OR EXISTS (SELECT 1 FROM invites WHERE code = ? AND used_by IS NULL AND revoked = 0))`
      ).bind(
        ch.payload.uid,
        ch.payload.name,
        usedInvite,
        nowIso,
        firstUserAdmin ? 1 : 0,
        usedInvite,
        usedInvite
      ),
      insertPasskey(
        c.env,
        {
          credentialId: credential.id,
          uid: ch.payload.uid,
          publicKey: credential.publicKey,
          counter: credential.counter,
          deviceType: credentialDeviceType,
          backedUp: credentialBackedUp,
          transports: credentialResp?.response?.transports,
          label: null,
          now: nowIso,
        },
        'EXISTS (SELECT 1 FROM users WHERE uid = ?)',
        [ch.payload.uid]
      ),
      c.env.DB.prepare(
        'UPDATE invites SET used_by = ?, used_at = ? WHERE code = ? AND used_by IS NULL AND revoked = 0 AND ? IS NOT NULL'
      ).bind(ch.payload.uid, nowIso, usedInvite, usedInvite),
    ]);
  } catch (e) {
    const dup = await c.env.DB.prepare('SELECT credential_id FROM passkeys WHERE credential_id = ?')
      .bind(credential.id)
      .first();
    if (dup) return c.json(CREDENTIAL_EXISTS, 409);
    throw e;
  }
  if (!results[0].meta.changes) {
    return c.json({ error: 'invite code is no longer valid, ask for a new one', code: 'invite' }, 403);
  }

  const user = (await getUserById(c.env, ch.payload.uid))!;
  await writeAudit(c.env, c.req.raw, 'auth.register.ok', { user, msg: usedInvite });
  const cookies = await makeSessionCookieHeaders(c.env, c.req.raw, user);
  const res = c.json({ user: publicUser(c.env, user) });
  setCookies(res.headers, cookies);
  return res;
});

/* ---------- Login ---------- */

authRoutes.post('/api/login/options', async (c) => {
  const options = await generateAuthenticationOptions({
    rpID: resolveRpId(c.env, c.req.raw),
    userVerification: 'preferred',
    allowCredentials: [],
  });
  const cid = randomBase64Url(16);
  await putEphemeral(c.env, `ch:${cid}`, 'challenge_login', { challenge: options.challenge }, CHALLENGE_TTL_MS);
  return c.json({ cid, options });
});

authRoutes.post('/api/login/verify', async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const cid = textField(body.cid);
  const ch = await takeEphemeral<{ challenge: string }>(c.env, `ch:${cid}`, 'challenge_login');
  if (!ch) {
    return c.json({ error: 'challenge expired, try again', code: 'challenge-expired' }, 400);
  }

  const credentialResp = body.credential as AuthenticationResponseJSON;
  if (!credentialResp?.id || typeof credentialResp.id !== 'string') {
    return c.json({ error: 'unknown passkey, create a profile first', code: 'unknown-credential' }, 404);
  }
  const cred = await c.env.DB.prepare('SELECT * FROM passkeys WHERE credential_id = ?')
    .bind(credentialResp.id)
    .first<PasskeyRow>();
  if (!cred) {
    return c.json({ error: 'unknown passkey, create a profile first', code: 'unknown-credential' }, 404);
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: credentialResp,
      expectedChallenge: ch.payload.challenge,
      expectedOrigin: resolveOrigin(c.env, c.req.raw),
      expectedRPID: resolveRpId(c.env, c.req.raw),
      requireUserVerification: false,
      credential: {
        id: cred.credential_id,
        publicKey: base64UrlToBytes(cred.public_key),
        counter: cred.counter,
        transports: cred.transports_json
          ? (parseTransports(cred.transports_json) as AuthenticatorTransportFuture[])
          : undefined,
      },
    });
  } catch (e) {
    await writeAudit(c.env, c.req.raw, 'auth.login.fail', { ok: false, uid: cred.uid, msg: 'verify-error' });
    return c.json(verifyAnswer(c.env, c.req.raw, e), 400);
  }

  if (!verification.verified) {
    return c.json({ error: 'not verified' }, 400);
  }

  await c.env.DB.prepare('UPDATE passkeys SET counter = ?, last_used_at = ? WHERE credential_id = ?')
    .bind(verification.authenticationInfo.newCounter, new Date().toISOString(), cred.credential_id)
    .run();

  const user = await getUserById(c.env, cred.uid);
  if (!user) return c.json({ error: 'user missing' }, 500);
  if (user.disabled === 1) {
    await writeAudit(c.env, c.req.raw, 'auth.login.fail', { ok: false, user, msg: 'account-disabled' });
    return c.json({ error: 'this account has been disabled', code: 'disabled' }, 403);
  }

  await writeAudit(c.env, c.req.raw, 'auth.login.ok', { user });
  const cookies = await makeSessionCookieHeaders(c.env, c.req.raw, user);
  const res = c.json({ user: publicUser(c.env, user) });
  setCookies(res.headers, cookies);
  return res;
});

/* ---------- Logout & Account Delete ---------- */

authRoutes.post('/api/logout', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (s) await writeAudit(c.env, c.req.raw, 'auth.logout', { user: s.user });
  const res = c.json({ ok: true });
  setCookies(res.headers, clearSessionCookieHeaders(c.env, c.req.raw));
  return res;
});

authRoutes.post('/api/logout/all', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json({ error: 'not signed in' }, 401);
  await c.env.DB.batch([
    c.env.DB.prepare('UPDATE users SET session_version = session_version + 1 WHERE uid = ?').bind(s.user.uid),
    c.env.DB.prepare("DELETE FROM ephemeral_codes WHERE uid = ? AND kind IN ('pair', 'device_link')").bind(s.user.uid),
    c.env.DB.prepare('DELETE FROM api_tokens WHERE uid = ?').bind(s.user.uid),
  ]);
  await writeAudit(c.env, c.req.raw, 'auth.logout.all', { user: s.user });
  const res = c.json({ ok: true });
  setCookies(res.headers, clearSessionCookieHeaders(c.env, c.req.raw));
  return res;
});

authRoutes.post('/api/account/delete', async (c) => {
  const limited = throttle(c, null);
  if (limited) return limited;
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json(SIGNED_OUT, 401);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  if (!(await stillSignedIn(c.env, c.req.raw, s.user.uid))) return c.json(SIGNED_OUT, 401);
  if (typeof body.name !== 'string' || body.name.trim() !== s.user.username) {
    return c.json({ error: 'type the account name to confirm', code: 'confirm-name' }, 400);
  }
  if (await lastAdminLeaving(c.env, s.user)) return c.json(LAST_ADMIN, 409);

  const paired = s.bearer && s.kind !== 'c';
  if (!paired) {
    const proof = await proveOwnerPasskey(c.env, c.req.raw, s.user, body);
    if (!proof.ok) return c.json(proof.body, proof.status);
  }
  // Everything above awaited: the session may have ended, and another admin may have left.
  if (!(await stillSignedIn(c.env, c.req.raw, s.user.uid))) return c.json(SIGNED_OUT, 401);
  if (await lastAdminLeaving(c.env, s.user)) return c.json(LAST_ADMIN, 409);

  await c.env.DB.prepare('DELETE FROM users WHERE uid = ?').bind(s.user.uid).run();
  await writeAudit(c.env, c.req.raw, 'auth.account.delete', { user: s.user, msg: paired ? 'device' : 'passkey' });
  const res = c.json({ ok: true });
  setCookies(res.headers, clearSessionCookieHeaders(c.env, c.req.raw));
  return res;
});

/* ---------- Multi-Passkey Management ---------- */

authRoutes.get('/api/account/passkeys', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json(SIGNED_OUT, 401);
  const state = await passkeyStatePayload(c.env, s.user);
  // The profile's own delete would be refused before any proof is looked at.
  return c.json({ ...state, ...((await lastAdminLeaving(c.env, s.user)) ? { deleteBlocked: 'last-admin' } : {}) });
});

authRoutes.post('/api/account/passkeys/options', async (c) => {
  const limited = throttle(c, null);
  if (limited) return limited;
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json(SIGNED_OUT, 401);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const existing = await listUserPasskeys(c.env, s.user.uid);
  if (existing.length >= MAX_PASSKEYS) return c.json(PASSKEY_LIMIT, 409);
  const proof = await proveOwnerPasskey(c.env, c.req.raw, s.user, body);
  if (!proof.ok) return c.json(proof.body, proof.status);
  if (!(await stillSignedIn(c.env, c.req.raw, s.user.uid))) return c.json(SIGNED_OUT, 401);

  const options = await generateRegistrationOptions({
    rpName: resolveRpName(c.env),
    rpID: resolveRpId(c.env, c.req.raw),
    userID: new Uint8Array(new TextEncoder().encode(s.user.uid)),
    userName: s.user.username,
    userDisplayName: s.user.username,
    attestationType: 'none',
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    excludeCredentials: existing.map((k) => ({
      id: k.credential_id,
      transports: parseTransports(k.transports_json) as AuthenticatorTransportFuture[],
    })),
  });
  const cid = randomBase64Url(16);
  await putEphemeral(
    c.env,
    `ch:${cid}`,
    'challenge_add',
    { challenge: options.challenge, uid: s.user.uid, sv: s.user.session_version },
    CHALLENGE_TTL_MS,
    s.user.uid
  );
  return c.json({ cid, options });
});

authRoutes.post('/api/account/passkeys/verify', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json(SIGNED_OUT, 401);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const ch = await takeEphemeral<{ challenge: string; uid: string; sv: number }>(
    c.env,
    `ch:${textField(body.cid)}`,
    'challenge_add'
  );
  if (!ch || ch.payload.uid !== s.user.uid || ch.payload.sv !== s.user.session_version) {
    return c.json({ error: 'challenge expired, try again', code: 'challenge-expired' }, 400);
  }
  const credentialResp = body.credential as RegistrationResponseJSON;
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: credentialResp,
      expectedChallenge: ch.payload.challenge,
      expectedOrigin: resolveOrigin(c.env, c.req.raw),
      expectedRPID: resolveRpId(c.env, c.req.raw),
      requireUserVerification: false,
    });
  } catch (e) {
    return c.json(verifyAnswer(c.env, c.req.raw, e), 400);
  }
  if (!verification.verified || !verification.registrationInfo) {
    return c.json({ error: 'not verified' }, 400);
  }
  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
  const dup = await c.env.DB.prepare('SELECT credential_id FROM passkeys WHERE credential_id = ?')
    .bind(credential.id)
    .first();
  if (dup) return c.json(CREDENTIAL_EXISTS, 409);
  const nowIso = new Date().toISOString();
  // The cap is checked in the INSERT itself, so two adds racing under it cannot both land.
  let added;
  try {
    added = await insertPasskey(
      c.env,
      {
        credentialId: credential.id,
        uid: s.user.uid,
        publicKey: credential.publicKey,
        counter: credential.counter,
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        transports: credentialResp?.response?.transports,
        label: passkeyName(body.name) || null,
        now: nowIso,
      },
      '(SELECT COUNT(*) FROM passkeys WHERE uid = ?) < ?',
      [s.user.uid, MAX_PASSKEYS]
    ).run();
  } catch (e) {
    const again = await c.env.DB.prepare('SELECT credential_id FROM passkeys WHERE credential_id = ?')
      .bind(credential.id)
      .first();
    if (again) return c.json(CREDENTIAL_EXISTS, 409);
    throw e;
  }
  if (!added.meta.changes) return c.json(PASSKEY_LIMIT, 409);
  await writeAudit(c.env, c.req.raw, 'auth.passkey.add', { user: s.user });
  return c.json({ ok: true, ...(await passkeyStatePayload(c.env, s.user)) });
});

authRoutes.post('/api/account/passkeys/rename', async (c) => {
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json(SIGNED_OUT, 401);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const id = textField(body.id);
  const label = passkeyName(body.name) || null;
  const res = await c.env.DB.prepare('UPDATE passkeys SET label = ? WHERE credential_id = ? AND uid = ?')
    .bind(label, id, s.user.uid)
    .run();
  if (!res.meta.changes) return c.json({ error: 'passkey not found', code: 'not-found' }, 404);
  return c.json({ ok: true, ...(await passkeyStatePayload(c.env, s.user)) });
});

authRoutes.delete('/api/account/passkeys', async (c) => {
  const limited = throttle(c, null);
  if (limited) return limited;
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json(SIGNED_OUT, 401);
  const id = c.req.query('id') || '';
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const existing = await listUserPasskeys(c.env, s.user.uid);
  if (!existing.some((k) => k.credential_id === id)) {
    return c.json({ error: 'passkey not found', code: 'not-found' }, 404);
  }
  if (existing.length <= 1) {
    return c.json({ error: 'this passkey is the only way into this profile', code: 'last-way-in' }, 409);
  }
  const proof = await proveOwnerPasskey(c.env, c.req.raw, s.user, body);
  if (!proof.ok) return c.json(proof.body, proof.status);
  if (!(await stillSignedIn(c.env, c.req.raw, s.user.uid))) return c.json(SIGNED_OUT, 401);

  // Never the last one: the delete lands only while another passkey is left.
  const removed = await c.env.DB.prepare(
    'DELETE FROM passkeys WHERE credential_id = ? AND uid = ? AND (SELECT COUNT(*) FROM passkeys WHERE uid = ?) > 1'
  )
    .bind(id, s.user.uid, s.user.uid)
    .run();
  if (!removed.meta.changes) {
    return c.json({ error: 'this passkey is the only way into this profile', code: 'last-way-in' }, 409);
  }
  await c.env.DB.prepare("DELETE FROM ephemeral_codes WHERE kind = 'device_link' AND uid = ?").bind(s.user.uid).run();
  await writeAudit(c.env, c.req.raw, 'auth.passkey.remove', { user: s.user });
  return c.json({ ok: true, ...(await passkeyStatePayload(c.env, s.user)) });
});

/* ---------- Device Link & Recovery ---------- */

const LINK_INVALID = { error: 'that code is wrong, used or expired', code: 'link-invalid' };

async function linkHash(code: unknown): Promise<string> {
  return sha256Hex('opengym-link:' + textField(code).replace(/[^A-Za-z0-9]/g, '').toUpperCase());
}

authRoutes.post('/api/account/device-link', async (c) => {
  const limited = throttle(c, null);
  if (limited) return limited;
  const s = await getSessionFromRequest(c.env, c.req.raw);
  if (!s) return c.json(SIGNED_OUT, 401);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const existing = await listUserPasskeys(c.env, s.user.uid);
  if (existing.length >= MAX_PASSKEYS) return c.json(PASSKEY_LIMIT, 409);
  const proof = await proveOwnerPasskey(c.env, c.req.raw, s.user, body);
  if (!proof.ok) return c.json(proof.body, proof.status);
  if (!(await stillSignedIn(c.env, c.req.raw, s.user.uid))) return c.json(SIGNED_OUT, 401);

  const rawCode = `${randomCode(4)}-${randomCode(4)}-${randomCode(4)}`;
  const hash = await linkHash(rawCode);
  const expires = Date.now() + DEVICE_LINK_TTL_MS;
  // One live code per profile: a new one retires the last.
  await c.env.DB.prepare("DELETE FROM ephemeral_codes WHERE kind = 'device_link' AND uid = ?").bind(s.user.uid).run();
  await putEphemeral(c.env, `dl:${hash}`, 'device_link', { uid: s.user.uid, kind: 'link' }, DEVICE_LINK_TTL_MS, s.user.uid);
  await writeAudit(c.env, c.req.raw, 'auth.link.create', { user: s.user, msg: 'passkey' });
  return c.json({ code: rawCode, expires });
});

authRoutes.post('/api/device-link/options', async (c) => {
  const limited = throttle(c, 'link');
  if (limited) return limited;
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const paused = addressPaused(c, 'link');
  if (paused) return paused;
  const hash = await linkHash(body.code);
  const link = await peekEphemeral<{ uid: string; kind: string }>(c.env, `dl:${hash}`, 'device_link');
  if (!link) {
    strikeAddress(c, 'link');
    return c.json(LINK_INVALID, 400);
  }

  const user = await getUserById(c.env, link.payload.uid);
  if (!user || user.disabled === 1) {
    return c.json(LINK_INVALID, 400);
  }
  const existing = await listUserPasskeys(c.env, user.uid);
  if (link.payload.kind !== 'recovery' && existing.length >= MAX_PASSKEYS) {
    return c.json(PASSKEY_LIMIT, 409);
  }
  const options = await generateRegistrationOptions({
    rpName: resolveRpName(c.env),
    rpID: resolveRpId(c.env, c.req.raw),
    userID: new Uint8Array(new TextEncoder().encode(user.uid)),
    userName: user.username,
    userDisplayName: user.username,
    attestationType: 'none',
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    excludeCredentials: existing.map((k) => ({
      id: k.credential_id,
      transports: parseTransports(k.transports_json) as AuthenticatorTransportFuture[],
    })),
  });
  const cid = randomBase64Url(16);
  await putEphemeral(
    c.env,
    `ch:${cid}`,
    'challenge_link',
    { challenge: options.challenge, uid: user.uid, lh: hash },
    CHALLENGE_TTL_MS,
    user.uid
  );
  return c.json({
    cid,
    options,
    id: user.uid,
    name: user.username,
    ...(link.payload.kind === 'recovery' ? { recovery: true } : {}),
  });
});

authRoutes.post('/api/device-link/verify', async (c) => {
  const limited = throttle(c, 'link');
  if (limited) return limited;
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const paused = addressPaused(c, 'link');
  if (paused) return paused;
  const hash = await linkHash(body.code);
  const ch = await takeEphemeral<{ challenge: string; uid: string; lh: string }>(
    c.env,
    `ch:${textField(body.cid)}`,
    'challenge_link'
  );
  // Only looked at here: the code is used up once the passkey is saved, so a prompt dismissed by
  // mistake can be tried again.
  const link = await peekEphemeral<{ uid: string; kind: string }>(c.env, `dl:${hash}`, 'device_link');
  if (!link) {
    strikeAddress(c, 'link');
    return c.json(LINK_INVALID, 400);
  }
  if (!ch || ch.payload.lh !== hash || ch.payload.uid !== link.payload.uid) {
    return c.json({ error: 'challenge expired, try again', code: 'challenge-expired' }, 400);
  }
  const user = await getUserById(c.env, link.payload.uid);
  if (!user || user.disabled === 1) {
    return c.json(LINK_INVALID, 400);
  }

  const credentialResp = body.credential as RegistrationResponseJSON;
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: credentialResp,
      expectedChallenge: ch.payload.challenge,
      expectedOrigin: resolveOrigin(c.env, c.req.raw),
      expectedRPID: resolveRpId(c.env, c.req.raw),
      requireUserVerification: false,
    });
  } catch (e) {
    await writeAudit(c.env, c.req.raw, 'auth.link.fail', { ok: false, user, msg: 'verify-error' });
    return c.json(verifyAnswer(c.env, c.req.raw, e), 400);
  }
  if (!verification.verified || !verification.registrationInfo) {
    return c.json({ error: 'not verified' }, 400);
  }
  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
  const dup = await c.env.DB.prepare('SELECT credential_id FROM passkeys WHERE credential_id = ?')
    .bind(credential.id)
    .first();
  if (dup) return c.json(CREDENTIAL_EXISTS, 409);

  const recovery = link.payload.kind === 'recovery';
  const existing = await listUserPasskeys(c.env, user.uid);
  if (!recovery && existing.length >= MAX_PASSKEYS) return c.json(PASSKEY_LIMIT, 409);

  const nowIso = new Date().toISOString();
  const linkAlive = 'EXISTS (SELECT 1 FROM ephemeral_codes WHERE code = ? AND expires_at > ?)';
  const linkBinds = [`dl:${hash}`, Date.now()];
  // Recovery on a full profile: the passkey used longest ago goes, to make room for this one.
  // Every statement lands only while the code is still live, and the code is burnt last, so two
  // redemptions cannot both succeed.
  let results;
  try {
    results = await c.env.DB.batch([
      c.env.DB.prepare(
        `DELETE FROM passkeys WHERE ? = 1 AND uid = ? AND (SELECT COUNT(*) FROM passkeys WHERE uid = ?) >= ?
           AND credential_id = (SELECT credential_id FROM passkeys WHERE uid = ? ORDER BY COALESCE(last_used_at, created_at) ASC LIMIT 1)
           AND ${linkAlive}`
      ).bind(recovery ? 1 : 0, user.uid, user.uid, MAX_PASSKEYS, user.uid, ...linkBinds),
      insertPasskey(
        c.env,
        {
          credentialId: credential.id,
          uid: user.uid,
          publicKey: credential.publicKey,
          counter: credential.counter,
          deviceType: credentialDeviceType,
          backedUp: credentialBackedUp,
          transports: credentialResp?.response?.transports,
          label: passkeyName(body.name) || null,
          now: nowIso,
        },
        linkAlive,
        linkBinds
      ),
      c.env.DB.prepare('DELETE FROM ephemeral_codes WHERE code = ?').bind(`dl:${hash}`),
    ]);
  } catch (e) {
    const again = await c.env.DB.prepare('SELECT credential_id FROM passkeys WHERE credential_id = ?')
      .bind(credential.id)
      .first();
    if (again) return c.json(CREDENTIAL_EXISTS, 409);
    throw e;
  }
  if (!results[1].meta.changes) {
    await writeAudit(c.env, c.req.raw, 'auth.link.fail', { ok: false, user, msg: 'link-invalid' });
    return c.json(LINK_INVALID, 400);
  }

  await writeAudit(c.env, c.req.raw, recovery ? 'auth.recovery.ok' : 'auth.link.ok', {
    user,
    msg: [passkeyName(body.name), results[0].meta.changes ? 'replaced a passkey' : ''].filter(Boolean).join(', ') || null,
  });
  const cookies = await makeSessionCookieHeaders(c.env, c.req.raw, user);
  const res = c.json({ user: publicUser(c.env, user) });
  setCookies(res.headers, cookies);
  return res;
});

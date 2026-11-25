/**
 * Pure WebCrypto helpers for Cloudflare Workers Free Tier (<1-2 ms CPU per request).
 * Preserves openGym's exact session token, API token, and AES-GCM sealing formats.
 */

const te = new TextEncoder();
const td = new TextDecoder();

export function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlToBytes(input: string): Uint8Array {
  const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4));
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

export function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  crypto.getRandomValues(buf);
  return buf;
}

export function randomBase64Url(byteLength: number): string {
  return bytesToBase64Url(randomBytes(byteLength));
}

export function randomHex(byteLength: number): string {
  return bytesToHex(randomBytes(byteLength));
}

export function randomCode(length: number, alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'): string {
  const bytes = randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) {
    out += alphabet[bytes[i] % alphabet.length];
  }
  return out;
}

export function timingSafeEqualStr(a: string, b: string): boolean {
  const ba = te.encode(a);
  const bb = te.encode(b);
  if (ba.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ba.length; i++) diff |= ba[i] ^ bb[i];
  return diff === 0;
}

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', te.encode(input));
  return bytesToHex(new Uint8Array(digest));
}

export async function sha256Base64Url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', te.encode(input));
  return bytesToBase64Url(new Uint8Array(digest));
}

export async function hmacSha256Base64Url(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    te.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, te.encode(payload));
  return bytesToBase64Url(new Uint8Array(sig));
}

export async function hmacSha256Hex(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    te.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, te.encode(payload));
  return bytesToHex(new Uint8Array(sig));
}

/** Sign `<uid>:<exp>:<sv>:<kind>` using openGym's exact HMAC-SHA256 base64url format. */
export async function signSessionToken(
  secret: string,
  uid: string,
  expMs: number,
  sv: number,
  kind: 'c' | 'b' = 'b'
): Promise<string> {
  const payload = `${uid}:${expMs}:${sv}:${kind}`;
  const mac = await hmacSha256Base64Url(secret, payload);
  return `${payload}.${mac}`;
}

export interface VerifiedSessionPayload {
  uid: string;
  exp: number;
  sv: number;
  kind: string | null;
}

export async function verifySessionToken(
  secret: string,
  token: string
): Promise<VerifiedSessionPayload | null> {
  const dot = token.lastIndexOf('.');
  if (dot <= 0) return null;
  const payload = token.slice(0, dot);
  const mac = token.slice(dot + 1);
  const expected = await hmacSha256Base64Url(secret, payload);
  if (!timingSafeEqualStr(mac, expected)) return null;
  const [uid, expStr, verStr, kind] = payload.split(':');
  const exp = Number(expStr);
  if (!uid || !Number.isFinite(exp) || exp < Date.now()) return null;
  const sv = verStr === undefined ? 0 : Number(verStr);
  if (!Number.isInteger(sv)) return null;
  return { uid, exp, sv, kind: kind || null };
}

/** Matches api/tokens.js `sha`: SHA-256('opengym-token:' + token) in hex. */
export async function hashApiToken(token: string): Promise<string> {
  return sha256Hex('opengym-token:' + token);
}

/** Matches api/oauth.js `rsha`: SHA-256('opengym-refresh:' + token) in hex. */
export async function hashRefreshToken(token: string): Promise<string> {
  return sha256Hex('opengym-refresh:' + token);
}

/** Derive a 256-bit AES-GCM key from ENC_KEY or SESSION_SECRET. */
async function deriveAesKey(secret: string): Promise<CryptoKey> {
  const hash = await crypto.subtle.digest('SHA-256', te.encode('opengym-aes:' + secret));
  return crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function sealSecret(secret: string, plaintext: string, aad = ''): Promise<string> {
  const key = await deriveAesKey(secret);
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, ...(aad ? { additionalData: te.encode(aad) } : {}) },
    key,
    te.encode(plaintext)
  );
  return `v1.${bytesToBase64Url(iv)}.${bytesToBase64Url(new Uint8Array(ct))}`;
}

export async function openSecret(secret: string, sealed: string, aad = ''): Promise<string | null> {
  try {
    const [v, ivStr, ctStr] = sealed.split('.');
    if (v !== 'v1' || !ivStr || !ctStr) return null;
    const key = await deriveAesKey(secret);
    const pt = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: base64UrlToBytes(ivStr),
        ...(aad ? { additionalData: te.encode(aad) } : {}),
      },
      key,
      base64UrlToBytes(ctStr)
    );
    return td.decode(pt);
  } catch {
    return null;
  }
}

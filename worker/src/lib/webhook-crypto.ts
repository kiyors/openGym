/** WebCrypto twins of api/integrations/crypto.js: signature format, ids, secrets, URL mask. */
import { bytesToBase64Url, bytesToHex, randomBytes } from '../crypto';

const te = new TextEncoder();

/** A new signing secret, shown to its owner once. */
export const newSecret = (): string => 'ogwh_' + bytesToBase64Url(randomBytes(24));

/** An id that says nothing about its owner. */
export const newId = (prefix = 'c'): string => prefix + '_' + bytesToBase64Url(randomBytes(9));

/**
 * `X-OpenGym-Signature: t=<unix seconds>,v1=<hex>`: HMAC-SHA256 over "<timestamp>.<body>" with the
 * webhook's secret, like api/integrations/crypto.js signature().
 */
export async function signature(
  secret: string,
  body: string,
  ts = Math.floor(Date.now() / 1000)
): Promise<string> {
  const key = await crypto.subtle.importKey('raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  const mac = await crypto.subtle.sign('HMAC', key, te.encode(`${ts}.${body}`));
  return `t=${ts},v1=${bytesToHex(new Uint8Array(mac))}`;
}

/** "https://ha.example.com/api/webhook/…x7Qk": enough to recognise, not enough to call. */
export function maskUrl(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return '';
  }
  const p = u.pathname;
  const seg = p.split('/').filter(Boolean);
  let shown = p;
  if (p.length > 16) shown = '/' + (seg.length > 1 ? seg.slice(0, -1).join('/').slice(0, 24) + '/' : '') + '…' + p.slice(-4);
  return `${u.protocol}//${u.host}${shown === '/' ? '' : shown}${u.search ? '?…' : ''}`.slice(0, 200);
}

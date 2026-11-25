/**
 * Where an outbound webhook may go. A port of api/net-guard.js without node:dns / node:net:
 * the hostname rules and the literal-address rules are the same; the DNS-rebinding half cannot be
 * done on Workers (no lookup hook), but a Worker fetch never reaches a private network anyway.
 * No INTEGRATIONS_ALLOW_LAN here: a Worker cannot see a home network.
 */

const V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isIPv4(v: string): boolean {
  const m = V4.exec(v);
  return !!m && m.slice(1).every((x) => +x <= 255);
}

export function isIPv6(v: string): boolean {
  const s = v.replace(/%.*$/, '');
  if (!/^[0-9a-f:.]+$/i.test(s) || (s.match(/:/g) || []).length < 2) return false;
  if ((s.match(/::/g) || []).length > 1) return false;
  return true;
}

export function ipv6Groups(v: string): number[] | null {
  if (!isIPv6(v)) return null;
  let s = v.replace(/%.*$/, '');
  const m4 = /:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s);
  if (m4) {
    const [a, b, c, d] = m4[1].split('.').map(Number);
    s = s.slice(0, -m4[1].length) + ((a << 8) | b).toString(16) + ':' + ((c << 8) | d).toString(16);
  }
  const [head, tail = ''] = s.split('::');
  const groups = head ? head.split(':') : [];
  const rest = tail ? tail.split(':') : [];
  if (s.includes('::')) while (groups.length + rest.length < 8) groups.push('0');
  const out = groups.concat(rest).map((x) => parseInt(x, 16));
  return out.length === 8 && out.every((x) => Number.isFinite(x)) ? out : null;
}

export function isPrivateAddr(ip: string): boolean {
  const v = String(ip).toLowerCase();
  const m4 = V4.exec(v);
  if (m4) {
    const a = +m4[1];
    const b = +m4[2];
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 192 && b === 0) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a >= 224) return true;
    return false;
  }
  const g = ipv6Groups(v);
  if (!g) return false;
  const v4 = (hi: number, lo: number) => isPrivateAddr(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return v4(g[6], g[7]);
  if (g.slice(0, 7).every((x) => x === 0) && g[7] <= 1) return true;
  if ((g[0] & 0xffc0) === 0xfe80) return true;
  if ((g[0] & 0xffc0) === 0xfec0) return true;
  if ((g[0] & 0xfe00) === 0xfc00) return true;
  if ((g[0] & 0xff00) === 0xff00) return true;
  if (g.slice(0, 6).every((x) => x === 0)) return v4(g[6], g[7]);
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return v4(g[6], g[7]);
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 1) return true;
  if (g[0] === 0x2002) return v4(g[1], g[2]);
  return false;
}

export const MAX_URL_LENGTH = 2048;

/** Why a webhook URL is refused, or null. Run when it is added and again before every send. */
export function outboundUrlError(raw: unknown): string | null {
  const s = String(raw || '').trim();
  if (!s) return 'url required';
  if (s.length > MAX_URL_LENGTH) return 'url is too long';
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return 'url is not valid';
  }
  if (u.protocol !== 'https:') return 'url must start with https://';
  if (u.username || u.password) return 'url must not carry a user name or password';
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (!host) return 'url is not valid';
  if (/^localhost$|\.localhost$/i.test(host)) return 'url must not point at this server';
  if (isIPv6(host) || isIPv4(host) || /^[0-9.]+$/.test(host)) {
    if (!isIPv6(host) && !isIPv4(host)) return 'url is not valid';
    if (isPrivateAddr(host)) return 'url points at a private address (your admin can allow the home network)';
  }
  return null;
}

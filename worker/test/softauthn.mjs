// A software WebAuthn authenticator for the end-to-end test: makes real "none"-attestation
// registrations and ES256 assertions, so the worker's @simplewebauthn/server checks run for real.
import { webcrypto as crypto } from 'node:crypto';

const enc = new TextEncoder();
export const b64u = (buf) => Buffer.from(buf).toString('base64url');
const fromB64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
const sha256 = async (data) => new Uint8Array(await crypto.subtle.digest('SHA-256', data));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

// Just enough CBOR for an attestation object and a COSE key.
function cborHead(major, n) {
  if (n < 24) return Uint8Array.of((major << 5) | n);
  if (n < 256) return Uint8Array.of((major << 5) | 24, n);
  if (n < 65536) return Uint8Array.of((major << 5) | 25, n >> 8, n & 255);
  return Uint8Array.of((major << 5) | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255);
}
function cbor(v) {
  if (typeof v === 'number') return v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v);
  if (typeof v === 'string') { const b = enc.encode(v); return concat(cborHead(3, b.length), b); }
  if (v instanceof Uint8Array) return concat(cborHead(2, v.length), v);
  if (v instanceof Map) {
    const parts = [cborHead(5, v.size)];
    for (const [k, val] of v) parts.push(cbor(k), cbor(val));
    return concat(...parts);
  }
  throw new Error('cbor: unsupported ' + typeof v);
}

// WebCrypto signs ECDSA as raw r||s; WebAuthn wants DER.
function rawToDer(raw) {
  const int = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    b = b.slice(i);
    if (b[0] & 0x80) b = concat(Uint8Array.of(0), b);
    return concat(Uint8Array.of(0x02, b.length), b);
  };
  const r = int(raw.slice(0, 32));
  const s = int(raw.slice(32));
  return concat(Uint8Array.of(0x30, r.length + s.length), r, s);
}

export class SoftAuthenticator {
  constructor(origin) {
    this.origin = origin;
    this.rpId = new URL(origin).hostname;
    this.counter = 0;
  }

  async create(options) {
    this.keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    this.credId = crypto.getRandomValues(new Uint8Array(16));
    this.userHandle = fromB64u(options.user.id);
    const jwk = await crypto.subtle.exportKey('jwk', this.keys.publicKey);
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, fromB64u(jwk.x)], [-3, fromB64u(jwk.y)]]));
    const clientDataJSON = enc.encode(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin: this.origin, crossOrigin: false }));
    const rpIdHash = await sha256(enc.encode(options.rp?.id || this.rpId));
    const counter = Uint8Array.of(0, 0, 0, this.counter);
    const attested = concat(new Uint8Array(16), Uint8Array.of(0, this.credId.length), this.credId, cose);
    const authData = concat(rpIdHash, Uint8Array.of(0x45), counter, attested); // UP | UV | AT
    const attestationObject = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
    return {
      id: b64u(this.credId), rawId: b64u(this.credId), type: 'public-key',
      clientExtensionResults: {}, authenticatorAttachment: 'platform',
      response: { clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(attestationObject), transports: ['internal'] },
    };
  }

  async get(options) {
    this.counter++;
    const clientDataJSON = enc.encode(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin: this.origin, crossOrigin: false }));
    const rpIdHash = await sha256(enc.encode(options.rpId || this.rpId));
    const authData = concat(rpIdHash, Uint8Array.of(0x05), Uint8Array.of(0, 0, 0, this.counter)); // UP | UV
    const signed = concat(authData, await sha256(clientDataJSON));
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.keys.privateKey, signed));
    return {
      id: b64u(this.credId), rawId: b64u(this.credId), type: 'public-key',
      clientExtensionResults: {}, authenticatorAttachment: 'platform',
      response: {
        clientDataJSON: b64u(clientDataJSON), authenticatorData: b64u(authData),
        signature: b64u(rawToDer(raw)), userHandle: b64u(this.userHandle),
      },
    };
  }
}

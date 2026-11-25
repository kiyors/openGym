export interface Env {
  DB: D1Database;
  ASSETS?: Fetcher;
  MEDIA?: R2Bucket;

  // Secrets (set via `wrangler secret put`)
  SESSION_SECRET: string;
  ENC_KEY?: string;

  // Public vars (wrangler.jsonc)
  RP_ID?: string;
  ORIGIN?: string;
  RP_NAME?: string;
  SESSION_DAYS?: string;
  FIRST_USER_ADMIN?: string;
  INVITE_ONLY?: string;
  ALLOW_GUEST?: string;
  PASSWORD_LOGIN?: string;
  API_TOKENS?: string;
  MCP?: string;
  MEDIA_UPLOADS?: string;
  INTEGRATIONS?: string;
  AUDIT_LOG?: string;
  AUDIT_IP?: string;
  ADMIN_UIDS?: string;
  ADMIN_DATA_VIEW?: string;
  DEFAULT_LANG?: string;
  SESSION_SAMESITE?: string;
}

export function flagOn(value: string | undefined, defaultOn = false): boolean {
  if (value === undefined || value === '') return defaultOn;
  return /^(1|true|yes|on)$/i.test(value.trim());
}

export function resolveOrigin(env: Env, req: Request): string {
  if (env.ORIGIN && env.ORIGIN.trim()) {
    return env.ORIGIN.trim().replace(/\/+$/, '');
  }
  return new URL(req.url).origin;
}

export function resolveRpId(env: Env, req: Request): string {
  if (env.RP_ID && env.RP_ID.trim()) {
    return env.RP_ID.trim();
  }
  return new URL(req.url).hostname;
}

export function resolveRpName(env: Env): string {
  return (env.RP_NAME || 'openGym').trim();
}

export function resolveSessionDays(env: Env): number {
  const n = Number(env.SESSION_DAYS || 90);
  return Number.isFinite(n) && n >= 1 ? Math.floor(n) : 90;
}

export function adminUidSet(env: Env): Set<string> {
  return new Set(
    (env.ADMIN_UIDS || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
  );
}

export function webhookEnabled(env: Env): boolean {
  return (env.INTEGRATIONS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .includes('webhook');
}

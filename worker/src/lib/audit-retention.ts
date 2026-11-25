import { Env } from '../env';

/** AUDIT_MAX / AUDIT_DAYS as upstream reads them (api/server.js): 0 means "no cap". */
export function auditRetention(env: Env): { max: number; days: number } {
  const e = env as unknown as Record<string, string | undefined>;
  return {
    max: Math.max(0, +(e.AUDIT_MAX || 5000) || 0),
    days: Math.max(0, +(e.AUDIT_DAYS || 90) || 0),
  };
}

/**
 * Retention is a cap, not an archive: age first, then the newest AUDIT_MAX of what is left
 * (upstream auditKeep). Cheap: two indexed deletes that usually touch nothing.
 */
export async function pruneAudit(env: Env): Promise<void> {
  const { max, days } = auditRetention(env);
  try {
    if (days) {
      await env.DB.prepare('DELETE FROM audit_log WHERE ts < ?')
        .bind(Date.now() - days * 86_400_000)
        .run();
    }
    if (max) {
      await env.DB.prepare(
        'DELETE FROM audit_log WHERE id <= (SELECT id FROM audit_log ORDER BY id DESC LIMIT 1 OFFSET ?)'
      )
        .bind(max)
        .run();
    }
  } catch (e) {
    console.error('audit prune failed', e);
  }
}

-- openGym Cloudflare D1 initial schema (Phases 1-4)
PRAGMA foreign_keys = ON;

-- 1. User accounts & roles (replaces users[] in db.json)
CREATE TABLE IF NOT EXISTS users (
  uid TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  email TEXT UNIQUE,
  session_version INTEGER NOT NULL DEFAULT 1,
  is_admin INTEGER NOT NULL DEFAULT 0,
  is_owner INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  invited_by TEXT,
  last_pull INTEGER,
  created_at TEXT NOT NULL
);

-- 2. WebAuthn passkeys (multiple passkeys per profile)
CREATE TABLE IF NOT EXISTS passkeys (
  credential_id TEXT PRIMARY KEY,
  uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  device_type TEXT,
  backed_up INTEGER NOT NULL DEFAULT 0,
  transports_json TEXT,
  label TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_passkeys_uid ON passkeys(uid);

-- 3. Per-user workout/app state JSON with atomic compare-and-swap revision
CREATE TABLE IF NOT EXISTS user_states (
  uid TEXT PRIMARY KEY REFERENCES users(uid) ON DELETE CASCADE,
  rev INTEGER NOT NULL DEFAULT 0,
  wid TEXT,
  state_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

-- 4. Admin invite codes
CREATE TABLE IF NOT EXISTS invites (
  code TEXT PRIMARY KEY,
  note TEXT NOT NULL DEFAULT '',
  created_by TEXT,
  used_by TEXT REFERENCES users(uid) ON DELETE SET NULL,
  used_at TEXT,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

-- 5. Short-lived codes: WebAuthn challenges, 5-min mobile pair codes,
--    device-link/recovery codes, OAuth pending requests, and OAuth auth codes
CREATE TABLE IF NOT EXISTS ephemeral_codes (
  code TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  uid TEXT REFERENCES users(uid) ON DELETE CASCADE,
  payload_json TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ephemeral_exp ON ephemeral_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_ephemeral_kind_uid ON ephemeral_codes(kind, uid);

-- 6. OAuth 2.1 dynamically registered MCP clients (RFC 7591)
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  redirects_json TEXT NOT NULL,
  grants_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);

-- 7. Scoped API tokens & OAuth 2.1 MCP tokens (only SHA-256 hashes stored)
CREATE TABLE IF NOT EXISTS api_tokens (
  id TEXT PRIMARY KEY,
  token_sha256 TEXT UNIQUE NOT NULL,
  uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  session_version INTEGER NOT NULL DEFAULT 1,
  hint TEXT NOT NULL,
  label TEXT NOT NULL,
  scopes_json TEXT NOT NULL,
  kind TEXT,
  connector_json TEXT,
  refresh_sha256 TEXT UNIQUE,
  prev_refresh_sha256 TEXT,
  rotated_at INTEGER,
  access_expires_at INTEGER,
  expires_at INTEGER,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_uid ON api_tokens(uid);
CREATE INDEX IF NOT EXISTS idx_api_tokens_refresh ON api_tokens(refresh_sha256);

-- 8. Optional custom media metadata index (bytes live in R2 if MEDIA_UPLOADS=1)
CREATE TABLE IF NOT EXISTS media_objects (
  uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  sha256 TEXT NOT NULL,
  mime TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  r2_key TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  deleted_at INTEGER,
  PRIMARY KEY (uid, sha256)
);

-- 9. Admin & security audit log (replaces audit.log)
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  uid TEXT,
  name TEXT,
  tgt TEXT,
  tname TEXT,
  action TEXT NOT NULL,
  ok INTEGER NOT NULL DEFAULT 1,
  msg TEXT,
  ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

-- 10. AI Coach instance settings & per-user chat/proposal state
CREATE TABLE IF NOT EXISTS coach_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  enabled INTEGER NOT NULL DEFAULT 0,
  active_provider TEXT NOT NULL DEFAULT 'gemini',
  config_json TEXT NOT NULL DEFAULT '{}',
  providers_enc_json TEXT NOT NULL DEFAULT '{}',
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS coach_threads (
  uid TEXT PRIMARY KEY REFERENCES users(uid) ON DELETE CASCADE,
  intake_json TEXT,
  messages_json TEXT NOT NULL DEFAULT '[]',
  pending_json TEXT,
  updated_at INTEGER NOT NULL
);

-- 11. Outbound webhooks (Home Assistant, n8n, ntfy, custom)
CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY,
  uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  label TEXT NOT NULL,
  url TEXT NOT NULL,
  secret_enc TEXT NOT NULL,
  events_json TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_status INTEGER,
  last_error TEXT,
  last_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webhooks_uid ON webhooks(uid);

CREATE TABLE IF NOT EXISTS webhook_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  webhook_id TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  status INTEGER,
  ok INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webhook_logs_uid ON webhook_logs(uid, created_at);

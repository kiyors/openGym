-- Integrations (webhook provider) and the calendar feed, matching api/integrations/.
-- 0001 already has `webhooks` and `webhook_logs`. For a webhook, `url` now holds the MASKED address
-- (what the app may show) and `url_enc` the sealed full address; `enabled = 0` means paused.
ALTER TABLE webhooks ADD COLUMN url_enc TEXT;
ALTER TABLE webhooks ADD COLUMN status TEXT NOT NULL DEFAULT 'ok';
ALTER TABLE webhooks ADD COLUMN failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE webhooks ADD COLUMN last_ok INTEGER;
ALTER TABLE webhooks ADD COLUMN updated_at INTEGER;

-- Delivery duration for the log lines.
ALTER TABLE webhook_logs ADD COLUMN ms INTEGER;

-- The outbox: every delivery owed is a row first. `key` is the idempotency key, so the same
-- workout pushed twice (two devices, a retried sync) is delivered once. state: queued | failed | done.
CREATE TABLE IF NOT EXISTS webhook_outbox (
  id TEXT PRIMARY KEY,
  key TEXT NOT NULL UNIQUE,
  uid TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  conn TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  ev TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'queued',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_at INTEGER NOT NULL,
  msg TEXT,
  created_at INTEGER NOT NULL,
  done_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_outbox_due ON webhook_outbox(state, next_at);
CREATE INDEX IF NOT EXISTS idx_outbox_conn ON webhook_outbox(uid, conn, state);

-- The calendar feed's token, sealed so Settings can show the address again.
ALTER TABLE api_tokens ADD COLUMN seal_enc TEXT;

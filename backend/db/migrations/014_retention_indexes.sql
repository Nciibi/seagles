-- Retention policy indexes for efficient data purging

CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at);
CREATE INDEX IF NOT EXISTS idx_alerts_triggered_at ON alerts(triggered_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_delivered_at ON webhook_deliveries(delivered_at);

-- Session tracking: add ip_address and user_agent to refresh_tokens
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS ip_address TEXT DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS user_agent TEXT DEFAULT '';

-- Webhook configuration table for SIEM & ChatOps integration
CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    webhook_type TEXT NOT NULL CHECK (webhook_type IN ('slack', 'teams', 'generic', 'syslog')),
    min_severity TEXT NOT NULL DEFAULT 'high' CHECK (min_severity IN ('critical', 'high', 'medium', 'low')),
    is_active BOOLEAN DEFAULT TRUE,
    secret TEXT,
    headers JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_triggered TIMESTAMPTZ
);

-- Webhook delivery log for audit trail
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id UUID REFERENCES webhooks(id) ON DELETE CASCADE,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    status_code INT,
    response_body TEXT,
    error TEXT,
    delivered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhooks_active ON webhooks(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id, delivered_at DESC);

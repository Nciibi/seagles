CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'running',
    scan_type TEXT NOT NULL DEFAULT 'full',
    open_ports JSONB,
    services JSONB,
    scan_output TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_device ON scans(device_id, started_at DESC);

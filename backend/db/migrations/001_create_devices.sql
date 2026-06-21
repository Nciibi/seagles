CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address INET NOT NULL,
    mac_address MACADDR,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT DEFAULT 'unknown',
    os_fingerprint TEXT,
    firmware_version TEXT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    risk_score NUMERIC(3,1) DEFAULT 0.0,
    is_active BOOLEAN DEFAULT TRUE,
    tags TEXT[],
    raw_nmap JSONB,
    UNIQUE(ip_address)
);

CREATE INDEX IF NOT EXISTS idx_devices_risk ON devices(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_devices_active ON devices(is_active, last_seen DESC);

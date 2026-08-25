-- Safelists table: IP/CIDR/MAC exclusions for active scanning
CREATE TABLE IF NOT EXISTS safelists (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entry_type TEXT NOT NULL CHECK (entry_type IN ('ip', 'cidr', 'mac')),
    value TEXT NOT NULL,
    reason TEXT,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    UNIQUE(entry_type, value)
);

-- Scan profiles table: configurable scan intensity
CREATE TABLE IF NOT EXISTS scan_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    skip_credential_test BOOLEAN DEFAULT FALSE,
    skip_protocol_probe BOOLEAN DEFAULT FALSE,
    max_port_count INT DEFAULT 11,
    timeout_seconds INT DEFAULT 90,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Scan scope configuration (replaces NETWORK_CIDR env var)
CREATE TABLE IF NOT EXISTS scan_scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cidr TEXT NOT NULL,
    label TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Insert default scan profiles
INSERT INTO scan_profiles (name, description, skip_credential_test, skip_protocol_probe, is_default)
VALUES
    ('aggressive', 'Full scan — port discovery, credential testing, protocol probing, TLS checks', FALSE, FALSE, TRUE),
    ('gentle', 'Gentle scan — port discovery only, no credential testing (safe for fragile ICS/IoMT devices)', TRUE, TRUE, FALSE),
    ('standard', 'Standard scan — port discovery and protocol probing, no credential testing', TRUE, FALSE, FALSE)
ON CONFLICT (name) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_safelists_active ON safelists(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_scan_scopes_active ON scan_scopes(is_active) WHERE is_active = TRUE;

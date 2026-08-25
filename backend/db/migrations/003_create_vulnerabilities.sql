CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    cve_id TEXT,
    cvss_score NUMERIC(3,1),
    severity TEXT NOT NULL DEFAULT 'medium',
    title TEXT NOT NULL,
    description TEXT,
    affected_component TEXT,
    remediation TEXT,
    is_kev BOOLEAN DEFAULT FALSE,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    is_resolved BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_vulns_device ON vulnerabilities(device_id, severity);
CREATE INDEX IF NOT EXISTS idx_vulns_kev ON vulnerabilities(is_kev) WHERE is_kev = TRUE;
CREATE INDEX IF NOT EXISTS idx_vulns_unresolved ON vulnerabilities(is_resolved) WHERE is_resolved = FALSE;

CREATE TABLE IF NOT EXISTS firmware (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    version TEXT,
    vendor TEXT,
    checksum TEXT,
    file_path TEXT,
    analyzed_at TIMESTAMPTZ,
    entropy_score NUMERIC(5,4),
    has_default_creds BOOLEAN DEFAULT FALSE,
    has_telnet BOOLEAN DEFAULT FALSE,
    has_backdoor_indicators BOOLEAN DEFAULT FALSE,
    strings_of_interest TEXT[],
    cve_matches TEXT[],
    analysis_status TEXT DEFAULT 'pending',
    analysis_report JSONB
);

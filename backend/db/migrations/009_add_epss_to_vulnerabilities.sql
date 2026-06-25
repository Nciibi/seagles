-- Add EPSS (Exploit Prediction Scoring System) columns to vulnerabilities
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS epss_score NUMERIC(5,4);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS epss_percentile NUMERIC(5,4);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS epss_updated_at TIMESTAMPTZ;

-- Add audit trail columns to alerts for webhook tracking
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS webhook_sent BOOLEAN DEFAULT FALSE;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS webhook_sent_at TIMESTAMPTZ;

-- Add scan_profile_id to scans for tracking which profile was used
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_profile_id UUID REFERENCES scan_profiles(id);

-- Add firmware upload support columns
ALTER TABLE firmware ADD COLUMN IF NOT EXISTS file_size_bytes BIGINT;
ALTER TABLE firmware ADD COLUMN IF NOT EXISTS original_filename TEXT;
ALTER TABLE firmware ADD COLUMN IF NOT EXISTS upload_source TEXT DEFAULT 'scan';

CREATE INDEX IF NOT EXISTS idx_vulns_epss ON vulnerabilities(epss_score DESC NULLS LAST) WHERE epss_score IS NOT NULL;

-- Migration 010: Add performance indexes for common query patterns

-- Devices
CREATE INDEX IF NOT EXISTS idx_devices_risk_score ON devices (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_devices_ip_address ON devices (ip_address);
CREATE INDEX IF NOT EXISTS idx_devices_device_type ON devices (device_type);
CREATE INDEX IF NOT EXISTS idx_devices_is_active ON devices (is_active);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices (last_seen);

-- Vulnerabilities
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_device_id ON vulnerabilities (device_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities (severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_is_resolved ON vulnerabilities (is_resolved);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_is_kev ON vulnerabilities (is_kev);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities (cve_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_discovered_at ON vulnerabilities (discovered_at);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_device_severity ON vulnerabilities (device_id, severity, is_resolved);

-- Scans
CREATE INDEX IF NOT EXISTS idx_scans_device_id ON scans (device_id);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status);

-- Alerts
CREATE INDEX IF NOT EXISTS idx_alerts_device_id ON alerts (device_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_is_acknowledged ON alerts (is_acknowledged);
CREATE INDEX IF NOT EXISTS idx_alerts_triggered_at ON alerts (triggered_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_device_acknowledged ON alerts (device_id, alert_type, is_acknowledged);

-- Firmware
CREATE INDEX IF NOT EXISTS idx_firmware_device_id ON firmware (device_id);
CREATE INDEX IF NOT EXISTS idx_firmware_analysis_status ON firmware (analysis_status);
CREATE INDEX IF NOT EXISTS idx_firmware_analyzed_at ON firmware (analyzed_at DESC);

-- Webhook deliveries
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_id ON webhook_deliveries (webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_alert_id ON webhook_deliveries (alert_id);

-- Users
CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);

package alerts

import (
	"database/sql"
	"encoding/json"
	"log"
	"time"
)

// Alert type constants
const (
	AlertDefaultCreds       = "default_creds"
	AlertKEVMatch           = "kev_match"
	AlertTelnetOpen         = "telnet_open"
	AlertADBExposed         = "adb_exposed"
	AlertPlaintextMQTT      = "plaintext_mqtt"
	AlertUnauthRTSP         = "unauth_rtsp"
	AlertNewDevice          = "new_device"
	AlertDeviceOffline      = "device_offline"
	AlertFirmwareEntropy    = "firmware_entropy"
	AlertWeakTLS            = "tls_weak"
	AlertCertExpiring       = "cert_expiring"
	AlertLockedOut          = "lockout_detected"
	AlertCriticalUnresolved = "critical_vuln_unresolved"
	AlertFirmwareReview     = "firmware_review_due"
)

// AlertRequest contains the data needed to create an alert.
type AlertRequest struct {
	DeviceID    string          `json:"device_id"`
	AlertType   string          `json:"alert_type"`
	Severity    string          `json:"severity"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
}

// CreateAlert creates an alert with 24-hour deduplication and dispatches webhooks.
func CreateAlert(db *sql.DB, req AlertRequest) error {
	// Deduplication check: same type + device + unacknowledged within 24 hours
	var existing int
	err := db.QueryRow(`SELECT COUNT(*) FROM alerts
		WHERE device_id = $1 AND alert_type = $2 AND is_acknowledged = FALSE
		AND triggered_at > NOW() - INTERVAL '24 hours'`,
		req.DeviceID, req.AlertType).Scan(&existing)
	if err == nil && existing > 0 {
		log.Printf("Alert deduplicated: %s for device %s", req.AlertType, req.DeviceID)
		return nil
	}

	// Insert alert
	metadata := req.Metadata
	if metadata == nil {
		metadata = json.RawMessage(`{}`)
	}

	var alertID string
	err = db.QueryRow(`INSERT INTO alerts (device_id, severity, alert_type, title, description, metadata)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		req.DeviceID, req.Severity, req.AlertType, req.Title, req.Description, metadata).Scan(&alertID)
	if err != nil {
		log.Printf("Failed to create alert: %v", err)
		return err
	}

	log.Printf("[ALERT] %s | %s | %s | device: %s", req.Severity, req.AlertType, req.Title, req.DeviceID)

	// Dispatch webhooks asynchronously
	go DispatchWebhooks(db, alertID, req.Severity, req.Title, req.Description, req.DeviceID)

	return nil
}

// StartAlertMonitor runs background checks every 60 seconds.
func StartAlertMonitor(db *sql.DB) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		checkOfflineDevices(db)
		checkFirmwareOverdue(db)
		checkUnresolvedCritical(db)
	}
}

// checkOfflineDevices alerts for devices not seen in 30+ minutes.
func checkOfflineDevices(db *sql.DB) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("checkOfflineDevices panic: %v", r)
		}
	}()

	rows, err := db.Query(`SELECT id, ip_address FROM devices
		WHERE is_active = TRUE AND last_seen < NOW() - INTERVAL '30 minutes'`)
	if err != nil {
		log.Printf("Offline device check failed: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var deviceID, ip string
		if err := rows.Scan(&deviceID, &ip); err != nil {
			continue
		}
		CreateAlert(db, AlertRequest{
			DeviceID:    deviceID,
			AlertType:   AlertDeviceOffline,
			Severity:    "medium",
			Title:       "Device offline: " + ip,
			Description: "Device has not been seen for more than 30 minutes",
		})
	}
}

// checkFirmwareOverdue alerts for firmware not analyzed in 90+ days.
func checkFirmwareOverdue(db *sql.DB) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("checkFirmwareOverdue panic: %v", r)
		}
	}()

	rows, err := db.Query(`SELECT device_id FROM firmware
		WHERE analyzed_at < NOW() - INTERVAL '90 days' OR analyzed_at IS NULL`)
	if err != nil {
		log.Printf("Firmware review check failed: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var deviceID sql.NullString
		if err := rows.Scan(&deviceID); err != nil || !deviceID.Valid {
			continue
		}
		CreateAlert(db, AlertRequest{
			DeviceID:    deviceID.String,
			AlertType:   AlertFirmwareReview,
			Severity:    "low",
			Title:       "Firmware analysis overdue",
			Description: "Firmware has not been analyzed in 90+ days",
		})
	}
}

// checkUnresolvedCritical alerts for critical vulnerabilities unresolved for 7+ days.
func checkUnresolvedCritical(db *sql.DB) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("checkUnresolvedCritical panic: %v", r)
		}
	}()

	rows, err := db.Query(`SELECT DISTINCT device_id FROM vulnerabilities
		WHERE severity = 'critical' AND is_resolved = FALSE
		AND discovered_at < NOW() - INTERVAL '7 days'`)
	if err != nil {
		log.Printf("Unresolved critical check failed: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var deviceID sql.NullString
		if err := rows.Scan(&deviceID); err != nil || !deviceID.Valid {
			continue
		}
		CreateAlert(db, AlertRequest{
			DeviceID:    deviceID.String,
			AlertType:   AlertCriticalUnresolved,
			Severity:    "high",
			Title:       "Critical vulnerability unresolved for 7+ days",
			Description: "A critical severity vulnerability has been open for more than 7 days",
		})
	}
}

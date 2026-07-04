package alerts

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/yourusername/seagles/slog"
)

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

type AlertRequest struct {
	DeviceID    string          `json:"device_id"`
	AlertType   string          `json:"alert_type"`
	Severity    string          `json:"severity"`
	Title       string          `json:"title"`
	Description string          `json:"description,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
}

func CreateAlert(db *sql.DB, req AlertRequest) error {
	var existing int
	err := db.QueryRow(`SELECT COUNT(*) FROM alerts
		WHERE device_id = $1 AND alert_type = $2 AND is_acknowledged = FALSE
		AND triggered_at > NOW() - INTERVAL '24 hours'`,
		req.DeviceID, req.AlertType).Scan(&existing)
	if err == nil && existing > 0 {
		slog.Debug("alert_deduplicated", "type", req.AlertType, "device", req.DeviceID)
		return nil
	}

	metadata := req.Metadata
	if metadata == nil {
		metadata = json.RawMessage(`{}`)
	}

	var alertID string
	err = db.QueryRow(`INSERT INTO alerts (device_id, severity, alert_type, title, description, metadata)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		req.DeviceID, req.Severity, req.AlertType, req.Title, req.Description, metadata).Scan(&alertID)
	if err != nil {
		slog.Error("Failed to create alert", "error", err.Error())
		return err
	}

	slog.Info("alert_created", "severity", req.Severity, "type", req.AlertType, "device", req.DeviceID, "title", req.Title)

	go DispatchWebhooks(db, alertID, req.Severity, req.Title, req.Description, req.DeviceID)

	return nil
}

func StartAlertMonitor(db *sql.DB) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		checkOfflineDevices(db)
		checkFirmwareOverdue(db)
		checkUnresolvedCritical(db)
	}
}

func checkOfflineDevices(db *sql.DB) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("checkOfflineDevices panic", "recover", r)
		}
	}()

	rows, err := db.Query(`SELECT id, ip_address FROM devices
		WHERE is_active = TRUE AND last_seen < NOW() - INTERVAL '30 minutes'`)
	if err != nil {
		slog.Error("Offline device check failed", "error", err.Error())
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

func checkFirmwareOverdue(db *sql.DB) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("checkFirmwareOverdue panic", "recover", r)
		}
	}()

	rows, err := db.Query(`SELECT device_id FROM firmware
		WHERE analyzed_at < NOW() - INTERVAL '90 days' OR analyzed_at IS NULL`)
	if err != nil {
		slog.Error("Firmware review check failed", "error", err.Error())
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

func checkUnresolvedCritical(db *sql.DB) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("checkUnresolvedCritical panic", "recover", r)
		}
	}()

	rows, err := db.Query(`SELECT DISTINCT device_id FROM vulnerabilities
		WHERE severity = 'critical' AND is_resolved = FALSE
		AND discovered_at < NOW() - INTERVAL '7 days'`)
	if err != nil {
		slog.Error("Unresolved critical check failed", "error", err.Error())
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

package alerts

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/Nciibi/seagles/events"
	"github.com/Nciibi/seagles/slog"
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

	// DefaultTenantID matches auth.DefaultTenantID. Kept local to avoid an
	// alerts -> auth dependency; alert callers should set TenantID explicitly.
	DefaultTenantID = "00000000-0000-0000-0000-000000000001"
)

type AlertRequest struct {
	TenantID    string          `json:"tenant_id,omitempty"`
	DeviceID    string          `json:"device_id"`
	AlertType   string          `json:"alert_type"`
	Severity    string          `json:"severity"`
	Title       string          `json:"title"`
	Description string          `json:"description,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
}

// AlertEvent is the real-time payload broadcast when an alert is persisted.
type AlertEvent struct {
	ID          string    `json:"id"`
	DeviceID    string    `json:"device_id"`
	AlertType   string    `json:"alert_type"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	TriggeredAt time.Time `json:"triggered_at"`
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
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = DefaultTenantID
	}
	err = db.QueryRow(`INSERT INTO alerts (tenant_id, device_id, severity, alert_type, title, description, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		tenantID, req.DeviceID, req.Severity, req.AlertType, req.Title, req.Description, metadata).Scan(&alertID)
	if err != nil {
		slog.Error("Failed to create alert", "error", err.Error())
		return err
	}

	slog.Info("alert_created", "severity", req.Severity, "type", req.AlertType, "device", req.DeviceID, "title", req.Title)

	events.Publish(events.Event{Type: events.AlertCreated, Data: AlertEvent{
		ID:          alertID,
		DeviceID:    req.DeviceID,
		AlertType:   req.AlertType,
		Severity:    req.Severity,
		Title:       req.Title,
		Description: req.Description,
		TriggeredAt: time.Now().UTC(),
	}})

	go DispatchWebhooks(db, alertID, req.Severity, req.Title, req.Description, req.DeviceID)

	return nil
}

func StartAlertMonitor(db *sql.DB, stop <-chan struct{}) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			slog.Info("Alert monitor stopped")
			return
		case <-ticker.C:
			checkOfflineDevices(db)
			checkFirmwareOverdue(db)
			checkUnresolvedCritical(db)
		}
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
	if err := rows.Err(); err != nil {
		log.Printf("Error iterating alerts for engine: %v", err)
		return
	}
}

func checkFirmwareOverdue(db *sql.DB) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("checkFirmwareOverdue panic", "recover", r)
		}
	}()

	// A pending (never analyzed) firmware is not "overdue" — it is simply
	// queued. Only flag images whose analysis happened long ago.
	rows, err := db.Query(`SELECT device_id FROM firmware
		WHERE analyzed_at IS NOT NULL AND analyzed_at < NOW() - INTERVAL '90 days'`)
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
	if err := rows.Err(); err != nil {
		log.Printf("Error iterating alerts for engine: %v", err)
		return
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
	if err := rows.Err(); err != nil {
		log.Printf("Error iterating alerts for engine: %v", err)
		return
	}
}

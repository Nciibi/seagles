package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/Nciibi/seagles/alerts"
	"github.com/Nciibi/seagles/config"
	"github.com/Nciibi/seagles/kev"
	"github.com/Nciibi/seagles/models"
	"github.com/Nciibi/seagles/risk"
	"github.com/Nciibi/seagles/scanner"
	"github.com/Nciibi/seagles/slog"
)

type TriggerScanRequest struct {
	ProfileID string `json:"profile_id" binding:"omitempty,uuid"`
	ScanType  string `json:"scan_type" binding:"omitempty,oneof=full quick"`
}

func ListScansHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID, _ := c.Get("request_id")

		rows, err := db.Query(`SELECT id, device_id, started_at, completed_at, status,
			scan_type, open_ports, services, scan_output
			FROM scans ORDER BY started_at DESC LIMIT 100`)
		if err != nil {
			slog.Error("Failed to query scans", "request_id", requestID, "error", err.Error())
			fail(c, 500, "Failed to query scans: "+err.Error())
			return
		}
		defer rows.Close()

		var scans []models.ScanJSON
		for rows.Next() {
			var s models.Scan
			if err := rows.Scan(&s.ID, &s.DeviceID, &s.StartedAt, &s.CompletedAt,
				&s.Status, &s.ScanType, &s.OpenPorts, &s.Services, &s.ScanOutput); err != nil {
				continue
			}
			scans = append(scans, s.ToJSON())
		}
		if err := rows.Err(); err != nil {
			fail(c, 500, "Failed to iterate scans: "+err.Error())
			return
		}
		if scans == nil {
			scans = []models.ScanJSON{}
		}
		success(c, scans)
	}
}

func GetScanHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID, _ := c.Get("request_id")
		id := c.Param("id")

		var s models.Scan
		err := db.QueryRow(`SELECT id, device_id, started_at, completed_at, status,
			scan_type, open_ports, services, scan_output
			FROM scans WHERE id = $1`, id).Scan(
			&s.ID, &s.DeviceID, &s.StartedAt, &s.CompletedAt,
			&s.Status, &s.ScanType, &s.OpenPorts, &s.Services, &s.ScanOutput)
		if err == sql.ErrNoRows {
			fail(c, 404, "Scan not found")
			return
		}
		if err != nil {
			slog.Error("Failed to query scan", "request_id", requestID, "scan_id", id, "error", err.Error())
			fail(c, 500, "Failed to query scan: "+err.Error())
			return
		}

		result := gin.H{"scan": s.ToJSON()}
		if s.DeviceID.Valid {
			var d models.Device
			if err := db.QueryRow(`SELECT id, ip_address, mac_address, hostname, vendor,
				device_type, os_fingerprint, firmware_version, first_seen, last_seen,
				risk_score, is_active, tags, raw_nmap
				FROM devices WHERE id = $1`, s.DeviceID.String).Scan(
				&d.ID, &d.IPAddress, &d.MACAddress, &d.Hostname, &d.Vendor,
				&d.DeviceType, &d.OSFingerprint, &d.FirmwareVersion,
				&d.FirstSeen, &d.LastSeen, &d.RiskScore, &d.IsActive,
				&d.Tags, &d.RawNmap); err == nil {
				result["device"] = d.ToJSON()
			}
		}
		success(c, result)
	}
}

func TriggerDeviceScanHandler(db *sql.DB, cfg *config.Config, kevCatalog *kev.KEVCatalog) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID, _ := c.Get("request_id")
		deviceID := c.Param("id")

		var ip string
		err := db.QueryRow(`SELECT ip_address FROM devices WHERE id = $1`, deviceID).Scan(&ip)
		if err == sql.ErrNoRows {
			fail(c, 404, "Device not found")
			return
		}
		if err != nil {
			slog.Error("Failed to query device", "request_id", requestID, "device_id", deviceID, "error", err.Error())
			fail(c, 500, "Failed to query device: "+err.Error())
			return
		}

		// The request body is optional; previously it was defined but never
		// bound, so scan_type / profile_id were silently ignored.
		var req TriggerScanRequest
		if err := c.ShouldBindJSON(&req); err != nil && err.Error() != "EOF" {
			fail(c, 400, "Invalid request body: "+err.Error())
			return
		}
		scanType := req.ScanType
		if scanType == "" {
			scanType = "full"
		}

		var scanID string
		err = db.QueryRow(`INSERT INTO scans (device_id, status, scan_type, scan_profile_id) VALUES ($1, 'running', $2, $3) RETURNING id`,
			deviceID, scanType, nullableString(req.ProfileID)).Scan(&scanID)
		if err != nil {
			slog.Error("Failed to create scan", "request_id", requestID, "device_id", deviceID, "error", err.Error())
			fail(c, 500, "Failed to create scan: "+err.Error())
			return
		}

		slog.Info("Scan triggered", "request_id", requestID, "device_id", deviceID, "ip", ip, "scan_id", scanID)

		go runDeviceScan(db, cfg, kevCatalog, deviceID, scanID, ip)

		success(c, gin.H{"scan_id": scanID, "status": "running"})
	}
}

func runDeviceScan(db *sql.DB, cfg *config.Config, kevCatalog *kev.KEVCatalog, deviceID, scanID, ip string) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Scan goroutine panicked", "device_id", deviceID, "recover", r)
			db.Exec(`UPDATE scans SET status='failed', completed_at=NOW() WHERE id=$1`, scanID)
		}
	}()

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		slog.Error("Failed to begin transaction", "error", err.Error())
		db.Exec(`UPDATE scans SET status='failed', completed_at=NOW() WHERE id=$1`, scanID)
		return
	}
	defer tx.Rollback()

	if IsSafelisted(db, ip) {
		slog.Info("Scan skipped: IP is safelisted", "ip", ip)
		tx.Exec(`UPDATE scans SET status='skipped', scan_output='Device is safelisted', completed_at=NOW() WHERE id=$1`, scanID)
		tx.Commit()
		return
	}

	startTime := time.Now()
	result, err := scanner.DeepScan(ip)
	if err != nil {
		slog.Error("Deep scan failed", "ip", ip, "error", err.Error())
		tx.Exec(`UPDATE scans SET status='failed', completed_at=NOW() WHERE id=$1`, scanID)
		tx.Commit()
		return
	}

	var openPortNumbers []int
	for _, p := range result.Host.OpenPorts {
		if p.State == "open" {
			openPortNumbers = append(openPortNumbers, p.Number)
		}
	}

	portsJSON, _ := json.Marshal(openPortNumbers)
	servicesJSON, _ := json.Marshal(result.Host.Services)

	tx.Exec(`UPDATE scans SET open_ports=$1, services=$2 WHERE id=$3`,
		portsJSON, servicesJSON, scanID)

	if result.Host.Hostname != "" {
		tx.Exec(`UPDATE devices SET hostname=$1 WHERE id=$2`, result.Host.Hostname, deviceID)
	}
	if result.Host.Vendor != "" {
		tx.Exec(`UPDATE devices SET vendor=$1 WHERE id=$2`, result.Host.Vendor, deviceID)
	}
	if result.Host.OSMatch != "" {
		tx.Exec(`UPDATE devices SET os_fingerprint=$1 WHERE id=$2`, result.Host.OSMatch, deviceID)
	}
	if len(result.Host.RawXML) > 0 {
		tx.Exec(`UPDATE devices SET raw_nmap=$1 WHERE id=$2`, result.Host.RawXML, deviceID)
	}

	findings := scanner.DetectProtocols(ip, openPortNumbers)
	for _, f := range findings {
		var vulnID string
		err := tx.QueryRow(`INSERT INTO vulnerabilities (device_id, scan_id, severity, title, description, affected_component)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
			deviceID, scanID, f.Risk, f.Protocol+" exposure detected", f.Description, fmt.Sprintf("port/%d", f.Port),
		).Scan(&vulnID)
		if err != nil {
			slog.Error("Failed to insert vulnerability", "error", err.Error())
		}

		alerts.CreateAlert(db, alerts.AlertRequest{
			DeviceID:    deviceID,
			AlertType:   protocolToAlertType(f.Protocol),
			Severity:    f.Risk,
			Title:       fmt.Sprintf("%s detected on %s:%d", f.Protocol, ip, f.Port),
			Description: f.Description,
		})
	}

	for _, p := range openPortNumbers {
		if p == 443 {
			tlsResult := scanner.CheckTLS(ip, 443)
			if tlsResult.SupportsTLS10 || tlsResult.SupportsTLS11 || len(tlsResult.WeakCiphers) > 0 {
				tx.QueryRow(`INSERT INTO vulnerabilities (device_id, scan_id, severity, title, description, affected_component)
					VALUES ($1, $2, 'high', 'Weak TLS configuration', 'Device supports deprecated TLS versions or weak ciphers', 'tls')
					RETURNING id`, deviceID, scanID).Scan(new(string))
				alerts.CreateAlert(db, alerts.AlertRequest{
					DeviceID: deviceID, AlertType: alerts.AlertWeakTLS, Severity: "high",
					Title: fmt.Sprintf("Weak TLS on %s:443", ip),
				})
			}
			if tlsResult.CertExpired {
				alerts.CreateAlert(db, alerts.AlertRequest{
					DeviceID: deviceID, AlertType: alerts.AlertCertExpiring, Severity: "medium",
					Title: fmt.Sprintf("Expired TLS certificate on %s:443", ip),
				})
			}
			break
		}
	}

	creds, credErr := scanner.LoadCredentials("data/default-credentials.txt")
	if credErr != nil {
		slog.Warn("Failed to load credentials", "error", credErr.Error())
	} else {
		runCredentialTests(db, deviceID, scanID, ip, openPortNumbers, creds, kevCatalog)
	}

	tx.Exec(`UPDATE scans SET status='complete', completed_at=NOW() WHERE id=$1`, scanID)
	if err := tx.Commit(); err != nil {
		slog.Error("Failed to commit transaction", "error", err.Error())
		db.Exec(`UPDATE scans SET status='failed', completed_at=NOW() WHERE id=$1`, scanID)
		return
	}
	risk.UpdateDeviceRiskScore(db, deviceID)

	slog.Info("Scan complete", "device_id", deviceID, "ip", ip,
		"open_ports", len(openPortNumbers),
		"findings", len(findings),
		"duration", time.Since(startTime).String())
}

func runCredentialTests(db *sql.DB, deviceID, scanID, ip string, ports []int, creds []scanner.Credential, kevCatalog *kev.KEVCatalog) {
	hasPort := func(target int) bool {
		for _, p := range ports {
			if p == target {
				return true
			}
		}
		return false
	}

	var results []scanner.CredentialResult

	if hasPort(22) {
		r := scanner.TestSSHCreds(ip, 22, creds, 50)
		r.Method = "ssh"
		results = append(results, r)
	}
	if hasPort(80) {
		r := scanner.TestHTTPBasicCreds(ip, 80, "/", creds, 50)
		r.Method = "http-basic"
		results = append(results, r)
	}
	if hasPort(23) {
		r := scanner.TestTelnetCreds(ip, 23, creds, 20)
		r.Method = "telnet"
		results = append(results, r)
	}

	for _, r := range results {
		if r.Found {
			db.QueryRow(`INSERT INTO vulnerabilities (device_id, scan_id, severity, cvss_score, title, description, affected_component)
				VALUES ($1, $2, 'critical', 9.5, 'Default credentials active', $3, 'authentication') RETURNING id`,
				deviceID, scanID, fmt.Sprintf("Device accepted login with username: %s via %s", r.Username, r.Method)).Scan(new(string))

			metadata, _ := json.Marshal(map[string]string{"username": r.Username, "method": r.Method})
			alerts.CreateAlert(db, alerts.AlertRequest{
				DeviceID:  deviceID,
				AlertType: alerts.AlertDefaultCreds,
				Severity:  "critical",
				Title:     fmt.Sprintf("Default credentials found on %s", ip),
				Metadata:  metadata,
			})

			db.Exec(`UPDATE devices SET tags = array_append(tags, 'default-creds') WHERE id = $1 AND NOT ('default-creds' = ANY(COALESCE(tags, '{}')))`, deviceID)
		}
		if r.LockedOut {
			slog.Warn("Credential lockout detected", "ip", ip)
			alerts.CreateAlert(db, alerts.AlertRequest{
				DeviceID:  deviceID,
				AlertType: alerts.AlertLockedOut,
				Severity:  "medium",
				Title:     fmt.Sprintf("Account lockout triggered during scan of %s", ip),
			})
			break
		}
	}
}

func protocolToAlertType(protocol string) string {
	switch protocol {
	case "Telnet":
		return alerts.AlertTelnetOpen
	case "ADB":
		return alerts.AlertADBExposed
	case "MQTT-plaintext":
		return alerts.AlertPlaintextMQTT
	case "RTSP-unauth":
		return alerts.AlertUnauthRTSP
	default:
		return protocol
	}
}

func NetworkScanHandler(db *sql.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID, _ := c.Get("request_id")
		slog.Info("Network scan triggered", "request_id", requestID)

		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("PANIC in network scan: %v", r)
				}
			}()
			hosts, err := scanner.DiscoverHosts(cfg.NetworkCIDR)
			if err != nil {
				slog.Error("Network discovery failed", "error", err.Error())
				return
			}

			discovered := 0
			for _, ip := range hosts {
				if IsSafelisted(db, ip) {
					slog.Debug("Skipping safelisted IP", "ip", ip)
					continue
				}

				var deviceID string
				var isNew bool

				err := db.QueryRow(`SELECT id FROM devices WHERE ip_address = $1`, ip).Scan(&deviceID)
				if err == sql.ErrNoRows {
					err = db.QueryRow(`INSERT INTO devices (ip_address) VALUES ($1)
						ON CONFLICT (ip_address) DO UPDATE SET last_seen = NOW()
						RETURNING id`, ip).Scan(&deviceID)
					isNew = true
				} else if err == nil {
					db.Exec(`UPDATE devices SET last_seen = NOW() WHERE id = $1`, deviceID)
				}

				if isNew && deviceID != "" {
					alerts.CreateAlert(db, alerts.AlertRequest{
						DeviceID:  deviceID,
						AlertType: alerts.AlertNewDevice,
						Severity:  "high",
						Title:     fmt.Sprintf("New device discovered: %s", ip),
					})
				}
				discovered++
			}
			slog.Info("Network scan complete", "hosts_discovered", discovered)
		}()

		success(c, gin.H{"message": "network scan started"})
	}
}

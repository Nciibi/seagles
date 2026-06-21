package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/seagles/alerts"
	"github.com/yourusername/seagles/config"
	"github.com/yourusername/seagles/kev"
	"github.com/yourusername/seagles/models"
	"github.com/yourusername/seagles/risk"
	"github.com/yourusername/seagles/scanner"
)

// ListScansHandler returns all scans ordered by started_at DESC.
func ListScansHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := db.Query(`SELECT id, device_id, started_at, completed_at, status,
			scan_type, open_ports, services, scan_output
			FROM scans ORDER BY started_at DESC LIMIT 100`)
		if err != nil {
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
		if scans == nil { scans = []models.ScanJSON{} }
		success(c, scans)
	}
}

// GetScanHandler returns a single scan with its device info.
func GetScanHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
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

// TriggerDeviceScanHandler creates a scan record and launches the scanner in a goroutine.
func TriggerDeviceScanHandler(db *sql.DB, cfg *config.Config, kevCatalog *kev.KEVCatalog) gin.HandlerFunc {
	return func(c *gin.Context) {
		deviceID := c.Param("id")

		// Get device IP
		var ip string
		err := db.QueryRow(`SELECT ip_address FROM devices WHERE id = $1`, deviceID).Scan(&ip)
		if err == sql.ErrNoRows {
			fail(c, 404, "Device not found")
			return
		}
		if err != nil {
			fail(c, 500, "Failed to query device: "+err.Error())
			return
		}

		// Create scan record
		var scanID string
		err = db.QueryRow(`INSERT INTO scans (device_id, status, scan_type) VALUES ($1, 'running', 'full') RETURNING id`,
			deviceID).Scan(&scanID)
		if err != nil {
			fail(c, 500, "Failed to create scan: "+err.Error())
			return
		}

		log.Printf("Scan triggered for device %s (%s)", deviceID, ip)

		// Launch scan goroutine
		go runDeviceScan(db, cfg, kevCatalog, deviceID, scanID, ip)

		success(c, gin.H{"scan_id": scanID, "status": "running"})
	}
}

// runDeviceScan performs a full scan pipeline on a device.
func runDeviceScan(db *sql.DB, cfg *config.Config, kevCatalog *kev.KEVCatalog, deviceID, scanID, ip string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Scan goroutine panicked for device %s: %v", deviceID, r)
			db.Exec(`UPDATE scans SET status='failed', completed_at=NOW() WHERE id=$1`, scanID)
		}
	}()

	// Step 1: Deep scan
	result, err := scanner.DeepScan(ip)
	if err != nil {
		log.Printf("Deep scan failed for %s: %v", ip, err)
		db.Exec(`UPDATE scans SET status='failed', completed_at=NOW() WHERE id=$1`, scanID)
		return
	}

	// Save ports and services
	var openPortNumbers []int
	for _, p := range result.Host.OpenPorts {
		if p.State == "open" {
			openPortNumbers = append(openPortNumbers, p.Number)
		}
	}

	portsJSON, _ := json.Marshal(openPortNumbers)
	servicesJSON, _ := json.Marshal(result.Host.Services)

	db.Exec(`UPDATE scans SET open_ports=$1, services=$2 WHERE id=$3`,
		portsJSON, servicesJSON, scanID)

	// Update device info from scan
	if result.Host.Hostname != "" {
		db.Exec(`UPDATE devices SET hostname=$1 WHERE id=$2`, result.Host.Hostname, deviceID)
	}
	if result.Host.Vendor != "" {
		db.Exec(`UPDATE devices SET vendor=$1 WHERE id=$2`, result.Host.Vendor, deviceID)
	}
	if result.Host.OSMatch != "" {
		db.Exec(`UPDATE devices SET os_fingerprint=$1 WHERE id=$2`, result.Host.OSMatch, deviceID)
	}
	if len(result.Host.RawXML) > 0 {
		db.Exec(`UPDATE devices SET raw_nmap=$1 WHERE id=$2`, result.Host.RawXML, deviceID)
	}

	// Step 2: Protocol detection
	findings := scanner.DetectProtocols(ip, openPortNumbers)
	for _, f := range findings {
		var vulnID string
		err := db.QueryRow(`INSERT INTO vulnerabilities (device_id, scan_id, severity, title, description, affected_component)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
			deviceID, scanID, f.Risk, f.Protocol+" exposure detected", f.Description, fmt.Sprintf("port/%d", f.Port),
		).Scan(&vulnID)
		if err != nil {
			log.Printf("Failed to insert vulnerability: %v", err)
		}

		alerts.CreateAlert(db, alerts.AlertRequest{
			DeviceID:  deviceID,
			AlertType: protocolToAlertType(f.Protocol),
			Severity:  f.Risk,
			Title:     fmt.Sprintf("%s detected on %s:%d", f.Protocol, ip, f.Port),
			Description: f.Description,
		})
	}

	// Step 3: TLS check if port 443 open
	for _, p := range openPortNumbers {
		if p == 443 {
			tlsResult := scanner.CheckTLS(ip, 443)
			if tlsResult.SupportsTLS10 || tlsResult.SupportsTLS11 || len(tlsResult.WeakCiphers) > 0 {
				db.QueryRow(`INSERT INTO vulnerabilities (device_id, scan_id, severity, title, description, affected_component)
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

	// Step 4: Credential testing
	creds, credErr := scanner.LoadCredentials("data/default-credentials.txt")
	if credErr != nil {
		log.Printf("Failed to load credentials: %v", credErr)
	} else {
		runCredentialTests(db, deviceID, scanID, ip, openPortNumbers, creds, kevCatalog)
	}

	// Step 5: Update scan status
	db.Exec(`UPDATE scans SET status='complete', completed_at=NOW() WHERE id=$1`, scanID)

	// Step 6: Update risk score
	risk.UpdateDeviceRiskScore(db, deviceID)

	log.Printf("Scan complete for %s: found %d open ports, %d protocol findings",
		ip, len(openPortNumbers), len(findings))
}

func runCredentialTests(db *sql.DB, deviceID, scanID, ip string, ports []int, creds []scanner.Credential, kevCatalog *kev.KEVCatalog) {
	hasPort := func(target int) bool {
		for _, p := range ports {
			if p == target { return true }
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
				DeviceID: deviceID, AlertType: alerts.AlertDefaultCreds, Severity: "critical",
				Title: fmt.Sprintf("Default credentials found on %s", ip),
				Metadata: metadata,
			})

			db.Exec(`UPDATE devices SET tags = array_append(tags, 'default-creds') WHERE id = $1 AND NOT ('default-creds' = ANY(COALESCE(tags, '{}')))`, deviceID)
		}
		if r.LockedOut {
			log.Printf("[WARNING] Credential lockout detected on %s - stopping credential tests", ip)
			alerts.CreateAlert(db, alerts.AlertRequest{
				DeviceID: deviceID, AlertType: alerts.AlertLockedOut, Severity: "medium",
				Title: fmt.Sprintf("Account lockout triggered during scan of %s", ip),
			})
			break
		}
	}
}

func protocolToAlertType(protocol string) string {
	switch protocol {
	case "Telnet": return alerts.AlertTelnetOpen
	case "ADB": return alerts.AlertADBExposed
	case "MQTT-plaintext": return alerts.AlertPlaintextMQTT
	case "RTSP-unauth": return alerts.AlertUnauthRTSP
	default: return protocol
	}
}

// NetworkScanHandler triggers a full network discovery.
func NetworkScanHandler(db *sql.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Println("Network scan triggered")

		go func() {
			hosts, err := scanner.DiscoverHosts(cfg.NetworkCIDR)
			if err != nil {
				log.Printf("Network discovery failed: %v", err)
				return
			}

			discovered := 0
			for _, ip := range hosts {
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
						DeviceID: deviceID, AlertType: alerts.AlertNewDevice, Severity: "high",
						Title: fmt.Sprintf("New device discovered: %s", ip),
					})
				}
				discovered++
			}
			log.Printf("Network scan complete: discovered %d hosts", discovered)
		}()

		success(c, gin.H{"message": "network scan started"})
	}
}

package api

import (
	"database/sql"

	"github.com/gin-gonic/gin"
)

// StatsHandler returns aggregated platform statistics.
func StatsHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var totalDevices, onlineDevices int
		var avgRiskScore sql.NullFloat64

		err := db.QueryRow(`
			SELECT
				COUNT(*) FILTER (WHERE is_active) as total_devices,
				COUNT(*) FILTER (WHERE is_active AND last_seen > NOW() - INTERVAL '5 minutes') as online_devices,
				AVG(risk_score) FILTER (WHERE is_active) as avg_risk_score
			FROM devices
		`).Scan(&totalDevices, &onlineDevices, &avgRiskScore)
		if err != nil {
			fail(c, 500, "Failed to query stats: "+err.Error())
			return
		}

		var criticalVulns, highVulns, mediumVulns, kevVulns, openAlerts, suspiciousFirmware int

		db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE is_resolved = FALSE AND severity = 'critical'`).Scan(&criticalVulns)
		db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE is_resolved = FALSE AND severity = 'high'`).Scan(&highVulns)
		db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE is_resolved = FALSE AND severity = 'medium'`).Scan(&mediumVulns)
		db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE is_resolved = FALSE AND is_kev = TRUE`).Scan(&kevVulns)
		db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE is_acknowledged = FALSE`).Scan(&openAlerts)
		db.QueryRow(`SELECT COUNT(*) FROM firmware WHERE analysis_status = 'complete' AND entropy_score > 7.2`).Scan(&suspiciousFirmware)

		avg := 0.0
		if avgRiskScore.Valid {
			avg = avgRiskScore.Float64
		}

		success(c, gin.H{
			"total_devices":      totalDevices,
			"online_devices":     onlineDevices,
			"avg_risk_score":     avg,
			"critical_vulns":     criticalVulns,
			"high_vulns":         highVulns,
			"medium_vulns":       mediumVulns,
			"kev_vulns":          kevVulns,
			"open_alerts":        openAlerts,
			"suspicious_firmware": suspiciousFirmware,
		})
	}
}

// RiskBreakdownHandler returns the risk score breakdown for a specific device.
func RiskBreakdownHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		deviceID := c.Param("id")

		// Import risk package functionality inline to avoid circular dependency
		// Build risk factors by querying vulnerabilities
		var factors = make(map[string]bool)
		rows, err := db.Query(
			`SELECT title FROM vulnerabilities WHERE device_id=$1 AND is_resolved=FALSE`, deviceID)
		if err != nil {
			fail(c, 500, "Failed to query vulnerabilities: "+err.Error())
			return
		}
		defer rows.Close()

		for rows.Next() {
			var title string
			if err := rows.Scan(&title); err != nil {
				continue
			}
			if contains(title, "Telnet") {
				factors["has_telnet"] = true
			}
			if contains(title, "ADB") || contains(title, "Android Debug") {
				factors["has_adb"] = true
			}
			if contains(title, "Modbus") {
				factors["has_modbus"] = true
			}
			if contains(title, "RTSP") {
				factors["has_unauth_rtsp"] = true
			}
			if contains(title, "MQTT") {
				factors["has_plaintext_mqtt"] = true
			}
			if contains(title, "HTTP") {
				factors["has_http_mgmt"] = true
			}
			if contains(title, "Default credentials") {
				factors["has_default_creds"] = true
			}
			if contains(title, "TLS") {
				factors["has_weak_tls"] = true
			}
		}

		var cveCount, kevCount int
		db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE device_id=$1 AND cve_id IS NOT NULL AND is_resolved=FALSE`, deviceID).Scan(&cveCount)
		db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE device_id=$1 AND is_kev=TRUE AND is_resolved=FALSE`, deviceID).Scan(&kevCount)

		var entropyScore sql.NullFloat64
		db.QueryRow(`SELECT entropy_score FROM firmware WHERE device_id=$1 ORDER BY analyzed_at DESC LIMIT 1`, deviceID).Scan(&entropyScore)

		// Calculate score
		score := 0.0
		breakdown := make(map[string]float64)

		if factors["has_default_creds"] {
			score += 4.0
			breakdown["default_credentials"] = 4.0
		}
		if factors["has_telnet"] {
			score += 3.0
			breakdown["telnet_exposed"] = 3.0
		}
		if factors["has_adb"] {
			score += 3.5
			breakdown["adb_exposed"] = 3.5
		}
		if factors["has_modbus"] {
			score += 2.5
			breakdown["modbus_detected"] = 2.5
		}
		if factors["has_unauth_rtsp"] {
			score += 2.0
			breakdown["unauth_rtsp"] = 2.0
		}
		if factors["has_plaintext_mqtt"] {
			score += 1.5
			breakdown["plaintext_mqtt"] = 1.5
		}
		if factors["has_http_mgmt"] {
			score += 1.0
			breakdown["http_management"] = 1.0
		}
		if factors["has_weak_tls"] {
			score += 1.5
			breakdown["weak_tls"] = 1.5
		}

		cvePoints := min(float64(cveCount)*0.5, 3.0)
		if cvePoints > 0 {
			score += cvePoints
			breakdown["known_cves"] = cvePoints
		}

		kevPoints := min(float64(kevCount)*2.0, 4.0)
		if kevPoints > 0 {
			score += kevPoints
			breakdown["kev_matches"] = kevPoints
		}

		if entropyScore.Valid && entropyScore.Float64 > 7.2 {
			score += 2.0
			breakdown["high_entropy_firmware"] = 2.0
		}

		if score > 10.0 {
			score = 10.0
		}

		severity := "low"
		if score >= 8.0 {
			severity = "critical"
		} else if score >= 6.0 {
			severity = "high"
		} else if score >= 3.0 {
			severity = "medium"
		}

		success(c, gin.H{
			"total_score":    score,
			"severity":       severity,
			"factors":        factors,
			"score_breakdown": breakdown,
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsCI(s, substr))
}

func containsCI(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if equalFoldSlice(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalFoldSlice(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

package risk

import (
	"database/sql"
	"log"
	"math"
	"strings"
	"time"
)

// RiskFactors contains all the factors that contribute to a device's risk score.
type RiskFactors struct {
	HasDefaultCreds     bool `json:"has_default_creds"`
	HasTelnet           bool `json:"has_telnet"`
	HasADB              bool `json:"has_adb"`
	HasModbus           bool `json:"has_modbus"`
	HasUnauthRTSP       bool `json:"has_unauth_rtsp"`
	HasPlaintextMQTT    bool `json:"has_plaintext_mqtt"`
	HasHTTPMgmt         bool `json:"has_http_mgmt"`
	HasWeakTLS          bool `json:"has_weak_tls"`
	KnownCVECount       int  `json:"known_cve_count"`
	KEVMatchCount       int  `json:"kev_match_count"`
	FirmwareOutdated    bool `json:"firmware_outdated"`
	HighEntropyFirmware bool `json:"high_entropy_firmware"`
	DaysSinceLastScan   int  `json:"days_since_last_scan"`
}

// CalculateRiskScore computes a 0-10 risk score from the given factors.
func CalculateRiskScore(factors RiskFactors) float64 {
	score := 0.0
	if factors.HasDefaultCreds {
		score += 4.0
	}
	if factors.HasTelnet {
		score += 3.0
	}
	if factors.HasADB {
		score += 3.5
	}
	if factors.HasModbus {
		score += 2.5
	}
	if factors.HasUnauthRTSP {
		score += 2.0
	}
	if factors.HasPlaintextMQTT {
		score += 1.5
	}
	if factors.HasHTTPMgmt {
		score += 1.0
	}
	if factors.HasWeakTLS {
		score += 1.5
	}
	score += math.Min(float64(factors.KnownCVECount)*0.5, 3.0)
	score += math.Min(float64(factors.KEVMatchCount)*2.0, 4.0)
	if factors.FirmwareOutdated {
		score += 1.0
	}
	if factors.HighEntropyFirmware {
		score += 2.0
	}
	score += math.Min(float64(factors.DaysSinceLastScan)/30*0.1, 1.0)
	return math.Min(score, 10.0)
}

// SeverityFromScore returns a severity label for a given risk score.
func SeverityFromScore(score float64) string {
	switch {
	case score >= 8.0:
		return "critical"
	case score >= 6.0:
		return "high"
	case score >= 3.0:
		return "medium"
	default:
		return "low"
	}
}

// ScoreBreakdown returns a map of each active factor and its point contribution.
func ScoreBreakdown(factors RiskFactors) map[string]float64 {
	breakdown := make(map[string]float64)
	if factors.HasDefaultCreds {
		breakdown["default_credentials"] = 4.0
	}
	if factors.HasTelnet {
		breakdown["telnet_exposed"] = 3.0
	}
	if factors.HasADB {
		breakdown["adb_exposed"] = 3.5
	}
	if factors.HasModbus {
		breakdown["modbus_detected"] = 2.5
	}
	if factors.HasUnauthRTSP {
		breakdown["unauth_rtsp"] = 2.0
	}
	if factors.HasPlaintextMQTT {
		breakdown["plaintext_mqtt"] = 1.5
	}
	if factors.HasHTTPMgmt {
		breakdown["http_management"] = 1.0
	}
	if factors.HasWeakTLS {
		breakdown["weak_tls"] = 1.5
	}
	cveScore := math.Min(float64(factors.KnownCVECount)*0.5, 3.0)
	if cveScore > 0 {
		breakdown["known_cves"] = cveScore
	}
	kevScore := math.Min(float64(factors.KEVMatchCount)*2.0, 4.0)
	if kevScore > 0 {
		breakdown["kev_matches"] = kevScore
	}
	if factors.FirmwareOutdated {
		breakdown["firmware_outdated"] = 1.0
	}
	if factors.HighEntropyFirmware {
		breakdown["high_entropy_firmware"] = 2.0
	}
	dayScore := math.Min(float64(factors.DaysSinceLastScan)/30*0.1, 1.0)
	if dayScore > 0 {
		breakdown["scan_age"] = dayScore
	}
	return breakdown
}

// BuildRiskFactors queries the database to build risk factors for a device.
func BuildRiskFactors(db *sql.DB, deviceID string) (RiskFactors, error) {
	var factors RiskFactors

	// Query vulnerability titles to determine active risk factors
	rows, err := db.Query(
		`SELECT title FROM vulnerabilities WHERE device_id=$1 AND is_resolved=FALSE`, deviceID)
	if err != nil {
		return factors, err
	}
	defer rows.Close()

	for rows.Next() {
		var title string
		if err := rows.Scan(&title); err != nil {
			continue
		}
		titleLower := strings.ToLower(title)
		if strings.Contains(titleLower, "telnet") {
			factors.HasTelnet = true
		}
		if strings.Contains(titleLower, "adb") || strings.Contains(titleLower, "android debug") {
			factors.HasADB = true
		}
		if strings.Contains(titleLower, "modbus") {
			factors.HasModbus = true
		}
		if strings.Contains(titleLower, "rtsp") {
			factors.HasUnauthRTSP = true
		}
		if strings.Contains(titleLower, "mqtt") {
			factors.HasPlaintextMQTT = true
		}
		if strings.Contains(titleLower, "http") {
			factors.HasHTTPMgmt = true
		}
		if strings.Contains(titleLower, "default credentials") {
			factors.HasDefaultCreds = true
		}
		if strings.Contains(titleLower, "tls") {
			factors.HasWeakTLS = true
		}
	}

	// Count known CVEs
	db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE device_id=$1 AND cve_id IS NOT NULL AND is_resolved=FALSE`,
		deviceID).Scan(&factors.KnownCVECount)

	// Count KEV matches
	db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE device_id=$1 AND is_kev=TRUE AND is_resolved=FALSE`,
		deviceID).Scan(&factors.KEVMatchCount)

	// Check firmware entropy
	var entropyScore sql.NullFloat64
	db.QueryRow(`SELECT entropy_score FROM firmware WHERE device_id=$1 ORDER BY analyzed_at DESC LIMIT 1`,
		deviceID).Scan(&entropyScore)
	if entropyScore.Valid && entropyScore.Float64 > 7.2 {
		factors.HighEntropyFirmware = true
	}

	// Calculate days since last scan
	var lastScan sql.NullTime
	db.QueryRow(`SELECT started_at FROM scans WHERE device_id=$1 ORDER BY started_at DESC LIMIT 1`,
		deviceID).Scan(&lastScan)
	if lastScan.Valid {
		factors.DaysSinceLastScan = int(time.Since(lastScan.Time).Hours() / 24)
	}

	return factors, nil
}

// UpdateDeviceRiskScore recalculates and saves the risk score for a device.
func UpdateDeviceRiskScore(db *sql.DB, deviceID string) error {
	factors, err := BuildRiskFactors(db, deviceID)
	if err != nil {
		return err
	}

	newScore := CalculateRiskScore(factors)

	var oldScore float64
	db.QueryRow(`SELECT risk_score FROM devices WHERE id=$1`, deviceID).Scan(&oldScore)

	_, err = db.Exec(`UPDATE devices SET risk_score=$1 WHERE id=$2`, newScore, deviceID)
	if err != nil {
		return err
	}

	log.Printf("Risk score updated for device %s: %.1f → %.1f", deviceID, oldScore, newScore)
	return nil
}

// GetRiskBreakdown returns the full risk breakdown for a device.
func GetRiskBreakdown(db *sql.DB, deviceID string) map[string]interface{} {
	factors, err := BuildRiskFactors(db, deviceID)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	score := CalculateRiskScore(factors)
	return map[string]interface{}{
		"total_score":     score,
		"severity":        SeverityFromScore(score),
		"factors":         factors,
		"score_breakdown": ScoreBreakdown(factors),
	}
}

package api

import (
	"database/sql"

	"github.com/gin-gonic/gin"
	"github.com/Nciibi/seagles/risk"
	"github.com/Nciibi/seagles/slog"
)

func StatsHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID, _ := c.Get("request_id")

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
			slog.Error("Failed to query stats", "request_id", requestID, "error", err.Error())
			fail(c, 500, "Failed to query stats: "+err.Error())
			return
		}

		var criticalVulns, highVulns, mediumVulns, lowVulns, kevVulns, openAlerts, suspiciousFirmware int

		err = db.QueryRow(`
			SELECT
				COALESCE((SELECT COUNT(*) FROM vulnerabilities WHERE severity='critical' AND is_resolved=FALSE), 0),
				COALESCE((SELECT COUNT(*) FROM vulnerabilities WHERE severity='high' AND is_resolved=FALSE), 0),
				COALESCE((SELECT COUNT(*) FROM vulnerabilities WHERE severity='medium' AND is_resolved=FALSE), 0),
				COALESCE((SELECT COUNT(*) FROM vulnerabilities WHERE severity='low' AND is_resolved=FALSE), 0),
				COALESCE((SELECT COUNT(*) FROM vulnerabilities WHERE is_kev=TRUE AND is_resolved=FALSE), 0),
				COALESCE((SELECT COUNT(*) FROM alerts WHERE is_acknowledged=FALSE), 0),
				COALESCE((SELECT COUNT(*) FROM firmware WHERE analysis_status='complete' AND (has_backdoor_indicators=TRUE OR has_default_creds=TRUE)), 0)
		`).Scan(&criticalVulns, &highVulns, &mediumVulns, &lowVulns, &kevVulns, &openAlerts, &suspiciousFirmware)
		if err != nil {
			slog.Error("Failed to query stats counts", "request_id", requestID, "error", err.Error())
			fail(c, 500, "Failed to query stats counts: "+err.Error())
			return
		}

		avg := 0.0
		if avgRiskScore.Valid {
			avg = avgRiskScore.Float64
		}

		success(c, gin.H{
			"total_devices":       totalDevices,
			"online_devices":      onlineDevices,
			"avg_risk_score":      avg,
			"critical_vulns":      criticalVulns,
			"high_vulns":          highVulns,
			"medium_vulns":        mediumVulns,
			"low_vulns":           lowVulns,
			"kev_vulns":           kevVulns,
			"open_alerts":         openAlerts,
			"suspicious_firmware": suspiciousFirmware,
		})
	}
}

// RiskBreakdownHandler delegates to the risk package so the API response uses
// exactly the same factors and weights as the score persisted on devices.
// The previous inline re-implementation silently omitted firmware_outdated and
// scan_age, so the breakdown disagreed with devices.risk_score.
func RiskBreakdownHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID, _ := c.Get("request_id")
		deviceID := c.Param("id")

		result := risk.GetRiskBreakdown(db, deviceID)
		if errMsg, ok := result["error"].(string); ok {
			slog.Error("Failed to compute risk breakdown", "request_id", requestID, "device_id", deviceID, "error", errMsg)
			fail(c, 500, "Failed to compute risk breakdown: "+errMsg)
			return
		}

		success(c, result)
	}
}


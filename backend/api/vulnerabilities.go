package api

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/Nciibi/seagles/models"
	"github.com/Nciibi/seagles/risk"
	"github.com/Nciibi/seagles/slog"
)

func ListVulnerabilitiesHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID, _ := c.Get("request_id")

		query := `SELECT id, device_id, scan_id, cve_id, cvss_score, severity, title,
			description, affected_component, remediation, is_kev, discovered_at,
			resolved_at, is_resolved FROM vulnerabilities WHERE 1=1`
		var args []interface{}
		argIdx := 1

		if v := c.Query("severity"); v != "" {
			query += fmt.Sprintf(" AND severity = $%d", argIdx)
			args = append(args, v)
			argIdx++
		}
		if v := c.Query("device_id"); v != "" {
			query += fmt.Sprintf(" AND device_id = $%d", argIdx)
			args = append(args, v)
			argIdx++
		}
		if v := c.Query("is_kev"); v != "" {
			b, _ := strconv.ParseBool(v)
			query += fmt.Sprintf(" AND is_kev = $%d", argIdx)
			args = append(args, b)
			argIdx++
		}
		if v := c.Query("is_resolved"); v != "" {
			b, _ := strconv.ParseBool(v)
			query += fmt.Sprintf(" AND is_resolved = $%d", argIdx)
			args = append(args, b)
			argIdx++
		}

		query += " ORDER BY cvss_score DESC NULLS LAST, discovered_at DESC"

		rows, err := db.Query(query, args...)
		if err != nil {
			slog.Error("Failed to query vulnerabilities", "request_id", requestID, "error", err.Error())
			fail(c, 500, "Failed to query vulnerabilities: "+err.Error())
			return
		}
		defer rows.Close()

		var vulns []models.VulnerabilityJSON
		for rows.Next() {
			var v models.Vulnerability
			if err := rows.Scan(&v.ID, &v.DeviceID, &v.ScanID, &v.CVEID, &v.CVSSScore,
				&v.Severity, &v.Title, &v.Description, &v.AffectedComponent,
				&v.Remediation, &v.IsKEV, &v.DiscoveredAt, &v.ResolvedAt, &v.IsResolved); err != nil {
				continue
			}
			vulns = append(vulns, v.ToJSON())
		}
		if err := rows.Err(); err != nil {
			fail(c, 500, "Failed to iterate vulnerabilities: "+err.Error())
			return
		}
		if vulns == nil {
			vulns = []models.VulnerabilityJSON{}
		}
		success(c, vulns)
	}
}

func ResolveVulnerabilityHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID, _ := c.Get("request_id")
		id := c.Param("id")

		result, err := db.Exec(`UPDATE vulnerabilities SET is_resolved=true, resolved_at=NOW() WHERE id=$1`, id)
		if err != nil {
			slog.Error("Failed to resolve vulnerability", "request_id", requestID, "vuln_id", id, "error", err.Error())
			fail(c, 500, "Failed to resolve vulnerability: "+err.Error())
			return
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			fail(c, 404, "Vulnerability not found")
			return
		}

		var deviceID sql.NullString
		db.QueryRow(`SELECT device_id FROM vulnerabilities WHERE id=$1`, id).Scan(&deviceID)
		if deviceID.Valid {
			go func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("PANIC in risk score update: %v", r)
					}
				}()
if err := risk.UpdateDeviceRiskScore(db, deviceID.String); err != nil {
				slog.Error("Failed to update risk score", "device_id", deviceID.String, "error", err.Error())
			}
			}()
		}

		slog.Info("Vulnerability resolved", "request_id", requestID, "vuln_id", id)
		success(c, gin.H{"message": "Vulnerability resolved"})
	}
}

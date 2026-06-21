package api

import (
	"database/sql"
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/seagles/models"
)

// ListVulnerabilitiesHandler returns vulnerabilities with optional filters.
func ListVulnerabilitiesHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
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
		if vulns == nil { vulns = []models.VulnerabilityJSON{} }
		success(c, vulns)
	}
}

// ResolveVulnerabilityHandler marks a vulnerability as resolved.
func ResolveVulnerabilityHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		result, err := db.Exec(`UPDATE vulnerabilities SET is_resolved=true, resolved_at=NOW() WHERE id=$1`, id)
		if err != nil {
			fail(c, 500, "Failed to resolve vulnerability: "+err.Error())
			return
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			fail(c, 404, "Vulnerability not found")
			return
		}

		// Update risk score for associated device
		var deviceID sql.NullString
		db.QueryRow(`SELECT device_id FROM vulnerabilities WHERE id=$1`, id).Scan(&deviceID)
		if deviceID.Valid {
			go func() {
				// Lazy import to avoid circular deps — calling inline
				db.Exec(`UPDATE devices SET risk_score = COALESCE(
					(SELECT LEAST(
						CASE WHEN EXISTS(SELECT 1 FROM vulnerabilities WHERE device_id=$1 AND is_resolved=FALSE AND title ILIKE '%Default credentials%') THEN 4.0 ELSE 0 END +
						CASE WHEN EXISTS(SELECT 1 FROM vulnerabilities WHERE device_id=$1 AND is_resolved=FALSE AND title ILIKE '%Telnet%') THEN 3.0 ELSE 0 END +
						LEAST((SELECT COUNT(*) FROM vulnerabilities WHERE device_id=$1 AND cve_id IS NOT NULL AND is_resolved=FALSE)::float * 0.5, 3.0),
					10.0)), 0) WHERE id=$1`, deviceID.String)
			}()
		}

		success(c, gin.H{"message": "Vulnerability resolved"})
	}
}

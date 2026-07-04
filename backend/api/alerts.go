package api

import (
	"database/sql"
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/Nciibi/seagles/models"
	"github.com/Nciibi/seagles/slog"
)

func ListAlertsHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID, _ := c.Get("request_id")

		query := `SELECT id, device_id, severity, alert_type, title, description,
			triggered_at, acknowledged_at, is_acknowledged, metadata
			FROM alerts WHERE 1=1`
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
		if v := c.Query("is_acknowledged"); v != "" {
			b, _ := strconv.ParseBool(v)
			query += fmt.Sprintf(" AND is_acknowledged = $%d", argIdx)
			args = append(args, b)
			argIdx++
		}

		query += " ORDER BY triggered_at DESC LIMIT 100"

		rows, err := db.Query(query, args...)
		if err != nil {
			slog.Error("Failed to query alerts", "request_id", requestID, "error", err.Error())
			fail(c, 500, "Failed to query alerts: "+err.Error())
			return
		}
		defer rows.Close()

		var alertList []models.AlertJSON
		for rows.Next() {
			var a models.Alert
			if err := rows.Scan(&a.ID, &a.DeviceID, &a.Severity, &a.AlertType, &a.Title,
				&a.Description, &a.TriggeredAt, &a.AcknowledgedAt, &a.IsAcknowledged, &a.Metadata); err != nil {
				continue
			}
			alertList = append(alertList, a.ToJSON())
		}
		if err := rows.Err(); err != nil {
			fail(c, 500, "Failed to iterate alerts: "+err.Error())
			return
		}
		if alertList == nil {
			alertList = []models.AlertJSON{}
		}
		success(c, alertList)
	}
}

func AckAlertHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID, _ := c.Get("request_id")
		id := c.Param("id")

		result, err := db.Exec(`UPDATE alerts SET is_acknowledged=true, acknowledged_at=NOW() WHERE id=$1`, id)
		if err != nil {
			slog.Error("Failed to acknowledge alert", "request_id", requestID, "alert_id", id, "error", err.Error())
			fail(c, 500, "Failed to acknowledge alert: "+err.Error())
			return
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			fail(c, 404, "Alert not found")
			return
		}
		slog.Info("Alert acknowledged", "request_id", requestID, "alert_id", id)
		success(c, gin.H{"message": "Alert acknowledged"})
	}
}

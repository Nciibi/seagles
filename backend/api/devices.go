package api

import (
	"database/sql"
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/Nciibi/seagles/models"
	"github.com/Nciibi/seagles/slog"
)

func ListDevicesHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		qdb := tenantDB(c, db)
		requestID, _ := c.Get("request_id")

		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		if page < 1 {
			page = 1
		}
		if limit < 1 || limit > 200 {
			limit = 50
		}
		offset := (page - 1) * limit

		query := `SELECT id, ip_address, mac_address, hostname, vendor, device_type,
			os_fingerprint, firmware_version, first_seen, last_seen, risk_score,
			is_active, tags, raw_nmap FROM devices WHERE 1=1`
		var args []interface{}
		argIdx := 1

		if v := c.Query("risk_min"); v != "" {
			query += fmt.Sprintf(" AND risk_score >= $%d", argIdx)
			f, _ := strconv.ParseFloat(v, 64)
			args = append(args, f)
			argIdx++
		}
		if v := c.Query("risk_max"); v != "" {
			query += fmt.Sprintf(" AND risk_score <= $%d", argIdx)
			f, _ := strconv.ParseFloat(v, 64)
			args = append(args, f)
			argIdx++
		}
		if v := c.Query("device_type"); v != "" {
			query += fmt.Sprintf(" AND device_type = $%d", argIdx)
			args = append(args, v)
			argIdx++
		}

		query += " ORDER BY risk_score DESC"
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
		args = append(args, limit, offset)

		rows, err := qdb.Query(query, args...)
		if err != nil {
			slog.Error("Failed to query devices", "request_id", requestID, "error", err.Error())
			failInternal(c, 500, "Failed to query devices: ", err)
			return
		}
		defer rows.Close()

		var devices []models.DeviceJSON
		for rows.Next() {
			var d models.Device
			if err := rows.Scan(&d.ID, &d.IPAddress, &d.MACAddress, &d.Hostname, &d.Vendor,
				&d.DeviceType, &d.OSFingerprint, &d.FirmwareVersion,
				&d.FirstSeen, &d.LastSeen, &d.RiskScore, &d.IsActive,
				&d.Tags, &d.RawNmap); err != nil {
				failInternal(c, 500, "Failed to read device row", err)
				return
			}
			devices = append(devices, d.ToJSON())
		}
		if err := rows.Err(); err != nil {
			failInternal(c, 500, "Failed to iterate devices: ", err)
			return
		}
		if devices == nil {
			devices = []models.DeviceJSON{}
		}
		success(c, devices)
	}
}

func GetDeviceHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		qdb := tenantDB(c, db)
		requestID, _ := c.Get("request_id")
		id, ok := uuidParam(c, "id")
		if !ok {
			return
		}

		var d models.Device
		err := qdb.QueryRow(`SELECT id, ip_address, mac_address, hostname, vendor, device_type,
			os_fingerprint, firmware_version, first_seen, last_seen, risk_score,
			is_active, tags, raw_nmap FROM devices WHERE id = $1`, id).Scan(
			&d.ID, &d.IPAddress, &d.MACAddress, &d.Hostname, &d.Vendor,
			&d.DeviceType, &d.OSFingerprint, &d.FirmwareVersion,
			&d.FirstSeen, &d.LastSeen, &d.RiskScore, &d.IsActive, &d.Tags, &d.RawNmap)
		if err == sql.ErrNoRows {
			fail(c, 404, "Device not found")
			return
		}
		if err != nil {
			slog.Error("Failed to query device", "request_id", requestID, "device_id", id, "error", err.Error())
			failInternal(c, 500, "Failed to query device: ", err)
			return
		}

		var latestScan *models.ScanJSON
		var s models.Scan
		if err := qdb.QueryRow(`SELECT id, device_id, started_at, completed_at, status, scan_type,
			open_ports, services, scan_output FROM scans WHERE device_id = $1
			ORDER BY started_at DESC LIMIT 1`, id).Scan(
			&s.ID, &s.DeviceID, &s.StartedAt, &s.CompletedAt, &s.Status,
			&s.ScanType, &s.OpenPorts, &s.Services, &s.ScanOutput); err == nil {
			sj := s.ToJSON()
			latestScan = &sj
		}

		var openVulns int
		qdb.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE device_id=$1 AND is_resolved=FALSE`, id).Scan(&openVulns)

		success(c, gin.H{
			"device": d.ToJSON(), "latest_scan": latestScan, "open_vulnerabilities": openVulns,
		})
	}
}

func DeleteDeviceHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		qdb := tenantDB(c, db)
		requestID, _ := c.Get("request_id")
		id, ok := uuidParam(c, "id")
		if !ok {
			return
		}

		result, err := qdb.Exec(`UPDATE devices SET is_active = false WHERE id = $1`, id)
		if err != nil {
			slog.Error("Failed to delete device", "request_id", requestID, "device_id", id, "error", err.Error())
			failInternal(c, 500, "Failed to delete device: ", err)
			return
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			fail(c, 404, "Device not found")
			return
		}
		slog.Info("Device deactivated", "request_id", requestID, "device_id", id)
		success(c, gin.H{"message": "Device deactivated"})
	}
}

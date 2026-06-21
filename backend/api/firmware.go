package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/seagles/alerts"
	"github.com/yourusername/seagles/config"
	"github.com/yourusername/seagles/models"
)

// ListFirmwareHandler returns all firmware records with device info joined.
func ListFirmwareHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := db.Query(`SELECT f.id, f.device_id, f.version, f.vendor, f.checksum,
			f.file_path, f.analyzed_at, f.entropy_score, f.has_default_creds,
			f.has_telnet, f.has_backdoor_indicators, f.strings_of_interest,
			f.cve_matches, f.analysis_status, f.analysis_report,
			d.ip_address, d.hostname
			FROM firmware f
			LEFT JOIN devices d ON f.device_id = d.id
			ORDER BY f.analyzed_at DESC NULLS LAST`)
		if err != nil {
			fail(c, 500, "Failed to query firmware: "+err.Error())
			return
		}
		defer rows.Close()

		type FirmwareWithDevice struct {
			models.FirmwareJSON
			DeviceIP       *string `json:"device_ip"`
			DeviceHostname *string `json:"device_hostname"`
		}

		var firmwareList []FirmwareWithDevice
		for rows.Next() {
			var f models.Firmware
			var deviceIP, deviceHostname sql.NullString
			if err := rows.Scan(&f.ID, &f.DeviceID, &f.Version, &f.Vendor, &f.Checksum,
				&f.FilePath, &f.AnalyzedAt, &f.EntropyScore, &f.HasDefaultCreds,
				&f.HasTelnet, &f.HasBackdoorIndicators, &f.StringsOfInterest,
				&f.CVEMatches, &f.AnalysisStatus, &f.AnalysisReport,
				&deviceIP, &deviceHostname); err != nil {
				continue
			}
			entry := FirmwareWithDevice{FirmwareJSON: f.ToJSON()}
			if deviceIP.Valid { entry.DeviceIP = &deviceIP.String }
			if deviceHostname.Valid { entry.DeviceHostname = &deviceHostname.String }
			firmwareList = append(firmwareList, entry)
		}
		if firmwareList == nil { firmwareList = []FirmwareWithDevice{} }
		success(c, firmwareList)
	}
}

// AnalyzeFirmwareHandler triggers firmware analysis via the Python microservice.
func AnalyzeFirmwareHandler(db *sql.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")

		// Get firmware record
		var f models.Firmware
		err := db.QueryRow(`SELECT id, device_id, version, vendor, file_path
			FROM firmware WHERE id = $1`, id).Scan(
			&f.ID, &f.DeviceID, &f.Version, &f.Vendor, &f.FilePath)
		if err == sql.ErrNoRows {
			fail(c, 404, "Firmware not found")
			return
		}
		if err != nil {
			fail(c, 500, "Failed to query firmware: "+err.Error())
			return
		}

		// Update status to pending
		db.Exec(`UPDATE firmware SET analysis_status='pending' WHERE id=$1`, id)
		log.Printf("Firmware analysis triggered for %s", id)

		// Launch analysis in background
		go func() {
			analyzerURL := cfg.FirmwareAnalyzerURL
			if analyzerURL == "" {
				analyzerURL = "http://firmware-analyzer:8001"
			}

			filePath := ""
			if f.FilePath.Valid { filePath = f.FilePath.String }
			vendor := ""
			if f.Vendor.Valid { vendor = f.Vendor.String }
			version := ""
			if f.Version.Valid { version = f.Version.String }

			reqBody, _ := json.Marshal(map[string]string{
				"firmware_id": id,
				"filepath":    filePath,
				"vendor":      vendor,
				"version":     version,
			})

			resp, err := http.Post(analyzerURL+"/analyze", "application/json", bytes.NewReader(reqBody))
			if err != nil {
				log.Printf("Firmware analysis request failed: %v", err)
				db.Exec(`UPDATE firmware SET analysis_status='failed' WHERE id=$1`, id)
				return
			}
			defer resp.Body.Close()

			var result struct {
				Report struct {
					Entropy struct {
						EntropyScore float64 `json:"entropy_score"`
						Suspicious   bool    `json:"suspicious"`
					} `json:"entropy"`
				} `json:"report"`
			}
			json.NewDecoder(resp.Body).Decode(&result)

			if result.Report.Entropy.Suspicious && f.DeviceID.Valid {
				alerts.CreateAlert(db, alerts.AlertRequest{
					DeviceID:  f.DeviceID.String,
					AlertType: alerts.AlertFirmwareEntropy,
					Severity:  "high",
					Title:     fmt.Sprintf("High entropy firmware detected (score: %.4f)", result.Report.Entropy.EntropyScore),
				})
			}
		}()

		success(c, gin.H{"message": "Firmware analysis started", "firmware_id": id})
	}
}

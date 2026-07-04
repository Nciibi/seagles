package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/seagles/alerts"
	"github.com/yourusername/seagles/config"
	"github.com/yourusername/seagles/models"
	"github.com/yourusername/seagles/slog"
)

type AnalyzeFirmwareRequest struct {
	Filepath string `json:"filepath" binding:"omitempty,min=1"`
	Vendor   string `json:"vendor" binding:"omitempty,min=1,max=200"`
	Version  string `json:"version" binding:"omitempty,min=1,max=100"`
}

func ListFirmwareHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID, _ := c.Get("request_id")

		rows, err := db.Query(`SELECT f.id, f.device_id, f.version, f.vendor, f.checksum,
			f.file_path, f.analyzed_at, f.entropy_score, f.has_default_creds,
			f.has_telnet, f.has_backdoor_indicators, f.strings_of_interest,
			f.cve_matches, f.analysis_status, f.analysis_report,
			d.ip_address, d.hostname
			FROM firmware f
			LEFT JOIN devices d ON f.device_id = d.id
			ORDER BY f.analyzed_at DESC NULLS LAST`)
		if err != nil {
			slog.Error("Failed to query firmware", "request_id", requestID, "error", err.Error())
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
			if deviceIP.Valid {
				entry.DeviceIP = &deviceIP.String
			}
			if deviceHostname.Valid {
				entry.DeviceHostname = &deviceHostname.String
			}
			firmwareList = append(firmwareList, entry)
		}
		if firmwareList == nil {
			firmwareList = []FirmwareWithDevice{}
		}
		success(c, firmwareList)
	}
}

func AnalyzeFirmwareHandler(db *sql.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID, _ := c.Get("request_id")
		id := c.Param("id")

		var f models.Firmware
		err := db.QueryRow(`SELECT id, device_id, version, vendor, file_path
			FROM firmware WHERE id = $1`, id).Scan(
			&f.ID, &f.DeviceID, &f.Version, &f.Vendor, &f.FilePath)
		if err == sql.ErrNoRows {
			fail(c, 404, "Firmware not found")
			return
		}
		if err != nil {
			slog.Error("Failed to query firmware", "request_id", requestID, "firmware_id", id, "error", err.Error())
			fail(c, 500, "Failed to query firmware: "+err.Error())
			return
		}

		db.Exec(`UPDATE firmware SET analysis_status='pending' WHERE id=$1`, id)
		slog.Info("Firmware analysis triggered", "request_id", requestID, "firmware_id", id)

		go func() {
			analyzerURL := cfg.FirmwareAnalyzerURL
			if analyzerURL == "" {
				analyzerURL = "http://firmware-analyzer:8001"
			}

			filePath := ""
			if f.FilePath.Valid {
				filePath = f.FilePath.String
			}
			vendor := ""
			if f.Vendor.Valid {
				vendor = f.Vendor.String
			}
			version := ""
			if f.Version.Valid {
				version = f.Version.String
			}

			reqBody, _ := json.Marshal(map[string]string{
				"firmware_id": id,
				"filepath":    filePath,
				"vendor":      vendor,
				"version":     version,
			})

			client := &http.Client{Timeout: 120 * time.Second}
			resp, err := client.Post(analyzerURL+"/analyze", "application/json", bytes.NewReader(reqBody))
			if err != nil {
				slog.Error("Firmware analysis request failed", "firmware_id", id, "error", err.Error())
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

			slog.Info("Firmware analysis complete", "firmware_id", id, "entropy", result.Report.Entropy.EntropyScore)
		}()

		success(c, gin.H{"message": "Firmware analysis started", "firmware_id": id})
	}
}

func UploadFirmwareHandler(db *sql.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUploadSize)

		file, header, err := c.Request.FormFile("firmware")
		if err != nil {
			fail(c, http.StatusBadRequest, "Firmware file is required (form field: 'firmware')")
			return
		}
		defer file.Close()

		deviceID := c.PostForm("device_id")
		vendor := c.PostForm("vendor")
		version := c.PostForm("version")

		if header.Size == 0 {
			fail(c, http.StatusBadRequest, "Uploaded file is empty")
			return
		}

		tempDir := "/tmp/ironmesh-uploads"
		os.MkdirAll(tempDir, 0750)
		tempPath := filepath.Join(tempDir, header.Filename)

		destFile, err := os.Create(tempPath)
		if err != nil {
			fail(c, http.StatusInternalServerError, "Failed to initialize upload buffer")
			return
		}

		hasher := sha256.New()
		tee := io.TeeReader(file, hasher)

		written, err := io.Copy(destFile, tee)
		destFile.Close()

		if err != nil {
			os.Remove(tempPath)
			fail(c, http.StatusInternalServerError, "Failed to write firmware file")
			return
		}

		checksum := hex.EncodeToString(hasher.Sum(nil))
		finalPath := tempPath

		if cfg.S3Endpoint != "" && cfg.S3AccessKey != "" {
			useSSL := false
			minioClient, err := minio.New(cfg.S3Endpoint, &minio.Options{
				Creds:  credentials.NewStaticV4(cfg.S3AccessKey, cfg.S3SecretKey, ""),
				Secure: useSSL,
			})

			if err == nil {
				bucketName := cfg.S3Bucket
				if bucketName == "" {
					bucketName = "ironmesh-firmware"
				}

				ctx := context.Background()
				exists, _ := minioClient.BucketExists(ctx, bucketName)
				if !exists {
					_ = minioClient.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
				}

				objectName := fmt.Sprintf("%s/%s", checksum, header.Filename)
				_, err = minioClient.FPutObject(ctx, bucketName, objectName, tempPath, minio.PutObjectOptions{
					ContentType: "application/octet-stream",
				})

				if err == nil {
					finalPath = fmt.Sprintf("s3://%s/%s", bucketName, objectName)
					os.Remove(tempPath)
					slog.Info("Firmware uploaded to S3", "path", finalPath)
				} else {
					slog.Warn("S3 upload failed, falling back to local storage", "error", err.Error())
				}
			} else {
				slog.Warn("MinIO client init failed, falling back to local storage", "error", err.Error())
			}
		}

		if finalPath == tempPath {
			uploadDir := "data/firmware-uploads"
			os.MkdirAll(uploadDir, 0750)
			finalPath = filepath.Join(uploadDir, fmt.Sprintf("%s_%s", checksum[:8], header.Filename))
			os.Rename(tempPath, finalPath)
		}

		var firmwareID string
		err = db.QueryRow(`INSERT INTO firmware (device_id, vendor, version, checksum, file_path, 
			file_size_bytes, original_filename, upload_source, analysis_status)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 'upload', 'pending') RETURNING id`,
			nullableString(deviceID), nullableString(vendor), nullableString(version),
			checksum, finalPath, written, header.Filename,
		).Scan(&firmwareID)

		if err != nil {
			slog.Error("Failed to insert firmware record", "error", err.Error())
			fail(c, http.StatusInternalServerError, "Failed to create firmware record")
			return
		}

		slog.Info("Firmware uploaded", "firmware_id", firmwareID, "filename", header.Filename, "size", written)

		success(c, gin.H{
			"firmware_id":       firmwareID,
			"filename":          header.Filename,
			"size_bytes":        written,
			"checksum_sha256":   checksum,
			"storage_path":      finalPath,
			"analysis_status":   "pending",
			"message":           fmt.Sprintf("Firmware uploaded. Use POST /firmware/%s/analyze to start analysis.", firmwareID),
		})
	}
}

package api

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/seagles/config"
)

const maxUploadSize = 256 << 20 // 256 MB

// UploadFirmwareHandler handles firmware binary uploads via multipart form data.
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

		// Create upload directory
		uploadDir := "/app/data/firmware-uploads"
		if err := os.MkdirAll(uploadDir, 0750); err != nil {
			// Fallback to local data dir
			uploadDir = "data/firmware-uploads"
			os.MkdirAll(uploadDir, 0750)
		}

		// Generate SHA-256 checksum while writing to disk
		hasher := sha256.New()
		tee := io.TeeReader(file, hasher)

		destPath := filepath.Join(uploadDir, header.Filename)
		destFile, err := os.Create(destPath)
		if err != nil {
			fail(c, http.StatusInternalServerError, "Failed to save firmware file")
			return
		}

		written, err := io.Copy(destFile, tee)
		destFile.Close()
		if err != nil {
			os.Remove(destPath)
			fail(c, http.StatusInternalServerError, "Failed to write firmware file")
			return
		}

		checksum := hex.EncodeToString(hasher.Sum(nil))

		// Insert firmware record
		var firmwareID string
		err = db.QueryRow(`INSERT INTO firmware (device_id, vendor, version, checksum, file_path, 
			file_size_bytes, original_filename, upload_source, analysis_status)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 'upload', 'pending') RETURNING id`,
			nullableString(deviceID), nullableString(vendor), nullableString(version),
			checksum, destPath, written, header.Filename,
		).Scan(&firmwareID)

		if err != nil {
			log.Printf("Failed to insert firmware record: %v", err)
			fail(c, http.StatusInternalServerError, "Failed to create firmware record")
			return
		}

		log.Printf("Firmware uploaded: %s (%s, %d bytes, SHA256: %s)",
			header.Filename, firmwareID, written, checksum[:16])

		success(c, gin.H{
			"firmware_id":       firmwareID,
			"filename":          header.Filename,
			"size_bytes":        written,
			"checksum_sha256":   checksum,
			"analysis_status":   "pending",
			"message":           fmt.Sprintf("Firmware uploaded. Use POST /firmware/%s/analyze to start analysis.", firmwareID),
		})
	}
}

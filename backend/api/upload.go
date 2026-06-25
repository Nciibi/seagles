package api

import (
	"context"
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
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/yourusername/seagles/config"
)

const maxUploadSize = 256 << 20 // 256 MB

// UploadFirmwareHandler handles firmware binary uploads, streaming them to S3 or local disk.
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

		// Create a temporary file to calculate SHA256 and hold data before S3 upload
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
		finalPath := tempPath // defaults to local temp path

		// Attempt S3 Upload if configured
		if cfg.S3Endpoint != "" && cfg.S3AccessKey != "" {
			useSSL := false // In dev/local this is often false; adjust as needed
			minioClient, err := minio.New(cfg.S3Endpoint, &minio.Options{
				Creds:  credentials.NewStaticV4(cfg.S3AccessKey, cfg.S3SecretKey, ""),
				Secure: useSSL,
			})
			
			if err == nil {
				// Ensure bucket exists
				bucketName := cfg.S3Bucket
				if bucketName == "" {
					bucketName = "ironmesh-firmware"
				}
				
				ctx := context.Background()
				exists, _ := minioClient.BucketExists(ctx, bucketName)
				if !exists {
					_ = minioClient.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{})
				}

				// Upload to S3
				objectName := fmt.Sprintf("%s/%s", checksum, header.Filename)
				_, err = minioClient.FPutObject(ctx, bucketName, objectName, tempPath, minio.PutObjectOptions{
					ContentType: "application/octet-stream",
				})

				if err == nil {
					finalPath = fmt.Sprintf("s3://%s/%s", bucketName, objectName)
					os.Remove(tempPath) // Clean up local temp file since it's in S3
					log.Printf("Firmware securely uploaded to S3: %s", finalPath)
				} else {
					log.Printf("[WARNING] S3 Upload failed, falling back to local storage: %v", err)
				}
			} else {
				log.Printf("[WARNING] MinIO client init failed, falling back to local storage: %v", err)
			}
		}

		// Fallback to local storage if S3 failed or wasn't configured
		if finalPath == tempPath {
			uploadDir := "data/firmware-uploads"
			os.MkdirAll(uploadDir, 0750)
			finalPath = filepath.Join(uploadDir, fmt.Sprintf("%s_%s", checksum[:8], header.Filename))
			os.Rename(tempPath, finalPath)
		}

		// Insert firmware record
		var firmwareID string
		err = db.QueryRow(`INSERT INTO firmware (device_id, vendor, version, checksum, file_path, 
			file_size_bytes, original_filename, upload_source, analysis_status)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 'upload', 'pending') RETURNING id`,
			nullableString(deviceID), nullableString(vendor), nullableString(version),
			checksum, finalPath, written, header.Filename,
		).Scan(&firmwareID)

		if err != nil {
			log.Printf("Failed to insert firmware record: %v", err)
			fail(c, http.StatusInternalServerError, "Failed to create firmware record")
			return
		}

		success(c, gin.H{
			"firmware_id":       firmwareID,
			"filename":          header.Filename,
			"size_bytes":        written,
			"checksum_sha256":   checksum,
			"storage_path":      finalPath,
			"analysis_status":   "pending",
			"message":           fmt.Sprintf("Firmware securely uploaded. Use POST /firmware/%s/analyze to start analysis.", firmwareID),
		})
	}
}

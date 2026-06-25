package config

import (
	"os"

	"github.com/joho/godotenv"
)

// Config holds all configuration values for the application.
type Config struct {
	DatabaseURL         string
	Port                string
	NetworkCIDR         string
	NVDAPIKey           string
	FirmwareAnalyzerURL string
	JWTSecret           string
	SlackWebhookURL     string
	TeamsWebhookURL     string
	S3Endpoint          string
	S3Bucket            string
	S3AccessKey         string
	S3SecretKey         string
}

// Load reads configuration from environment variables and .env files.
func Load() (*Config, error) {
	_ = godotenv.Load(".env", "../.env")

	cfg := &Config{
		DatabaseURL:         getEnv("DATABASE_URL", "postgres://ironmesh:changeme_strong_password_here@localhost:5432/ironmesh?sslmode=disable"),
		Port:                getEnv("PORT", "8080"),
		NetworkCIDR:         getEnv("NETWORK_CIDR", "192.168.1.0/24"),
		NVDAPIKey:           getEnv("NVD_API_KEY", ""),
		FirmwareAnalyzerURL: getEnv("FIRMWARE_ANALYZER_URL", "http://firmware-analyzer:8001"),
		JWTSecret:           getEnv("JWT_SECRET", ""),
		SlackWebhookURL:     getEnv("SLACK_WEBHOOK_URL", ""),
		TeamsWebhookURL:     getEnv("TEAMS_WEBHOOK_URL", ""),
		S3Endpoint:          getEnv("S3_ENDPOINT", ""),
		S3Bucket:            getEnv("S3_BUCKET", "ironmesh-firmware"),
		S3AccessKey:         getEnv("S3_ACCESS_KEY", ""),
		S3SecretKey:         getEnv("S3_SECRET_KEY", ""),
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

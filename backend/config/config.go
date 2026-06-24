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
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

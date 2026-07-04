package config

import (
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL         string
	Port                string
	NetworkCIDR         string
	NVDAPIKey           string
	FirmwareAnalyzerURL string
	JWTSecret           string
	JWTPrivateKeyFile   string
	SlackWebhookURL     string
	TeamsWebhookURL     string
	S3Endpoint          string
	S3Bucket            string
	S3AccessKey         string
	S3SecretKey         string
	RedisURL            string
	RateLimitPerMin     int
	ScanMaxConcurrent   int
	LogLevel            string
	DBMaxOpenConns      int
	DBMaxIdleConns      int
	DBConnMaxLifetime   time.Duration
}

func Load() (*Config, error) {
	_ = godotenv.Load(".env", "../.env")

	cfg := &Config{
		DatabaseURL:         getEnv("DATABASE_URL", "postgres://ironmesh:changeme_strong_password_here@localhost:5432/ironmesh?sslmode=disable"),
		Port:                getEnv("PORT", "8080"),
		NetworkCIDR:         getEnv("NETWORK_CIDR", "192.168.1.0/24"),
		NVDAPIKey:           getEnv("NVD_API_KEY", ""),
		FirmwareAnalyzerURL: getEnv("FIRMWARE_ANALYZER_URL", "http://firmware-analyzer:8001"),
		JWTSecret:           getEnv("JWT_SECRET", ""),
		JWTPrivateKeyFile:   getEnv("JWT_PRIVATE_KEY_FILE", ""),
		SlackWebhookURL:     getEnv("SLACK_WEBHOOK_URL", ""),
		TeamsWebhookURL:     getEnv("TEAMS_WEBHOOK_URL", ""),
		S3Endpoint:          getEnv("S3_ENDPOINT", ""),
		S3Bucket:            getEnv("S3_BUCKET", "ironmesh-firmware"),
		S3AccessKey:         getEnv("S3_ACCESS_KEY", ""),
		S3SecretKey:         getEnv("S3_SECRET_KEY", ""),
		RedisURL:            getEnv("REDIS_URL", ""),
		RateLimitPerMin:     getEnvInt("RATE_LIMIT_PER_MIN", 60),
		ScanMaxConcurrent:   getEnvInt("SCAN_MAX_CONCURRENT", 20),
		LogLevel:            getEnv("LOG_LEVEL", "info"),
		DBMaxOpenConns:      getEnvInt("DB_MAX_OPEN_CONNS", 25),
		DBMaxIdleConns:      getEnvInt("DB_MAX_IDLE_CONNS", 5),
		DBConnMaxLifetime:   time.Duration(getEnvInt("DB_CONN_MAX_LIFETIME_MINUTES", 5)) * time.Minute,
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return fallback
}

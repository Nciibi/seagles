package config

import (
	"os"
	"strconv"
	"strings"
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
	LogFormat           string
	DBMaxOpenConns      int
	DBMaxIdleConns      int
	DBConnMaxLifetime   time.Duration
	AllowedOrigins      []string

	// Data retention (days, 0 = disabled)
	RetentionScansDays         int
	RetentionAlertsDays        int
	RetentionAuditLogDays      int
	RetentionWebhookDelivDays  int

	// Webhook retry
	WebhookRetryMaxAttempts int
	WebhookRetryBaseDelayMs int

	// SMTP / Email
	SMTPServer  string
	SMTPPort    int
	SMTPUser    string
	SMTPPass    string
	SMTPFrom    string

	// TLS
	TLSEnabled  bool
	TLSCertFile string
	TLSKeyFile  string
}

func Load() (*Config, error) {
	_ = godotenv.Load(".env", "../.env")

	cfg := &Config{
		DatabaseURL:         getEnv("DATABASE_URL", ""),
		Port:                getEnv("PORT", "8080"),
		NetworkCIDR:         getEnv("NETWORK_CIDR", "192.168.1.0/24"),
		NVDAPIKey:           getEnv("NVD_API_KEY", ""),
		FirmwareAnalyzerURL: getEnv("FIRMWARE_ANALYZER_URL", "http://firmware-analyzer:8001"),
		JWTSecret:           getEnv("JWT_SECRET", ""),
		JWTPrivateKeyFile:   getEnv("JWT_PRIVATE_KEY_FILE", ""),
		SlackWebhookURL:     getEnv("SLACK_WEBHOOK_URL", ""),
		TeamsWebhookURL:     getEnv("TEAMS_WEBHOOK_URL", ""),
		S3Endpoint:          getEnv("S3_ENDPOINT", ""),
		S3Bucket:            getEnv("S3_BUCKET", "seagles-firmware"),
		S3AccessKey:         getEnv("S3_ACCESS_KEY", ""),
		S3SecretKey:         getEnv("S3_SECRET_KEY", ""),
		RedisURL:            getEnv("REDIS_URL", ""),
		RateLimitPerMin:     getEnvInt("RATE_LIMIT_PER_MIN", 60),
		ScanMaxConcurrent:   getEnvInt("SCAN_MAX_CONCURRENT", 20),
		LogLevel:            getEnv("LOG_LEVEL", "info"),
		LogFormat:           getEnv("LOG_FORMAT", "kv"),
		DBMaxOpenConns:      getEnvInt("DB_MAX_OPEN_CONNS", 25),
		DBMaxIdleConns:      getEnvInt("DB_MAX_IDLE_CONNS", 5),
		DBConnMaxLifetime:   time.Duration(getEnvInt("DB_CONN_MAX_LIFETIME_MINUTES", 5)) * time.Minute,
		AllowedOrigins:      getAllowedOrigins(getEnv("ALLOWED_ORIGINS", "")),

		RetentionScansDays:        getEnvInt("RETENTION_SCANS_DAYS", 90),
		RetentionAlertsDays:       getEnvInt("RETENTION_ALERTS_DAYS", 90),
		RetentionAuditLogDays:     getEnvInt("RETENTION_AUDIT_LOG_DAYS", 90),
		RetentionWebhookDelivDays: getEnvInt("RETENTION_WEBHOOK_DELIV_DAYS", 30),

		WebhookRetryMaxAttempts: getEnvInt("WEBHOOK_RETRY_MAX_ATTEMPTS", 3),
		WebhookRetryBaseDelayMs: getEnvInt("WEBHOOK_RETRY_BASE_DELAY_MS", 1000),

		SMTPServer: getEnv("SMTP_SERVER", ""),
		SMTPPort:   getEnvInt("SMTP_PORT", 587),
		SMTPUser:   getEnv("SMTP_USER", ""),
		SMTPPass:   getEnv("SMTP_PASS", ""),
		SMTPFrom:   getEnv("SMTP_FROM", ""),

		TLSEnabled:  getEnv("TLS_ENABLED", "") == "true",
		TLSCertFile: getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:  getEnv("TLS_KEY_FILE", ""),
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

func getAllowedOrigins(val string) []string {
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	origins := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			origins = append(origins, trimmed)
		}
	}
	return origins
}

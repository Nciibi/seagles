package config

import (
	"os"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	os.Clearenv()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.Port != "8080" {
		t.Fatalf("expected default port 8080, got %s", cfg.Port)
	}
	if cfg.DatabaseURL != "" {
		t.Fatalf("expected empty DatabaseURL, got %s", cfg.DatabaseURL)
	}
	if cfg.RateLimitPerMin != 60 {
		t.Fatalf("expected default RateLimitPerMin 60, got %d", cfg.RateLimitPerMin)
	}
	if cfg.ScanMaxConcurrent != 20 {
		t.Fatalf("expected default ScanMaxConcurrent 20, got %d", cfg.ScanMaxConcurrent)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("expected default LogLevel info, got %s", cfg.LogLevel)
	}
	if cfg.DBMaxOpenConns != 25 {
		t.Fatalf("expected default DBMaxOpenConns 25, got %d", cfg.DBMaxOpenConns)
	}
	if cfg.DBMaxIdleConns != 5 {
		t.Fatalf("expected default DBMaxIdleConns 5, got %d", cfg.DBMaxIdleConns)
	}
	if cfg.AllowedOrigins != nil {
		t.Fatalf("expected nil AllowedOrigins, got %v", cfg.AllowedOrigins)
	}
}

func TestLoad_EnvOverrides(t *testing.T) {
	os.Clearenv()
	os.Setenv("PORT", "9090")
	os.Setenv("DATABASE_URL", "postgres://user:pass@localhost/mydb")
	os.Setenv("RATE_LIMIT_PER_MIN", "200")
	os.Setenv("SCAN_MAX_CONCURRENT", "50")
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("DB_MAX_OPEN_CONNS", "100")
	os.Setenv("DB_MAX_IDLE_CONNS", "10")
	os.Setenv("ALLOWED_ORIGINS", "http://localhost:3000,https://app.example.com")
	os.Setenv("JWT_SECRET", "my-secret")
	os.Setenv("NVD_API_KEY", "nvd-key-123")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if cfg.Port != "9090" {
		t.Fatalf("expected PORT 9090, got %s", cfg.Port)
	}
	if cfg.DatabaseURL != "postgres://user:pass@localhost/mydb" {
		t.Fatalf("expected DATABASE_URL to be overridden, got %s", cfg.DatabaseURL)
	}
	if cfg.RateLimitPerMin != 200 {
		t.Fatalf("expected RATE_LIMIT_PER_MIN 200, got %d", cfg.RateLimitPerMin)
	}
	if cfg.ScanMaxConcurrent != 50 {
		t.Fatalf("expected SCAN_MAX_CONCURRENT 50, got %d", cfg.ScanMaxConcurrent)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("expected LOG_LEVEL debug, got %s", cfg.LogLevel)
	}
	if cfg.DBMaxOpenConns != 100 {
		t.Fatalf("expected DB_MAX_OPEN_CONNS 100, got %d", cfg.DBMaxOpenConns)
	}
	if cfg.DBMaxIdleConns != 10 {
		t.Fatalf("expected DB_MAX_IDLE_CONNS 10, got %d", cfg.DBMaxIdleConns)
	}
	if cfg.JWTSecret != "my-secret" {
		t.Fatalf("expected JWT_SECRET my-secret, got %s", cfg.JWTSecret)
	}
	if cfg.NVDAPIKey != "nvd-key-123" {
		t.Fatalf("expected NVD_API_KEY nvd-key-123, got %s", cfg.NVDAPIKey)
	}
	if len(cfg.AllowedOrigins) != 2 {
		t.Fatalf("expected 2 allowed origins, got %d", len(cfg.AllowedOrigins))
	}
	if cfg.AllowedOrigins[0] != "http://localhost:3000" {
		t.Fatalf("expected origin http://localhost:3000, got %s", cfg.AllowedOrigins[0])
	}
}

func TestLoad_InvalidIntFallback(t *testing.T) {
	os.Clearenv()
	os.Setenv("RATE_LIMIT_PER_MIN", "not-a-number")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.RateLimitPerMin != 60 {
		t.Fatalf("expected fallback 60, got %d", cfg.RateLimitPerMin)
	}
}

func TestLoad_DatabaseURLRequired(t *testing.T) {
	os.Clearenv()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if cfg.DatabaseURL != "" {
		t.Fatalf("expected empty DatabaseURL without env set, got %s", cfg.DatabaseURL)
	}
}

func TestGetEnv(t *testing.T) {
	os.Clearenv()
	os.Setenv("EXISTING_KEY", "value")

	result := getEnv("EXISTING_KEY", "fallback")
	if result != "value" {
		t.Fatalf("expected 'value', got '%s'", result)
	}

	result = getEnv("MISSING_KEY", "fallback")
	if result != "fallback" {
		t.Fatalf("expected 'fallback', got '%s'", result)
	}
}

func TestGetEnvInt(t *testing.T) {
	os.Clearenv()
	os.Setenv("INT_KEY", "42")

	result := getEnvInt("INT_KEY", 0)
	if result != 42 {
		t.Fatalf("expected 42, got %d", result)
	}

	result = getEnvInt("MISSING_INT", 99)
	if result != 99 {
		t.Fatalf("expected 99, got %d", result)
	}

	os.Setenv("INVALID_INT", "not-a-number")
	result = getEnvInt("INVALID_INT", 77)
	if result != 77 {
		t.Fatalf("expected 77, got %d", result)
	}
}

func TestGetAllowedOrigins(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"", 0},
		{"http://localhost:3000", 1},
		{"http://localhost:3000,https://app.com", 2},
		{"  http://a.com  ,  https://b.com  ", 2},
		{",,http://a.com,,", 1},
	}
	for _, tt := range tests {
		result := getAllowedOrigins(tt.input)
		if len(result) != tt.want {
			t.Errorf("getAllowedOrigins(%q) returned %d items, want %d", tt.input, len(result), tt.want)
		}
	}
}

package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL string
	Port        string
	NetworkCIDR string
	NVDAPIKey   string
}

func Load() (*Config, error) {
	_ = godotenv.Load(".env", "../.env")

	cfg := &Config{
		DatabaseURL: fmt.Sprintf("postgres://user:%s@localhost:5432/seagles?sslmode=disable", getEnv("DB_PASSWORD", "changeme_strong_password_here")),
		Port:        getEnv("PORT", "8080"),
		NetworkCIDR: getEnv("NETWORK_CIDR", "192.168.1.0/24"),
		NVDAPIKey:   getEnv("NVD_API_KEY", ""),
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

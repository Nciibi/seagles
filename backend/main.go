package main

import (
	"log"

	"github.com/yourusername/seagles/alerts"
	"github.com/yourusername/seagles/api"
	"github.com/yourusername/seagles/auth"
	"github.com/yourusername/seagles/config"
	"github.com/yourusername/seagles/db"
	"github.com/yourusername/seagles/kev"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Configure JWT secret from environment
	auth.SetJWTSecret(cfg.JWTSecret)

	// Connect to database
	database := db.Connect(cfg.DatabaseURL)
	defer database.Close()

	// Run migrations
	db.RunMigrations(database)

	// Start KEV updater (background refresh every 24h)
	kevCatalog := kev.StartKEVUpdater("data/cisa-kev.json")

	// Start EPSS updater (background refresh every 6h)
	kev.StartEPSSUpdater(database)

	// Start alert monitor (background checks every 60s)
	go alerts.StartAlertMonitor(database)

	// Create and start the API server
	router := api.NewRouter(database, cfg, kevCatalog)

	log.Printf("IronMesh API v2.0.0 running on :%s", cfg.Port)
	log.Printf("Default admin credentials: admin / changeme")
	log.Fatal(router.Run(":" + cfg.Port))
}

package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Nciibi/seagles/alerts"
	"github.com/Nciibi/seagles/api"
	"github.com/Nciibi/seagles/auth"
	"github.com/Nciibi/seagles/config"
	"github.com/Nciibi/seagles/db"
	"github.com/Nciibi/seagles/kev"
	"github.com/Nciibi/seagles/scanner"
	"github.com/Nciibi/seagles/slog"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	jwtKey := cfg.JWTSecret
	if jwtKey == "" && cfg.JWTPrivateKeyFile != "" {
		if keyData, err := os.ReadFile(cfg.JWTPrivateKeyFile); err == nil {
			jwtKey = string(keyData)
		}
	}
	auth.SetJWTSecret(jwtKey)

	database := db.Connect(cfg.DatabaseURL)
	defer database.Close()

	db.RunMigrations(database)

	kevCatalog := kev.StartKEVUpdater("data/cisa-kev.json")
	kev.StartEPSSUpdater(database)

	go alerts.StartAlertMonitor(database)

	passiveMonitor := scanner.NewPassiveMonitor(database, "")
	go passiveMonitor.Start()

	router := api.NewRouter(database, cfg, kevCatalog)

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: router,
	}

	go func() {
		slog.Info("IronMesh API v2.0.0", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	slog.Info("Shutting down server", "signal", sig.String())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	passiveMonitor.Stop()
	slog.Info("Server exited gracefully")
}

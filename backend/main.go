package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
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
	"github.com/Nciibi/seagles/retention"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	slog.SetLevel(parseLogLevel(cfg.LogLevel))
	slog.SetFormat(cfg.LogFormat)

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

	var wg sync.WaitGroup

	kevCatalog := kev.StartKEVUpdater("data/cisa-kev.json")
	kev.StartEPSSUpdater(database)

	wg.Add(1)
	go func() {
		defer wg.Done()
		alerts.StartAlertMonitor(database)
	}()

	passiveMonitor := scanner.NewPassiveMonitor(database, "")
	wg.Add(1)
	go func() {
		defer wg.Done()
		passiveMonitor.Start()
	}()

	if cfg.RetentionScansDays > 0 || cfg.RetentionAlertsDays > 0 ||
		cfg.RetentionAuditLogDays > 0 || cfg.RetentionWebhookDelivDays > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			retention.StartRetentionJob(database, cfg)
		}()
		slog.Info("Data retention job enabled",
			"scans_days", cfg.RetentionScansDays,
			"alerts_days", cfg.RetentionAlertsDays,
			"audit_log_days", cfg.RetentionAuditLogDays,
			"webhook_deliv_days", cfg.RetentionWebhookDelivDays)
	}

	router := api.NewRouter(database, cfg, kevCatalog)

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: router,
	}

	useTLS := cfg.TLSEnabled && cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
	if useTLS {
		slog.Info("TLS enabled", "cert", cfg.TLSCertFile)
	}

	go func() {
		slog.Info("Seagles API v2.1.0", "port", cfg.Port, "log_format", cfg.LogFormat)
		var serveErr error
		if useTLS {
			serveErr = srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			serveErr = srv.ListenAndServe()
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", serveErr)
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

	slog.Info("Waiting for background goroutines to finish...")
	wg.Wait()

	passiveMonitor.Stop()
	slog.Info("Server exited gracefully")
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

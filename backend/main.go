package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Nciibi/seagles/alerts"
	"github.com/Nciibi/seagles/api"
	"github.com/Nciibi/seagles/auth"
	"github.com/Nciibi/seagles/config"
	"github.com/Nciibi/seagles/db"
	"github.com/Nciibi/seagles/kev"
	"github.com/Nciibi/seagles/retention"
	"github.com/Nciibi/seagles/scanner"
	"github.com/Nciibi/seagles/slog"
)

// drainTimeout is how long in-flight HTTP requests get to finish after
// SIGTERM. Kubernetes' terminationGracePeriodSeconds must exceed this (the
// backend manifest sets 45s) so the process is never SIGKILLed mid-drain.
const drainTimeout = 30 * time.Second

const REQUIRE_SHARED_JWT_KEY_MSG = `no JWT signing key is configured, and REQUIRE_SHARED_JWT_KEY is set.

Refusing to start: without a shared key this process generates its own RSA key
pair, so every replica and every restart uses a different key. Access tokens
minted by one instance then fail signature verification on the others, users
see intermittent 401s, and each rollout invalidates every session.

Configure one of:
  JWT_SECRET             an RSA private key in PEM form (single line, newlines
                         encoded as \n)
  JWT_PRIVATE_KEY_FILE   path to a PEM file readable by this process

Generate a key with:
  openssl genrsa 2048 | tee jwt-private.pem
  kubectl -n security-tools create secret generic seagles-jwt-secret \
    --from-file=secret=jwt-private.pem

To run a deliberate single-instance deployment instead, unset
REQUIRE_SHARED_JWT_KEY.`

// resolveJWTKey returns the PEM signing key from configuration, preferring the
// inline JWT_SECRET and falling back to JWT_PRIVATE_KEY_FILE.
//
// A configured-but-unreadable key file is a hard error. It used to be ignored
// (`if keyData, err := os.ReadFile(...); err == nil`), which silently fell
// through to generating a per-process key — turning a missing mount or bad
// permissions into an authentication outage rather than a startup failure.
func resolveJWTKey(cfg *config.Config) (string, error) {
	if key := strings.TrimSpace(cfg.JWTSecret); key != "" {
		return key, nil
	}

	if cfg.JWTPrivateKeyFile == "" {
		return "", nil
	}

	keyData, err := os.ReadFile(cfg.JWTPrivateKeyFile)
	if err != nil {
		return "", fmt.Errorf("JWT_PRIVATE_KEY_FILE is set to %q but could not be read: %w",
			cfg.JWTPrivateKeyFile, err)
	}
	if len(strings.TrimSpace(string(keyData))) == 0 {
		return "", fmt.Errorf("JWT_PRIVATE_KEY_FILE %q is empty; expected an RSA private key in PEM form",
			cfg.JWTPrivateKeyFile)
	}
	return string(keyData), nil
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	slog.SetLevel(parseLogLevel(cfg.LogLevel))
	slog.SetFormat(cfg.LogFormat)

	jwtKey, err := resolveJWTKey(cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}
	auth.SetJWTSecret(jwtKey)

	if auth.UsingEphemeralKey() {
		// An auto-generated key is unique to this process. A single local
		// instance is fine; a second replica or a restart silently invalidates
		// every issued token.
		if cfg.RequireSharedJWTKey {
			log.Fatalf(REQUIRE_SHARED_JWT_KEY_MSG)
		}
		slog.Warn("Starting with an auto-generated JWT signing key. This is " +
			"acceptable for a single local instance only. Set REQUIRE_SHARED_JWT_KEY=true " +
			"along with JWT_SECRET or JWT_PRIVATE_KEY_FILE for any multi-replica deployment.")
	}

	database := db.Connect(cfg.DatabaseURL, cfg.DBMaxOpenConns, cfg.DBMaxIdleConns, cfg.DBConnMaxLifetime)
	defer database.Close()

	if err := db.RunMigrations(database); err != nil {
		log.Fatalf("Database migration failed: %v", err)
	}

	var wg sync.WaitGroup

	stopAlertMonitor := make(chan struct{})
	stopRetention := make(chan struct{})

	kevCatalog := kev.StartKEVUpdater("data/cisa-kev.json")
	kev.StartEPSSUpdater(database)

	wg.Add(1)
	go func() {
		defer wg.Done()
		alerts.StartAlertMonitor(database, stopAlertMonitor)
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
			retention.StartRetentionJob(database, cfg, stopRetention)
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

	// Stop the background workers FIRST so they wind down in parallel with the
	// HTTP drain rather than competing with it. They are periodic jobs with no
	// dependency on in-flight requests, so signalling them early cannot lose
	// request state — and it gives a long-running retention purge the whole
	// grace period to finish instead of being SIGKILLed at the end of it.
	//
	// Every one of these loops must observe its stop channel: an infinite
	// `for range ticker.C` would make the wg.Wait() below block forever, the
	// container would be SIGKILLed at terminationGracePeriodSeconds, and any
	// scan, alert dispatch or webhook retry still running would be dropped.
	close(stopAlertMonitor)
	close(stopRetention)
	passiveMonitor.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		// Requests outlived the drain budget. Log rather than log.Fatalf:
		// the background workers still need to be reaped, and exiting here
		// would skip wg.Wait() and turn a slow drain into a hard kill.
		slog.Error("HTTP drain exceeded budget, forcing close",
			"error", err.Error(), "timeout", drainTimeout.String())
		_ = srv.Close()
	}

	slog.Info("Waiting for background goroutines to finish...")
	wg.Wait()

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

package retention

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/Nciibi/seagles/config"
	"github.com/Nciibi/seagles/slog"
)
func StartRetentionJob(db *sql.DB, cfg *config.Config) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	runOnce(db, cfg)

	for range ticker.C {
		runOnce(db, cfg)
	}
}

// purgeTarget pairs a table with the timestamp column its retention policy is
// measured against. Both fields are compile-time constants declared in this
// file — never user input — and TestPurgeTargetsMatchSchema verifies every
// pairing against the actual migration SQL.
type purgeTarget struct {
	table  string
	column string
}

func (p purgeTarget) query() string {
	return fmt.Sprintf("DELETE FROM %s WHERE %s < NOW() - make_interval(days => $1)",
		p.table, p.column)
}

var (
	purgeScans           = purgeTarget{"scans", "started_at"}
	purgeAlerts          = purgeTarget{"alerts", "triggered_at"}
	purgeAuditLog        = purgeTarget{"audit_log", "created_at"}
	purgeWebhookDelivery = purgeTarget{"webhook_deliveries", "delivered_at"}
)

func runOnce(db *sql.DB, cfg *config.Config) {
	if cfg.RetentionScansDays > 0 {
		purgeOld(db, purgeScans, cfg.RetentionScansDays)
	}
	if cfg.RetentionAlertsDays > 0 {
		purgeOld(db, purgeAlerts, cfg.RetentionAlertsDays)
	}
	if cfg.RetentionAuditLogDays > 0 {
		purgeOld(db, purgeAuditLog, cfg.RetentionAuditLogDays)
	}
	if cfg.RetentionWebhookDelivDays > 0 {
		// webhook_deliveries has no created_at column: 008_create_webhooks.sql
		// declares only delivered_at. The previous query used created_at, so
		// this purge failed with "column does not exist" on every run and the
		// table grew without bound.
		purgeOld(db, purgeWebhookDelivery, cfg.RetentionWebhookDelivDays)
	}
}

func purgeOld(db *sql.DB, target purgeTarget, days int) {
	// Pass an integer day count into make_interval() instead of a Go
	// duration string cast to ::interval — the old format ("2160h0m0s") only
	// worked by luck of Postgres's lenient parser and is not guaranteed.
	result, err := db.Exec(target.query(), days)
	if err != nil {
		slog.Error("retention purge failed", "table", target.table, "error", err.Error())
		return
	}
	count, _ := result.RowsAffected()
	if count > 0 {
		slog.Info("retention purge completed", "table", target.table, "deleted", count)
	}
}

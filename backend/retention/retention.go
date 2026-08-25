package retention

import (
	"database/sql"
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

func runOnce(db *sql.DB, cfg *config.Config) {
	if cfg.RetentionScansDays > 0 {
		purgeOld(db, "DELETE FROM scans WHERE started_at < NOW() - make_interval(days => $1)",
			cfg.RetentionScansDays, "scans")
	}
	if cfg.RetentionAlertsDays > 0 {
		purgeOld(db, "DELETE FROM alerts WHERE triggered_at < NOW() - make_interval(days => $1)",
			cfg.RetentionAlertsDays, "alerts")
	}
	if cfg.RetentionAuditLogDays > 0 {
		purgeOld(db, "DELETE FROM audit_log WHERE created_at < NOW() - make_interval(days => $1)",
			cfg.RetentionAuditLogDays, "audit_log")
	}
	if cfg.RetentionWebhookDelivDays > 0 {
		purgeOld(db, "DELETE FROM webhook_deliveries WHERE created_at < NOW() - make_interval(days => $1)",
			cfg.RetentionWebhookDelivDays, "webhook_deliveries")
	}
}

func purgeOld(db *sql.DB, query string, days int, table string) {
	// Pass an integer day count into make_interval() instead of a Go
	// duration string cast to ::interval — the old format ("2160h0m0s") only
	// worked by luck of Postgres's lenient parser and is not guaranteed.
	result, err := db.Exec(query, days)
	if err != nil {
		slog.Error("retention purge failed", "table", table, "error", err.Error())
		return
	}
	count, _ := result.RowsAffected()
	if count > 0 {
		slog.Info("retention purge completed", "table", table, "deleted", count)
	}
}

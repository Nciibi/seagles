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
		purgeOld(db, "DELETE FROM scans WHERE started_at < NOW() - $1::INTERVAL",
			cfg.RetentionScansDays, "scans")
	}
	if cfg.RetentionAlertsDays > 0 {
		purgeOld(db, "DELETE FROM alerts WHERE triggered_at < NOW() - $1::INTERVAL",
			cfg.RetentionAlertsDays, "alerts")
	}
	if cfg.RetentionAuditLogDays > 0 {
		purgeOld(db, "DELETE FROM audit_log WHERE created_at < NOW() - $1::INTERVAL",
			cfg.RetentionAuditLogDays, "audit_log")
	}
	if cfg.RetentionWebhookDelivDays > 0 {
		purgeOld(db, "DELETE FROM webhook_deliveries WHERE delivered_at < NOW() - $1::INTERVAL",
			cfg.RetentionWebhookDelivDays, "webhook_deliveries")
	}
}

func purgeOld(db *sql.DB, query string, days int, table string) {
	interval := time.Duration(days) * 24 * time.Hour
	result, err := db.Exec(query, interval.String())
	if err != nil {
		slog.Error("retention purge failed", "table", table, "error", err.Error())
		return
	}
	count, _ := result.RowsAffected()
	if count > 0 {
		slog.Info("retention purge completed", "table", table, "deleted", count)
	}
}

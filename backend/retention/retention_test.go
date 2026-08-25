package retention

import (
	"database/sql"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/Nciibi/seagles/config"
)

func newMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, mock
}

func TestRunOnce_ZeroConfigDoesNothing(t *testing.T) {
	db, mock := newMockDB(t)

	runOnce(db, &config.Config{})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expected no queries for zero retention config: %v", err)
	}
}

func TestRunOnce_PurgesAllTables(t *testing.T) {
	db, mock := newMockDB(t)
	cfg := &config.Config{
		RetentionScansDays:        30,
		RetentionAlertsDays:       90,
		RetentionAuditLogDays:     90,
		RetentionWebhookDelivDays: 14,
	}

	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM scans WHERE started_at < NOW() - make_interval(days => $1)")).
		WithArgs(30).
		WillReturnResult(sqlmock.NewResult(0, 5))
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM alerts WHERE triggered_at < NOW() - make_interval(days => $1)")).
		WithArgs(90).
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM audit_log WHERE created_at < NOW() - make_interval(days => $1)")).
		WithArgs(90).
		WillReturnResult(sqlmock.NewResult(0, 10))
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM webhook_deliveries WHERE created_at < NOW() - make_interval(days => $1)")).
		WithArgs(14).
		WillReturnResult(sqlmock.NewResult(0, 1))

	runOnce(db, cfg)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRunOnce_PurgeErrorIsSwallowed(t *testing.T) {
	db, mock := newMockDB(t)
	cfg := &config.Config{RetentionScansDays: 7}

	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM scans WHERE started_at < NOW() - make_interval(days => $1)")).
		WithArgs(7).
		WillReturnError(sqlmock.ErrCancelled)

	runOnce(db, cfg)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPurgeOld_UsesTypedDayParameter(t *testing.T) {
	// The purge must bind an integer day count into make_interval(), not a
	// Go duration string ("2160h0m0s") cast to ::interval.
	if !strings.Contains(makeIntervalQuery("scans"), "make_interval(days => $1)") &&
		!strings.Contains(purgeScansQuery, "make_interval(days => $1)") {
		t.Fatal("expected make_interval(days => $1) in purge query")
	}
}

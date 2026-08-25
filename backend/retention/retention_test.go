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

	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM scans")).
		WithArgs("720h0m0s").
		WillReturnResult(sqlmock.NewResult(0, 5))
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM alerts")).
		WithArgs("2160h0m0s").
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM audit_log")).
		WithArgs("2160h0m0s").
		WillReturnResult(sqlmock.NewResult(0, 10))
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM webhook_deliveries")).
		WithArgs("336h0m0s").
		WillReturnResult(sqlmock.NewResult(0, 1))

	runOnce(db, cfg)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRunOnce_PurgeErrorIsSwallowed(t *testing.T) {
	db, mock := newMockDB(t)
	cfg := &config.Config{RetentionScansDays: 7}

	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM scans")).
		WithArgs("168h0m0s").
		WillReturnError(sqlmock.ErrCancelled)

	runOnce(db, cfg)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPurgeOld_IntervalFormat(t *testing.T) {
	cases := map[int]string{
		1:   "24h0m0s",
		7:   "168h0m0s",
		90:  "2160h0m0s",
		365: "8760h0m0s",
	}
	for days, want := range cases {
		got := (time.Duration(days) * 24 * time.Hour).String()
		if got != want {
			t.Errorf("interval for %d days = %q, want %q", days, got, want)
		}
	}
}

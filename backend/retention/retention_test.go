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
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM webhook_deliveries WHERE delivered_at < NOW() - make_interval(days => $1)")).
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

// The make_interval SQL shape is asserted exactly by the sqlmock expectations
// in TestRunOnce_PurgesAllTables / TestRunOnce_PurgeErrorIsSwallowed above;
// a separate string test would only duplicate them.

// Regression guard for the graceful-shutdown deadlock: main() adds this job to
// a sync.WaitGroup and waits on it during SIGTERM handling. When the loop was
// `for range ticker.C` with no stop channel it never returned, wg.Wait()
// blocked forever, and the container was SIGKILLed at the end of its
// termination grace period — dropping every in-flight scan, alert dispatch and
// webhook retry.
func TestStartRetentionJobReturnsWhenStopped(t *testing.T) {
	db, _ := newMockDB(t)
	// Zero retention config: runOnce issues no queries.
	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		StartRetentionJob(db, &config.Config{}, stop)
	}()

	close(stop)

	select {
	case <-done:
		// Returned promptly: wg.Wait() can complete.
	case <-time.After(5 * time.Second):
		t.Fatal("StartRetentionJob did not return after its stop channel was " +
			"closed; wg.Wait() in main() would deadlock and the container " +
			"would be SIGKILLed on every deploy")
	}
}

// The job must keep running until told to stop, i.e. it must not exit on its
// own after the initial purge.
func TestStartRetentionJobKeepsRunningUntilStopped(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM scans WHERE started_at < NOW() - make_interval(days => $1)")).
		WithArgs(30).
		WillReturnResult(sqlmock.NewResult(0, 1))

	cfg := &config.Config{RetentionScansDays: 30}
	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		StartRetentionJob(db, cfg, stop)
	}()

	// The initial purge should have run; the goroutine should still be alive.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mock.ExpectationsWereMet() == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("initial purge did not run: %v", err)
	}

	select {
	case <-done:
		t.Fatal("StartRetentionJob exited without being stopped")
	case <-time.After(100 * time.Millisecond):
		// Still running, as expected.
	}

	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("did not stop after close(stop)")
	}
}

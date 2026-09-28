package db

import (
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
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

func setMigrationsDir(t *testing.T, dir string) {
	t.Helper()
	const envKey = "MIGRATIONS_DIR"
	oldVal, hadVal := os.LookupEnv(envKey)
	t.Cleanup(func() {
		if hadVal {
			os.Setenv(envKey, oldVal)
		} else {
			os.Unsetenv(envKey)
		}
	})
	os.Setenv(envKey, dir)
}

func TestNewDBMonitor_InitiallyHealthy(t *testing.T) {
	db, _ := newMockDB(t)

	m := NewDBMonitor(db)
	if !m.IsHealthy() {
		t.Error("fresh monitor should report healthy")
	}
	if !m.LastChecked().IsZero() {
		t.Errorf("LastChecked should be zero before first tick, got %v", m.LastChecked())
	}
}

func TestIsHealthy_NoMonitor(t *testing.T) {
	saved := monitor
	t.Cleanup(func() { monitor = saved })

	monitor = nil
	if IsHealthy() {
		t.Error("IsHealthy with nil monitor should be false")
	}

	db, _ := newMockDB(t)
	monitor = NewDBMonitor(db)
	if !IsHealthy() {
		t.Error("IsHealthy with healthy monitor should be true")
	}
}

func TestFindMigrationsDir_EnvOverride(t *testing.T) {
	dir := t.TempDir()
	setMigrationsDir(t, dir)

	if got := findMigrationsDir(); got != dir {
		t.Errorf("findMigrationsDir() = %q, want %q", got, dir)
	}
}

func TestFindMigrationsDir_CWDRelativeFallback(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Skipf("cannot get cwd: %v", err)
	}
	fallback := filepath.Join(cwd, "db", "migrations")
	if info, statErr := os.Stat(fallback); statErr != nil || !info.IsDir() {
		t.Skip("no db/migrations dir relative to cwd; fallback path not reachable")
	}

	os.Unsetenv("MIGRATIONS_DIR")
	defer os.Unsetenv("MIGRATIONS_DIR")

	if got := findMigrationsDir(); got != fallback {
		t.Errorf("findMigrationsDir() = %q, want %q", got, fallback)
	}
}


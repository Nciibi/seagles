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

func TestRunMigrations_ExecutesSQLFilesInSortedOrder(t *testing.T) {
	dir := t.TempDir()

	files := map[string]string{
		"002_second.sql": "CREATE TABLE b (id int);",
		"001_first.sql":  "CREATE TABLE a (id int);",
		"003_third.sql":  "CREATE TABLE c (id int);",
		"notes.txt":      "not a migration",
		"README.md":      "also not a migration",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	setMigrationsDir(t, dir)

	db, mock := newMockDB(t)
	mock.ExpectExec(regexp.QuoteMeta("CREATE TABLE a (id int);")).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("CREATE TABLE b (id int);")).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("CREATE TABLE c (id int);")).WillReturnResult(sqlmock.NewResult(0, 0))

	RunMigrations(db)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (order or count wrong): %v", err)
	}
}

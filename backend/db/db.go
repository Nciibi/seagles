package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nciibi/seagles/slog"
	_ "github.com/lib/pq"
)

type DBMonitor struct {
	db          *sql.DB
	healthy     int32
	lastChecked time.Time
	mu          sync.RWMutex
}

func NewDBMonitor(database *sql.DB) *DBMonitor {
	m := &DBMonitor{
		db:      database,
		healthy: 1,
	}
	go m.startHealthChecks()
	return m
}

func (m *DBMonitor) startHealthChecks() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		healthy := true
		if err := m.db.Ping(); err != nil {
			healthy = false
			slog.Error("Database health check failed", "error", err.Error())

			for retries := 0; retries < 5; retries++ {
				time.Sleep(2 * time.Second)
				if err := m.db.Ping(); err == nil {
					healthy = true
					slog.Info("Database reconnected after retry")
					break
				}
			}
		}

		if healthy {
			atomic.StoreInt32(&m.healthy, 1)
		} else {
			atomic.StoreInt32(&m.healthy, 0)
		}

		m.mu.Lock()
		m.lastChecked = time.Now()
		m.mu.Unlock()
	}
}

func (m *DBMonitor) IsHealthy() bool {
	return atomic.LoadInt32(&m.healthy) == 1
}

func (m *DBMonitor) LastChecked() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastChecked
}

var monitor *DBMonitor

func Connect(databaseURL string, maxOpenConns, maxIdleConns int, connMaxLifetime time.Duration) *sql.DB {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		slog.Fatal("Failed to open database connection", "error", err.Error())
	}

	// Apply caller-supplied pool settings (falling back to sane defaults so
	// callers that don't care can pass zero values).
	if maxOpenConns <= 0 {
		maxOpenConns = 25
	}
	if maxIdleConns <= 0 {
		maxIdleConns = 5
	}
	if connMaxLifetime <= 0 {
		connMaxLifetime = 5 * time.Minute
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetConnMaxIdleTime(2 * time.Minute)

	if err := db.Ping(); err != nil {
		slog.Fatal("Failed to ping database", "error", err.Error())
	}

	monitor = NewDBMonitor(db)

	slog.Info("Database connection established")
	return db
}

// Migration is a single numbered SQL file on disk.
type Migration struct {
	Version  string
	Path     string
	Content  string
	Checksum string
}

// DiscoverMigrations reads every *.sql file in dir, in lexical order. The
// files are zero-padded (001_, 015_), so lexical order is apply order.
func DiscoverMigrations(dir string) ([]Migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations directory %s: %w", dir, err)
	}

	var out []Migration
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		sum := sha256.Sum256(content)
		out = append(out, Migration{
			Version:  entry.Name(),
			Path:     filepath.Join(dir, entry.Name()),
			Content:  string(content),
			Checksum: hex.EncodeToString(sum[:]),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

const migrationTableDDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    checksum   TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`

func ensureMigrationTable(db *sql.DB) error {
	if _, err := db.Exec(migrationTableDDL); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	return nil
}

func appliedMigrations(db *sql.DB) (map[string]string, error) {
	rows, err := db.Query(`SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()

	out := make(map[string]string)
	for rows.Next() {
		var version, checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			return nil, fmt.Errorf("scan schema_migrations: %w", err)
		}
		out[version] = checksum
	}
	return out, rows.Err()
}

// RunMigrations applies every migration that has not been applied yet, each in
// its own transaction, and records it in schema_migrations.
//
// Why this exists: the previous implementation re-executed every file on every
// boot and relied entirely on each file being individually idempotent. That is
// fragile now that migrations are non-trivial. Two concrete failures observed
// against PostgreSQL 16 while adding tenant scoping:
//
//  1. A migration that fails part-way leaves earlier statements committed,
//     because psql-style multi-statement Exec is not atomic. Re-running then
//     executes a file whose preconditions a previous partial run destroyed.
//  2. Migration 015 replaces the global unique constraint on users.username
//     with a tenant-scoped one. Re-running 006 afterwards fails with
//     "there is no unique or exclusion constraint matching the ON CONFLICT
//     specification", so the database could not be migrated at all.
//
// Applying each file exactly once, transactionally, removes both failure
// modes and makes the applied set auditable in the database itself.
func RunMigrations(db *sql.DB) error {
	migrationsDir := findMigrationsDir()
	migrations, err := DiscoverMigrations(migrationsDir)
	if err != nil {
		return err
	}

	if err := ensureMigrationTable(db); err != nil {
		return err
	}

	applied, err := appliedMigrations(db)
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if prev, ok := applied[m.Version]; ok {
			if prev != m.Checksum {
				return fmt.Errorf(
					"migration %s was modified after it was applied "+
						"(recorded checksum %s, file checksum %s); "+
						"add a new migration instead of editing an applied one",
					m.Version, prev[:12], m.Checksum[:12])
			}
			continue
		}

		slog.Info("Running migration", "file", m.Version)

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", m.Version, err)
		}

		if _, err := tx.Exec(m.Content); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %s failed: %w", m.Version, err)
		}

		if _, err := tx.Exec(
			`INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)`,
			m.Version, m.Checksum,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", m.Version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", m.Version, err)
		}
	}

	slog.Info("Migrations up to date", "count", len(migrations))
	return nil
}

func findMigrationsDir() string {
	candidates := []string{
		"db/migrations",
		"backend/db/migrations",
		"../db/migrations",
	}

	if envPath := os.Getenv("MIGRATIONS_DIR"); envPath != "" {
		if info, err := os.Stat(envPath); err == nil && info.IsDir() {
			return envPath
		}
	}

	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}

	execPath, err := os.Executable()
	if err == nil {
		execDir := filepath.Dir(execPath)
		candidate := filepath.Join(execDir, "db", "migrations")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}

	slog.Fatal(fmt.Sprintf("Could not find migrations directory. Tried: %v", candidates))
	return ""
}

func GetMonitor() *DBMonitor {
	return monitor
}

func IsHealthy() bool {
	if monitor == nil {
		return false
	}
	return monitor.IsHealthy()
}

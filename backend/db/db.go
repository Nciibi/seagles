package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/lib/pq"
	"github.com/Nciibi/seagles/slog"
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

func Connect(databaseURL string) *sql.DB {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		slog.Fatal("Failed to open database connection", "error", err.Error())
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(2 * time.Minute)

	if err := db.Ping(); err != nil {
		slog.Fatal("Failed to ping database", "error", err.Error())
	}

	monitor = NewDBMonitor(db)

	slog.Info("Database connection established")
	return db
}

func RunMigrations(db *sql.DB) {
	migrationsDir := findMigrationsDir()
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		slog.Fatal("Failed to read migrations directory", "path", migrationsDir, "error", err.Error())
	}

	var sqlFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			sqlFiles = append(sqlFiles, entry.Name())
		}
	}
	sort.Strings(sqlFiles)

	for _, file := range sqlFiles {
		filePath := filepath.Join(migrationsDir, file)
		content, err := os.ReadFile(filePath)
		if err != nil {
			slog.Fatal("Failed to read migration file", "file", file, "error", err.Error())
		}

		slog.Info("Running migration", "file", file)
		if _, err := db.Exec(string(content)); err != nil {
			slog.Fatal("Migration failed", "file", file, "error", err.Error())
		}
	}

	slog.Info("All migrations completed successfully")
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

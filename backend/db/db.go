package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// Connect opens a PostgreSQL connection using lib/pq and configures connection pool settings.
func Connect(databaseURL string) *sql.DB {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		log.Fatalf("Failed to open database connection: %v", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Println("Database connection established")
	return db
}

// RunMigrations reads all .sql files from the db/migrations/ directory in alphabetical
// order and executes them in sequence against the database.
func RunMigrations(db *sql.DB) {
	migrationsDir := findMigrationsDir()
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		log.Fatalf("Failed to read migrations directory %s: %v", migrationsDir, err)
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
			log.Fatalf("Failed to read migration file %s: %v", file, err)
		}

		log.Printf("Running migration: %s", file)
		if _, err := db.Exec(string(content)); err != nil {
			log.Fatalf("Migration %s failed: %v", file, err)
		}
	}

	log.Println("All migrations completed successfully")
}

// findMigrationsDir searches for the migrations directory relative to common locations.
func findMigrationsDir() string {
	candidates := []string{
		"db/migrations",
		"backend/db/migrations",
		"../db/migrations",
	}

	// Check if an absolute path is set via env var
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

	// Try from executable directory
	execPath, err := os.Executable()
	if err == nil {
		execDir := filepath.Dir(execPath)
		candidate := filepath.Join(execDir, "db", "migrations")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}

	log.Fatal(fmt.Sprintf("Could not find migrations directory. Tried: %v", candidates))
	return ""
}

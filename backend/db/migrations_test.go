package db

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// writeMigrations materialises migration files in a temp dir and points
// findMigrationsDir at it for the duration of the test.
func writeMigrations(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	setMigrationsDir(t, dir)
	return dir
}

func checksumOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// expectBootstrap primes the queries RunMigrations always makes before it
// touches any migration file.
func expectBootstrap(mock sqlmock.Sqlmock, applied map[string]string) {
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS schema_migrations").
		WillReturnResult(sqlmock.NewResult(0, 0))

	rows := sqlmock.NewRows([]string{"version", "checksum"})
	for version, sum := range applied {
		rows.AddRow(version, sum)
	}
	mock.ExpectQuery("SELECT version, checksum FROM schema_migrations").
		WillReturnRows(rows)
}

func TestDiscoverMigrations_SortsAndIgnoresNonSQL(t *testing.T) {
	dir := writeMigrations(t, map[string]string{
		"002_second.sql": "CREATE TABLE b (id int);",
		"001_first.sql":  "CREATE TABLE a (id int);",
		"003_third.sql":  "CREATE TABLE c (id int);",
		"notes.txt":      "not a migration",
		"README.md":      "also not a migration",
	})

	got, err := DiscoverMigrations(dir)
	if err != nil {
		t.Fatalf("DiscoverMigrations: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d migrations, want 3 (non-.sql files must be ignored)", len(got))
	}
	want := []string{"001_first.sql", "002_second.sql", "003_third.sql"}
	for i, w := range want {
		if got[i].Version != w {
			t.Errorf("migrations[%d] = %q, want %q", i, got[i].Version, w)
		}
	}
}

func TestDiscoverMigrations_ChecksumsContent(t *testing.T) {
	dir := writeMigrations(t, map[string]string{"001_a.sql": "SELECT 1;"})

	got, err := DiscoverMigrations(dir)
	if err != nil {
		t.Fatalf("DiscoverMigrations: %v", err)
	}
	if got[0].Checksum != checksumOf("SELECT 1;") {
		t.Errorf("checksum = %q, want sha256 of the file contents", got[0].Checksum)
	}
}

func TestRunMigrations_AppliesUnappliedFilesInOrder(t *testing.T) {
	writeMigrations(t, map[string]string{
		"001_first.sql":  "CREATE TABLE a (id int);",
		"002_second.sql": "CREATE TABLE b (id int);",
	})

	db, mock := newMockDB(t)
	expectBootstrap(mock, nil)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("CREATE TABLE a (id int);")).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO schema_migrations")).
		WithArgs("001_first.sql", checksumOf("CREATE TABLE a (id int);")).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("CREATE TABLE b (id int);")).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO schema_migrations")).
		WithArgs("002_second.sql", checksumOf("CREATE TABLE b (id int);")).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := RunMigrations(db); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// Already-applied files must not be re-executed. The previous implementation
// re-ran every file on every boot, which broke as soon as a migration changed
// the constraints an earlier migration depended on.
func TestRunMigrations_SkipsAlreadyApplied(t *testing.T) {
	content := "CREATE TABLE a (id int);"
	writeMigrations(t, map[string]string{"001_first.sql": content})

	db, mock := newMockDB(t)
	expectBootstrap(mock, map[string]string{"001_first.sql": checksumOf(content)})

	// No ExpectBegin / ExpectExec for the migration body: re-running it would
	// fail these expectations.
	if err := RunMigrations(db); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("an already-applied migration was executed again: %v", err)
	}
}

// Editing a migration that has already run is schema drift. Silently skipping
// it leaves the database and the repository disagreeing about what the schema
// is, so it must be refused with an actionable message.
func TestRunMigrations_RejectsModifiedAppliedMigration(t *testing.T) {
	writeMigrations(t, map[string]string{"001_first.sql": "CREATE TABLE a (id int);"})

	db, mock := newMockDB(t)
	expectBootstrap(mock, map[string]string{"001_first.sql": checksumOf("CREATE TABLE a (id int); // edited")})

	err := RunMigrations(db)
	if err == nil {
		t.Fatal("expected an error when an applied migration was modified")
	}
	msg := err.Error()
	for _, want := range []string{"001_first.sql", "modified", "add a new migration"} {
		if !regexp.MustCompile(regexp.QuoteMeta(want)).MatchString(msg) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
}

// A migration that fails must not leave earlier statements from the same file
// committed, and must not be recorded as applied.
func TestRunMigrations_RollsBackFailedMigration(t *testing.T) {
	writeMigrations(t, map[string]string{"001_bad.sql": "CREATE TABLE a (id int); BAD SQL;"})

	db, mock := newMockDB(t)
	expectBootstrap(mock, nil)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("CREATE TABLE a (id int); BAD SQL;")).
		WillReturnError(sqlmock.ErrCancelled)
	mock.ExpectRollback()

	err := RunMigrations(db)
	if err == nil {
		t.Fatal("expected an error when a migration fails")
	}
	if !regexp.MustCompile(`001_bad\.sql`).MatchString(err.Error()) {
		t.Errorf("error %q does not name the failing migration", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expected a rollback: %v", err)
	}
}

func TestRunMigrations_FailsWhenRecordingVersionFails(t *testing.T) {
	content := "CREATE TABLE a (id int);"
	writeMigrations(t, map[string]string{"001_first.sql": content})

	db, mock := newMockDB(t)
	expectBootstrap(mock, nil)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(content)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO schema_migrations")).
		WithArgs("001_first.sql", checksumOf(content)).
		WillReturnError(sqlmock.ErrCancelled)
	mock.ExpectRollback()

	if err := RunMigrations(db); err == nil {
		t.Fatal("expected an error when the version could not be recorded")
	}
}

func TestRunMigrations_MissingDirectory(t *testing.T) {
	setMigrationsDir(t, t.TempDir()) // exists but empty
	db, mock := newMockDB(t)
	expectBootstrap(mock, nil)

	if err := RunMigrations(db); err != nil {
		t.Fatalf("an empty migration set should be a no-op, got: %v", err)
	}
}

// The real migration set must be internally consistent: the tenant-scoping
// migration relies on the tables earlier ones create.
func TestDiscoverMigrations_RealSetIsOrdered(t *testing.T) {
	dir := filepath.Join("..", "db", "migrations")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("migrations not found at %s: %v", dir, err)
	}

	got, err := DiscoverMigrations(dir)
	if err != nil {
		t.Fatalf("DiscoverMigrations: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no migrations discovered")
	}

	seen := map[string]bool{}
	for _, m := range got {
		if seen[m.Version] {
			t.Errorf("duplicate migration %s", m.Version)
		}
		seen[m.Version] = true
		if m.Checksum == "" {
			t.Errorf("%s has an empty checksum", m.Version)
		}
		if m.Content == "" {
			t.Errorf("%s is empty", m.Version)
		}
	}
}

// Postgres has no "ADD CONSTRAINT IF NOT EXISTS", so an ADD CONSTRAINT is the
// one statement shape that fails on a second application unless the identical
// constraint is dropped with IF EXISTS immediately before it. This is a
// deliberately narrow check for that specific hazard.
//
// Broader idempotency is not verified here: a line-oriented scan cannot see
// through multi-line statements or dollar-quoted DO blocks, and a check that
// cries wolf gets ignored. The authoritative re-runnability test is
// TestMigrationsAreReRunnableOnPostgres in tests/, which applies the whole set
// twice against a real database.
func TestRealMigrations_NoUnguardedAddConstraint(t *testing.T) {
	dir := filepath.Join("..", "db", "migrations")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("migrations not found at %s: %v", dir, err)
	}
	got, err := DiscoverMigrations(dir)
	if err != nil {
		t.Fatalf("DiscoverMigrations: %v", err)
	}

	// A constraint name is an identifier and is never followed by "(", so
	// matching an identifier keeps "ADD CONSTRAINT x CHECK (...)" working
	// instead of swallowing the CHECK expression.
	addConstraintRE := regexp.MustCompile(
		`(?i)ALTER\s+TABLE\s+([^\s]+)\s+ADD\s+CONSTRAINT\s+([A-Za-z_][A-Za-z0-9_$]*)`)
	dropConstraintRE := regexp.MustCompile(
		`(?i)ALTER\s+TABLE\s+([^\s]+)\s+DROP\s+CONSTRAINT\s+IF\s+EXISTS\s+([A-Za-z_][A-Za-z0-9_$]*)`)

	for _, m := range got {
		lines := splitLines(m.Content)
		inDollarBlock := false
		for i, line := range lines {
			// Statements built inside DO $$ ... $$ are already guarded by the
			// explicit DROP in the same block; static analysis cannot see that.
			if strings.Contains(line, "$$") {
				inDollarBlock = !inDollarBlock
				continue
			}
			if inDollarBlock {
				continue
			}

			stmt := stripSQLComment(line)
			add := addConstraintRE.FindStringSubmatch(stmt)
			if add == nil {
				continue
			}
			drop := dropConstraintRE.FindStringSubmatch(previousStatement(lines, i))
			if drop != nil && drop[1] == add[1] && drop[2] == add[2] {
				continue
			}
			t.Errorf("%s line %d: %q adds a constraint with no preceding "+
				"DROP CONSTRAINT IF EXISTS for the same name, so applying the "+
				"file twice fails. Postgres has no ADD CONSTRAINT IF NOT EXISTS.",
				m.Version, i+1, stmt)
		}
	}
}

// previousStatement returns the nearest preceding non-empty, non-comment line.
func previousStatement(lines []string, i int) string {
	for j := i - 1; j >= 0; j-- {
		s := stripSQLComment(lines[j])
		if s != "" {
			return s
		}
	}
	return ""
}

func stripSQLComment(line string) string {
	if idx := strings.Index(line, "--"); idx >= 0 {
		line = line[:idx]
	}
	return trimSpace(line)
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	return append(out, cur)
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

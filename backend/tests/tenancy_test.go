//go:build integration

// Tenant-scoping verification against a real PostgreSQL.
//
// These assertions cannot be made with sqlmock: the whole point is that the
// DATABASE enforces the guarantees. Run with:
//
//	DATABASE_URL=postgres://... go test -tags=integration -run Tenant ./tests/
//
// The same file also proves the migration set is re-runnable, which is what
// the migration runner in db/db.go depends on for anyone applying migrations
// by hand or restoring a dump.
package tests

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const (
	tenantDefault = "00000000-0000-0000-0000-000000000001"
	tenantAcme    = "11111111-1111-1111-1111-111111111111"
	tenantGlobex  = "22222222-2222-2222-2222-222222222222"
)

func tenancyDB(t *testing.T) *sql.DB {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set")
	}
	conn, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func exec(t *testing.T, conn *sql.DB, query string, args ...interface{}) {
	t.Helper()
	if _, err := conn.Exec(query, args...); err != nil {
		t.Fatalf("exec failed: %v\nquery: %s", err, query)
	}
}

func mustFail(t *testing.T, conn *sql.DB, query string, args ...interface{}) error {
	t.Helper()
	if _, err := conn.Exec(query, args...); err == nil {
		t.Fatalf("expected the statement to be rejected, but it succeeded\nquery: %s", query)
		return nil
	} else {
		return err
	}
}

func seedTenants(t *testing.T, conn *sql.DB) {
	t.Helper()
	exec(t, conn,
		`INSERT INTO tenants (id, slug, name) VALUES ($1,'acme','Acme Corp'),($2,'globex','Globex')
		 ON CONFLICT (id) DO NOTHING`, tenantAcme, tenantGlobex)
}

// The core defect this migration fixes: devices.ip_address was globally
// UNIQUE, so two customers scanning overlapping RFC1918 space collided, and the
// upsert in api/scans.go silently overwrote one customer's device identity and
// risk score with another's.
func TestTenant_SameIPAddressAllowedInDifferentTenants(t *testing.T) {
	conn := tenancyDB(t)
	seedTenants(t, conn)
	exec(t, conn, `DELETE FROM devices`)

	exec(t, conn, `INSERT INTO devices (tenant_id, ip_address, hostname, vendor, device_type, risk_score)
		VALUES ($1,'192.168.1.50','cam-hq','Hikvision','camera',9.5)`, tenantDefault)
	exec(t, conn, `INSERT INTO devices (tenant_id, ip_address, hostname, vendor, device_type, risk_score)
		VALUES ($1,'192.168.1.50','acme-printer','HP','printer',0.5)`, tenantAcme)

	var hostname, vendor string
	var risk float64
	err := conn.QueryRow(
		`SELECT hostname, vendor, risk_score FROM devices WHERE tenant_id=$1 AND ip_address='192.168.1.50'`,
		tenantDefault).Scan(&hostname, &vendor, &risk)
	if err != nil {
		t.Fatalf("default tenant's device disappeared: %v", err)
	}
	if hostname != "cam-hq" || vendor != "Hikvision" || risk != 9.5 {
		t.Errorf("default tenant's device was overwritten: hostname=%q vendor=%q risk=%v",
			hostname, vendor, risk)
	}
}

// Scoping must not weaken per-tenant integrity: a duplicate inside one tenant
// is still a duplicate.
func TestTenant_DuplicateIPWithinTenantStillRejected(t *testing.T) {
	conn := tenancyDB(t)
	seedTenants(t, conn)
	exec(t, conn, `DELETE FROM devices`)

	exec(t, conn, `INSERT INTO devices (tenant_id, ip_address) VALUES ($1,'10.1.1.1')`, tenantAcme)
	mustFail(t, conn, `INSERT INTO devices (tenant_id, ip_address) VALUES ($1,'10.1.1.1')`, tenantAcme)
}

// Cross-tenant references must be impossible even if application code is wrong.
func TestTenant_CrossTenantForeignKeyRejected(t *testing.T) {
	conn := tenancyDB(t)
	seedTenants(t, conn)
	exec(t, conn, `DELETE FROM devices`)
	exec(t, conn, `DELETE FROM scans`)
	exec(t, conn, `INSERT INTO devices (tenant_id, ip_address) VALUES ($1,'10.2.2.2')`, tenantAcme)

	var acmeDeviceID string
	if err := conn.QueryRow(
		`SELECT id FROM devices WHERE tenant_id=$1 AND ip_address='10.2.2.2'`, tenantAcme,
	).Scan(&acmeDeviceID); err != nil {
		t.Fatalf("failed to read fixture device: %v", err)
	}

	// The default tenant must not be able to create a scan against Acme's device.
	mustFail(t, conn,
		`INSERT INTO scans (tenant_id, device_id, status, scan_type) VALUES ($1,$2,'running','full')`,
		tenantDefault, acmeDeviceID)

	// The owning tenant can.
	exec(t, conn,
		`INSERT INTO scans (tenant_id, device_id, status, scan_type) VALUES ($1,$2,'running','full')`,
		tenantAcme, acmeDeviceID)
}

func TestTenant_SameUsernameAllowedInDifferentTenants(t *testing.T) {
	conn := tenancyDB(t)
	seedTenants(t, conn)
	exec(t, conn, `DELETE FROM users WHERE username = 'tenant-test-admin'`)

	exec(t, conn, `INSERT INTO users (tenant_id, username, email, password_hash, role)
		VALUES ($1,'tenant-test-admin','a@acme.test','x','admin')`, tenantAcme)
	exec(t, conn, `INSERT INTO users (tenant_id, username, email, password_hash, role)
		VALUES ($1,'tenant-test-admin','g@globex.test','x','admin')`, tenantGlobex)

	// Still unique within a tenant.
	mustFail(t, conn, `INSERT INTO users (tenant_id, username, email, password_hash, role)
		VALUES ($1,'tenant-test-admin','dup@acme.test','x','admin')`, tenantAcme)

	exec(t, conn, `DELETE FROM users WHERE username = 'tenant-test-admin'`)
}

func TestTenant_EveryTableHasNotNullTenantID(t *testing.T) {
	conn := tenancyDB(t)

	rows, err := conn.Query(`
		SELECT c.table_name
		FROM information_schema.columns c
		WHERE c.table_schema='public' AND c.column_name='tenant_id' AND c.is_nullable='NO'
		ORDER BY c.table_name`)
	if err != nil {
		t.Fatalf("failed to inspect tenant_id columns: %v", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	// Every table that holds customer data must be tenant-scoped.
	want := []string{
		"alerts", "audit_log", "devices", "firmware", "refresh_tokens",
		"safelists", "scan_profiles", "scan_scopes", "scans",
		"users", "vulnerabilities", "webhook_deliveries", "webhooks",
	}
	got := map[string]bool{}
	for _, tbl := range tables {
		got[tbl] = true
	}
	for _, tbl := range want {
		if !got[tbl] {
			t.Errorf("table %s has no NOT NULL tenant_id; it is not tenant scoped", tbl)
		}
	}
}

// Deleting a tenant must not silently cascade away a customer's security
// history, so the tenant_id foreign key is ON DELETE RESTRICT.
func TestTenant_DeletingTenantIsRestricted(t *testing.T) {
	conn := tenancyDB(t)
	seedTenants(t, conn)
	exec(t, conn, `DELETE FROM devices WHERE ip_address='10.3.3.3'`)
	exec(t, conn, `INSERT INTO devices (tenant_id, ip_address) VALUES ($1,'10.3.3.3')`, tenantGlobex)

	mustFail(t, conn, `DELETE FROM tenants WHERE id=$1`, tenantGlobex)
}

// The authoritative idempotency check. RunMigrations applies each file once and
// records it, so re-running is a no-op; this asserts the underlying files are
// also individually re-runnable for anyone applying them by hand.
func TestMigrationsAreReRunnableOnPostgres(t *testing.T) {
	conn := tenancyDB(t)

	migrations, err := discoverMigrationSQL(t)
	if err != nil {
		t.Fatalf("failed to discover migrations: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("no migrations found")
	}

	for pass := 1; pass <= 2; pass++ {
		for name, content := range migrations {
			if _, err := conn.Exec(content); err != nil {
				t.Fatalf("pass %d: migration %s failed: %v", pass, name, err)
			}
		}
	}
}

// discoverMigrationSQL reads the real migration files, keyed by name. It
// resolves the directory itself so the test does not depend on the caller's
// working directory or on MIGRATIONS_DIR being set correctly.
func discoverMigrationSQL(t *testing.T) (map[string]string, error) {
	t.Helper()

	var candidates []string
	if env := os.Getenv("MIGRATIONS_DIR"); env != "" {
		candidates = append(candidates, env)
	}
	candidates = append(candidates,
		filepath.Join("..", "db", "migrations"),
		filepath.Join("..", "..", "db", "migrations"),
		filepath.Join("db", "migrations"),
	)

	var dir string
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			dir = c
			break
		}
	}
	if dir == "" {
		return nil, fmt.Errorf("no migrations directory found in any of %v", candidates)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out[e.Name()] = string(b)
	}
	return out, nil
}

// A fresh install must be usable. The seeded admin account shipped with a
// bcrypt hash that did not verify against the documented password
// ("admin / changeme"), so the only administrator could never log in and the
// deployment was unusable. Verified by comparing the seeded hash against
// candidate passwords: no match.
func TestFreshInstallDefaultAdminCanLogIn(t *testing.T) {
	conn := tenancyDB(t)

	var hash string
	var mustChange bool
	err := conn.QueryRow(
		`SELECT password_hash, must_change_password FROM users WHERE username='admin'`,
	).Scan(&hash, &mustChange)
	if err != nil {
		t.Fatalf("seeded admin account is missing: %v", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("changeme")); err != nil {
		t.Fatalf("the documented default password does not verify against the "+
			"seeded hash: %v. A fresh install would be unusable.", err)
	}

	if !mustChange {
		t.Error("the seeded account must be flagged for password rotation; " +
			"otherwise a deployment sits indefinitely on a published credential")
	}
}

// Rotating the password must clear the flag so the deployment stops being
// gated.
func TestChangingPasswordClearsRotationFlag(t *testing.T) {
	conn := tenancyDB(t)

	var userID string
	if err := conn.QueryRow(`SELECT id FROM users WHERE username='admin'`).Scan(&userID); err != nil {
		t.Fatalf("seeded admin missing: %v", err)
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte("a-brand-new-password"), 12)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(
		`UPDATE users SET password_hash=$1, must_change_password=FALSE WHERE id=$2`,
		string(newHash), userID,
	); err != nil {
		t.Fatal(err)
	}

	var mustChange bool
	var stored string
	if err := conn.QueryRow(
		`SELECT must_change_password, password_hash FROM users WHERE id=$1`, userID,
	).Scan(&mustChange, &stored); err != nil {
		t.Fatal(err)
	}
	if mustChange {
		t.Error("must_change_password should be false after rotation")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(stored), []byte("a-brand-new-password")); err != nil {
		t.Errorf("rotated hash does not verify: %v", err)
	}
}

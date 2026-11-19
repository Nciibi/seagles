//go:build integration

package tests

import (
	"testing"
)

// Migration 017 enables forced RLS with a policy derived from app.tenant_id.
// These assertions can only be made against a real PostgreSQL.
func TestRLS_TenantIsolation(t *testing.T) {
	conn := tenancyDB(t)
	seedTenants(t, conn)

	var forced bool
	if err := conn.QueryRow(
		`SELECT relforcerowsecurity FROM pg_class WHERE relname = 'devices'`,
	).Scan(&forced); err != nil {
		t.Fatalf("read RLS status: %v", err)
	}
	if !forced {
		t.Fatal("devices does not have FORCE ROW LEVEL SECURITY enabled")
	}

	// With no tenant context the policy is permissive (background jobs use
	// this path), so clean up and seed both tenants' rows.
	_, _ = conn.Exec(`SELECT set_config('app.tenant_id', '', false)`)
	exec(t, conn, `DELETE FROM devices`)
	exec(t, conn, `INSERT INTO devices (tenant_id, ip_address, hostname)
		VALUES ($1, '10.99.0.1', 'acme-device')`, tenantAcme)
	exec(t, conn, `INSERT INTO devices (tenant_id, ip_address, hostname)
		VALUES ($1, '10.99.0.1', 'globex-device')`, tenantGlobex)

	// Scoped to Acme: only Acme's row is visible even though both share an IP.
	exec(t, conn, `SELECT set_config('app.tenant_id', $1, false)`, tenantAcme)
	var count int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&count); err != nil {
		t.Fatalf("count acme devices: %v", err)
	}
	if count != 1 {
		t.Fatalf("visible device count = %d, want 1", count)
	}
	var hostname string
	if err := conn.QueryRow(`SELECT hostname FROM devices`).Scan(&hostname); err != nil {
		t.Fatalf("read hostname: %v", err)
	}
	if hostname != "acme-device" {
		t.Fatalf("visible hostname = %q, want acme-device", hostname)
	}

	// A write that claims another tenant must be rejected by WITH CHECK.
	if err := conn.QueryRow(
		`INSERT INTO devices (tenant_id, ip_address, hostname)
		 VALUES ($1, '10.99.0.9', 'cross-tenant') RETURNING id`, tenantGlobex,
	).Scan(new(string)); err == nil {
		t.Fatal("cross-tenant INSERT was accepted while scoped to Acme")
	}

	// Reset so later tests are not affected by this connection's GUC.
	exec(t, conn, `SELECT set_config('app.tenant_id', '', false)`)
}

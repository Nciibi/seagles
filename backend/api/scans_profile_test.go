package api

import (
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/Nciibi/seagles/auth"

	"github.com/Nciibi/seagles/scanner"
)

func mockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, mock
}

func TestLoadScanProfileByID(t *testing.T) {
	db, mock := mockDB(t)
	mock.ExpectQuery(`SELECT skip_credential_test`).WithArgs("profile-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"skip_credential_test", "skip_protocol_probe", "max_port_count", "timeout_seconds",
		}).AddRow(true, true, 5, 30))

	profile := loadScanProfile(db, "profile-1")
	if !profile.SkipCredentialTest || !profile.SkipProtocolProbe {
		t.Fatal("profile skip flags not loaded")
	}
	if profile.MaxPorts != 5 || profile.Timeout != 30*time.Second {
		t.Fatalf("profile limits = %d/%v, want 5/30s", profile.MaxPorts, profile.Timeout)
	}
}

func TestLoadScanProfileDefaultsAndFallback(t *testing.T) {
	db, mock := mockDB(t)
	mock.ExpectQuery(`is_default`).WillReturnRows(sqlmock.NewRows([]string{
		"skip_credential_test", "skip_protocol_probe", "max_port_count", "timeout_seconds",
	}).AddRow(false, false, 13, 90))

	profile := loadScanProfile(db, "")
	if profile.SkipCredentialTest || profile.SkipProtocolProbe {
		t.Fatal("default profile should run all probe stages")
	}
	if profile.MaxPorts != len(scanner.DefaultScanPorts) || profile.Timeout != 90*time.Second {
		t.Fatalf("unexpected defaults: %+v", profile)
	}
}

func TestLoadScanProfileFallsBackOnMissingRow(t *testing.T) {
	db, mock := mockDB(t)
	mock.ExpectQuery(`SELECT skip_credential_test`).WithArgs("deleted").
		WillReturnRows(sqlmock.NewRows([]string{
			"skip_credential_test", "skip_protocol_probe", "max_port_count", "timeout_seconds",
		}))

	profile := loadScanProfile(db, "deleted")
	if profile.MaxPorts != len(scanner.DefaultScanPorts) || profile.Timeout != 90*time.Second {
		t.Fatalf("fallback = %+v, want full-scan defaults", profile)
	}
}

func TestActiveScanScopes(t *testing.T) {
	db, mock := mockDB(t)
	mock.ExpectQuery(`SELECT cidr FROM scan_scopes`).WillReturnRows(
		sqlmock.NewRows([]string{"cidr"}).AddRow("192.168.1.0/24").AddRow("10.0.0.0/8"),
	)

	scopes := activeScanScopes(db, auth.DefaultTenantID)
	if len(scopes) != 2 || scopes[0] != "192.168.1.0/24" || scopes[1] != "10.0.0.0/8" {
		t.Fatalf("scopes = %v", scopes)
	}
}

func TestActiveScanScopesEmptyFallsBackToEnv(t *testing.T) {
	db, mock := mockDB(t)
	mock.ExpectQuery(`SELECT cidr FROM scan_scopes`).WillReturnRows(sqlmock.NewRows([]string{"cidr"}))
	if scopes := activeScanScopes(db, auth.DefaultTenantID); len(scopes) != 0 {
		t.Fatalf("expected no scopes, got %v", scopes)
	}
}

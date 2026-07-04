package risk

import (
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestBuildRiskFactors_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	vulnRows := sqlmock.NewRows([]string{"title"})
	mock.ExpectQuery(`SELECT title FROM vulnerabilities`).
		WithArgs("device-1").
		WillReturnRows(vulnRows)

	mock.ExpectQuery(`SELECT COUNT.*FROM vulnerabilities`).
		WithArgs("device-1").
		WillReturnRows(sqlmock.NewRows([]string{""}).AddRow(0))
	mock.ExpectQuery(`SELECT COUNT.*FROM vulnerabilities`).
		WithArgs("device-1").
		WillReturnRows(sqlmock.NewRows([]string{""}).AddRow(0))
	mock.ExpectQuery(`SELECT entropy_score FROM firmware`).
		WithArgs("device-1").
		WillReturnRows(sqlmock.NewRows([]string{"entropy_score"}).AddRow(nil))
	mock.ExpectQuery(`SELECT started_at FROM scans`).
		WithArgs("device-1").
		WillReturnRows(sqlmock.NewRows([]string{"started_at"}).AddRow(nil))

	factors, err := BuildRiskFactors(db, "device-1")
	if err != nil {
		t.Fatalf("BuildRiskFactors failed: %v", err)
	}
	if factors.HasDefaultCreds || factors.HasTelnet || factors.HasADB {
		t.Fatal("expected no risk factors for empty device")
	}
}

func TestBuildRiskFactors_WithVulnerabilities(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	vulnRows := sqlmock.NewRows([]string{"title"}).
		AddRow("Default credentials active").
		AddRow("Telnet service exposed").
		AddRow("ADB exposed on port 5555")

	mock.ExpectQuery(`SELECT title FROM vulnerabilities`).
		WithArgs("device-2").
		WillReturnRows(vulnRows)

	mock.ExpectQuery(`SELECT COUNT.*FROM vulnerabilities`).
		WithArgs("device-2").
		WillReturnRows(sqlmock.NewRows([]string{""}).AddRow(5))
	mock.ExpectQuery(`SELECT COUNT.*FROM vulnerabilities`).
		WithArgs("device-2").
		WillReturnRows(sqlmock.NewRows([]string{""}).AddRow(2))
	mock.ExpectQuery(`SELECT entropy_score FROM firmware`).
		WithArgs("device-2").
		WillReturnRows(sqlmock.NewRows([]string{"entropy_score"}).AddRow(7.8))
	mock.ExpectQuery(`SELECT started_at FROM scans`).
		WithArgs("device-2").
		WillReturnRows(sqlmock.NewRows([]string{"started_at"}).AddRow(time.Now().Add(-72*time.Hour)))

	factors, err := BuildRiskFactors(db, "device-2")
	if err != nil {
		t.Fatalf("BuildRiskFactors failed: %v", err)
	}
	if !factors.HasDefaultCreds {
		t.Fatal("expected HasDefaultCreds")
	}
	if !factors.HasTelnet {
		t.Fatal("expected HasTelnet")
	}
	if !factors.HasADB {
		t.Fatal("expected HasADB")
	}
	if factors.KnownCVECount != 5 {
		t.Fatalf("expected 5 CVEs, got %d", factors.KnownCVECount)
	}
	if factors.KEVMatchCount != 2 {
		t.Fatalf("expected 2 KEV matches, got %d", factors.KEVMatchCount)
	}
	if !factors.HighEntropyFirmware {
		t.Fatal("expected HighEntropyFirmware for entropy 7.8")
	}
	if factors.DaysSinceLastScan != 3 {
		t.Fatalf("expected 3 days since last scan, got %d", factors.DaysSinceLastScan)
	}
}

func TestBuildRiskFactors_CaseInsensitive(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	vulnRows := sqlmock.NewRows([]string{"title"}).
		AddRow("TELNET SERVICE EXPOSED").
		AddRow("Default Credentials Active")

	mock.ExpectQuery(`SELECT title FROM vulnerabilities`).
		WithArgs("device-3").
		WillReturnRows(vulnRows)

	mock.ExpectQuery(`SELECT COUNT.*FROM vulnerabilities`).
		WithArgs("device-3").
		WillReturnRows(sqlmock.NewRows([]string{""}).AddRow(0))
	mock.ExpectQuery(`SELECT COUNT.*FROM vulnerabilities`).
		WithArgs("device-3").
		WillReturnRows(sqlmock.NewRows([]string{""}).AddRow(0))
	mock.ExpectQuery(`SELECT entropy_score FROM firmware`).
		WithArgs("device-3").
		WillReturnRows(sqlmock.NewRows([]string{"entropy_score"}).AddRow(nil))
	mock.ExpectQuery(`SELECT started_at FROM scans`).
		WithArgs("device-3").
		WillReturnRows(sqlmock.NewRows([]string{"started_at"}).AddRow(nil))

	factors, err := BuildRiskFactors(db, "device-3")
	if err != nil {
		t.Fatalf("BuildRiskFactors failed: %v", err)
	}
	if !factors.HasTelnet {
		t.Fatal("expected HasTelnet (case insensitive)")
	}
	if !factors.HasDefaultCreds {
		t.Fatal("expected HasDefaultCreds (case insensitive)")
	}
}

func TestBuildRiskFactors_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`SELECT title FROM vulnerabilities`).
		WithArgs("device-error").
		WillReturnError(sql.ErrConnDone)

	_, err = BuildRiskFactors(db, "device-error")
	if err == nil {
		t.Fatal("expected error for DB failure")
	}
}

func TestUpdateDeviceRiskScore(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	vulnRows := sqlmock.NewRows([]string{"title"}).
		AddRow("Default credentials active").
		AddRow("Telnet service exposed")

	mock.ExpectQuery(`SELECT title FROM vulnerabilities`).
		WithArgs("device-update").
		WillReturnRows(vulnRows)

	mock.ExpectQuery(`SELECT COUNT.*FROM vulnerabilities`).
		WithArgs("device-update").
		WillReturnRows(sqlmock.NewRows([]string{""}).AddRow(0))
	mock.ExpectQuery(`SELECT COUNT.*FROM vulnerabilities`).
		WithArgs("device-update").
		WillReturnRows(sqlmock.NewRows([]string{""}).AddRow(0))
	mock.ExpectQuery(`SELECT entropy_score FROM firmware`).
		WithArgs("device-update").
		WillReturnRows(sqlmock.NewRows([]string{"entropy_score"}).AddRow(nil))
	mock.ExpectQuery(`SELECT started_at FROM scans`).
		WithArgs("device-update").
		WillReturnRows(sqlmock.NewRows([]string{"started_at"}).AddRow(nil))

	mock.ExpectQuery(`SELECT risk_score FROM devices`).
		WithArgs("device-update").
		WillReturnRows(sqlmock.NewRows([]string{"risk_score"}).AddRow(3.0))

	mock.ExpectExec(`UPDATE devices SET risk_score`).
		WithArgs(7.0, "device-update").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = UpdateDeviceRiskScore(db, "device-update")
	if err != nil {
		t.Fatalf("UpdateDeviceRiskScore failed: %v", err)
	}
}

func TestScoreBreakdown(t *testing.T) {
	factors := RiskFactors{
		HasDefaultCreds:     true,
		HasTelnet:           true,
		HasADB:              true,
		KnownCVECount:       5,
		KEVMatchCount:       1,
		HighEntropyFirmware: true,
	}

	breakdown := ScoreBreakdown(factors)
	expectedKeys := []string{
		"default_credentials",
		"telnet_exposed",
		"adb_exposed",
		"known_cves",
		"kev_matches",
		"high_entropy_firmware",
	}
	for _, key := range expectedKeys {
		if _, ok := breakdown[key]; !ok {
			t.Errorf("expected key %s in breakdown", key)
		}
	}
}

func TestSeverityFromScore(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{9.0, "critical"},
		{8.0, "critical"},
		{7.0, "high"},
		{6.0, "high"},
		{4.0, "medium"},
		{3.0, "medium"},
		{2.0, "low"},
		{0.0, "low"},
	}
	for _, tt := range tests {
		got := SeverityFromScore(tt.score)
		if got != tt.want {
			t.Errorf("SeverityFromScore(%.1f) = %s, want %s", tt.score, got, tt.want)
		}
	}
}

func TestGetRiskBreakdown_Error(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`SELECT title FROM vulnerabilities`).
		WithArgs("fail-id").
		WillReturnError(sql.ErrConnDone)

	result := GetRiskBreakdown(db, "fail-id")
	if result["error"] == nil {
		t.Fatal("expected error in result")
	}
}

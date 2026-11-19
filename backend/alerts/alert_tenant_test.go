package alerts

import (
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

func TestCreateAlertWritesExplicitTenant(t *testing.T) {
	db, mock := newMockDB(t)
	const tenant = "22222222-2222-2222-2222-222222222222"

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM alerts")).
		WithArgs("dev-1", AlertNewDevice).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO alerts")).
		WithArgs(tenant, "dev-1", "high", AlertNewDevice, "title", "", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("alert-1"))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, COALESCE(tenant_id")).
		WithArgs(DefaultTenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "tenant_id", "name", "url", "webhook_type", "min_severity", "secret", "headers"}))

	if err := CreateAlert(db, AlertRequest{
		TenantID: tenant, DeviceID: "dev-1", AlertType: AlertNewDevice,
		Severity: "high", Title: "title",
	}); err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}
	time.Sleep(100 * time.Millisecond) // webhook dispatch runs in a goroutine
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

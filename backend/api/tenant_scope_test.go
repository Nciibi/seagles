package api

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
)

const otherTenant = "11111111-1111-1111-1111-111111111111"

func routerWithTenant(tenant string, register func(*gin.Engine, *sql.DB)) (*gin.Engine, sqlmock.Sqlmock, func()) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		panic(err)
	}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("tenant_id", tenant)
		c.Set("user_id", "test-user")
		c.Next()
	})
	register(r, db)
	return r, mock, func() { db.Close() }
}

// Handlers must write into the tenant from the authenticated context, not
// the schema's transitional DEFAULT. sqlmock checks the exact first argument.
func TestCreateSafelistUsesContextTenant(t *testing.T) {
	r, mock, done := routerWithTenant(otherTenant, func(r *gin.Engine, db *sql.DB) {
		r.POST("/safelists", CreateSafelistHandler(db))
	})
	defer done()

	mock.ExpectQuery(`INSERT INTO safelists`).
		WithArgs(otherTenant, "ip", "10.20.30.40", nil, "test-user").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("sl-1"))

	body := bytes.NewBufferString(`{"entry_type":"ip","value":"10.20.30.40"}`)
	req := httptest.NewRequest(http.MethodPost, "/safelists", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestCreateWebhookUsesContextTenant(t *testing.T) {
	r, mock, done := routerWithTenant(otherTenant, func(r *gin.Engine, db *sql.DB) {
		r.POST("/webhooks", CreateWebhookHandler(db))
	})
	defer done()
	t.Setenv("WEBHOOK_ALLOW_PRIVATE_TARGETS", "true")

	mock.ExpectQuery(`INSERT INTO webhooks`).
		WithArgs(otherTenant, "hook", "https://example.com/hook", "generic", "high").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("wh-1"))

	body := bytes.NewBufferString(`{"name":"hook","url":"https://example.com/hook","webhook_type":"generic"}`)
	req := httptest.NewRequest(http.MethodPost, "/webhooks", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

package api

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
)

func TestTenantDBMiddlewareSetsTenantOnRequestTransaction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	const tenant = "11111111-1111-1111-1111-111111111111"
	mock.ExpectBegin()
	mock.ExpectExec(`set_config`).WithArgs(tenant).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT count\(\*\) FROM widgets`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(7))
	mock.ExpectCommit()

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("tenant_id", tenant)
		c.Next()
	})
	r.Use(TenantDBMiddleware(db))
	r.GET("/t", func(c *gin.Context) {
		handle := tenantDB(c, db)
		if _, ok := handle.(*sql.Tx); !ok {
			t.Errorf("tenantDB returned %T, want the request-scoped *sql.Tx", handle)
		}
		var count int
		if err := handle.QueryRow(`SELECT count(*) FROM widgets`).Scan(&count); err != nil {
			t.Errorf("query: %v", err)
		}
		if count != 7 {
			t.Errorf("count = %d, want 7", count)
		}
		c.Status(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/t", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestTenantDBFallsBackToPoolWithoutMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT 1")).
		WillReturnRows(sqlmock.NewRows([]string{"one"}).AddRow(1))

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	var one int
	if err := tenantDB(c, db).QueryRow("SELECT 1").Scan(&one); err != nil {
		t.Fatalf("query via pool: %v", err)
	}
	if one != 1 {
		t.Fatalf("one = %d", one)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

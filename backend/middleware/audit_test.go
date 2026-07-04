package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
)

func TestAuditLogger_WritesToDB(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	r := gin.New()
	r.Use(AuditLogger(db, "/skip"))
	r.POST("/api/v1/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	mock.ExpectExec(`INSERT INTO audit_log`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "POST", "/api/v1/test", "", "", "", 200, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	body, _ := json.Marshal(map[string]string{"key": "val"})
	req := httptest.NewRequest("POST", "/api/v1/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unfulfilled expectations: %v", err)
	}
}

func TestAuditLogger_SkipsReadMethods(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	r := gin.New()
	r.Use(AuditLogger(db))
	r.GET("/api/v1/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAuditLogger_SkipsConfiguredPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	r := gin.New()
	r.Use(AuditLogger(db, "/api/v1/health"))
	r.GET("/api/v1/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestIsWriteMethod(t *testing.T) {
	tests := []struct {
		method string
		want   bool
	}{
		{"GET", false},
		{"HEAD", false},
		{"OPTIONS", false},
		{"POST", true},
		{"PUT", true},
		{"PATCH", true},
		{"DELETE", true},
	}
	for _, tt := range tests {
		got := isWriteMethod(tt.method)
		if got != tt.want {
			t.Errorf("isWriteMethod(%q) = %v, want %v", tt.method, got, tt.want)
		}
	}
}

func TestListAuditLogsHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	r := gin.New()
	r.GET("/audit-log", ListAuditLogsHandler(db))

	rows := sqlmock.NewRows([]string{
		"id", "user_id", "username", "action", "resource", "resource_id", "detail",
		"ip_address", "user_agent", "status_code", "latency_ms", "created_at",
	}).AddRow(
		"test-id", nil, "testuser", "POST", "/api/v1/test", nil,
		nil, "10.0.0.1", "agent", 200, 5, "2026-01-01T00:00:00Z",
	)

	mock.ExpectQuery(`SELECT id, user_id, username, action, resource, resource_id, detail`).
		WillReturnRows(rows)

	req := httptest.NewRequest("GET", "/audit-log", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestListAuditLogsHandler_Empty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	r := gin.New()
	r.GET("/audit-log", ListAuditLogsHandler(db))

	rows := sqlmock.NewRows([]string{
		"id", "user_id", "username", "action", "resource", "resource_id", "detail",
		"ip_address", "user_agent", "status_code", "latency_ms", "created_at",
	})

	mock.ExpectQuery(`SELECT id, user_id, username, action, resource, resource_id, detail`).
		WillReturnRows(rows)

	req := httptest.NewRequest("GET", "/audit-log", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestListAuditLogsHandler_DBError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	r := gin.New()
	r.GET("/audit-log", ListAuditLogsHandler(db))

	mock.ExpectQuery(`SELECT id, user_id, username, action, resource, resource_id, detail`).
		WillReturnError(&testError{"connection refused"})

	req := httptest.NewRequest("GET", "/audit-log", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 500 {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/Nciibi/seagles/config"
	"github.com/Nciibi/seagles/models"
	"github.com/lib/pq"
)

func setupTestRouter(t *testing.T) (*gin.Engine, sqlmock.Sqlmock, *config.Config) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	cfg := &config.Config{
		RateLimitPerMin: 1000,
		AllowedOrigins:  []string{"http://localhost:5173"},
	}

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("request_id", uuid.NewString())
		c.Next()
	})
	v1 := r.Group("/api/v1")
	{
		v1.GET("/health", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		protected := v1.Group("")
		protected.Use(func(c *gin.Context) {
			c.Set("user_id", "test-user-id")
			c.Set("username", "testuser")
			c.Set("user_role", "admin")
			c.Next()
		})
		{
			protected.GET("/stats", StatsHandler(db))
			protected.GET("/devices", ListDevicesHandler(db))
		protected.GET("/devices/:id", GetDeviceHandler(db))
		protected.GET("/devices/:id/risk-breakdown", RiskBreakdownHandler(db))
		protected.DELETE("/devices/:id", DeleteDeviceHandler(db))
			protected.GET("/scans", ListScansHandler(db))
			protected.GET("/scans/:id", GetScanHandler(db))
			protected.GET("/vulnerabilities", ListVulnerabilitiesHandler(db))
			protected.PATCH("/vulnerabilities/:id/resolve", ResolveVulnerabilityHandler(db))
			protected.GET("/alerts", ListAlertsHandler(db))
			protected.POST("/alerts/:id/ack", AckAlertHandler(db))
			protected.GET("/firmware", ListFirmwareHandler(db))
			protected.GET("/safelists", ListSafelistHandler(db))
			protected.POST("/safelists", CreateSafelistHandler(db))
			protected.DELETE("/safelists/:id", DeleteSafelistHandler(db))
			protected.GET("/scan-profiles", ListScanProfilesHandler(db))
			protected.GET("/scan-scopes", ListScanScopesHandler(db))
			protected.POST("/scan-scopes", CreateScanScopeHandler(db))
			protected.DELETE("/scan-scopes/:id", DeleteScanScopeHandler(db))
			protected.GET("/webhooks", ListWebhooksHandler(db))
			protected.POST("/webhooks", CreateWebhookHandler(db))
			protected.DELETE("/webhooks/:id", DeleteWebhookHandler(db))
			protected.POST("/webhooks/:id/test", TestWebhookHandler(db))

		}
	}

	return r, mock, cfg
}

func request(router *gin.Engine, method, path string, body interface{}) *httptest.ResponseRecorder {
	var reqBody []byte
	if body != nil {
		reqBody, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestHealthEndpoint(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	w := request(router, "GET", "/api/v1/health", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestListDevicesHandler_Success(t *testing.T) {
	router, mock, _ := setupTestRouter(t)
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "ip_address", "mac_address", "hostname", "vendor", "device_type",
		"os_fingerprint", "firmware_version", "first_seen", "last_seen", "risk_score",
		"is_active", "tags", "raw_nmap",
	}).AddRow(
		uuid.NewString(), "192.168.1.100", nil, nil, nil, "router",
		nil, nil, now, now, 5.0, true,
		pq.StringArray{}, []byte("null"),
	)

	mock.ExpectQuery(`SELECT id, ip_address, mac_address, hostname, vendor, device_type`).
		WillReturnRows(rows)

	w := request(router, "GET", "/api/v1/devices", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Data []models.DeviceJSON `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("expected 1 device, got %d", len(resp.Data))
	}
	if resp.Data[0].IPAddress != "192.168.1.100" {
		t.Fatalf("expected IP 192.168.1.100, got %s", resp.Data[0].IPAddress)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unfulfilled expectations: %v", err)
	}
}

func TestListDevicesHandler_Empty(t *testing.T) {
	router, mock, _ := setupTestRouter(t)

	rows := sqlmock.NewRows([]string{
		"id", "ip_address", "mac_address", "hostname", "vendor", "device_type",
		"os_fingerprint", "firmware_version", "first_seen", "last_seen", "risk_score",
		"is_active", "tags", "raw_nmap",
	})

	mock.ExpectQuery(`SELECT id, ip_address, mac_address, hostname, vendor, device_type`).
		WillReturnRows(rows)

	w := request(router, "GET", "/api/v1/devices", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Data []models.DeviceJSON `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Data) != 0 {
		t.Fatalf("expected empty array, got %d items", len(resp.Data))
	}
}

func TestListDevicesHandler_DBError(t *testing.T) {
	router, mock, _ := setupTestRouter(t)

	mock.ExpectQuery(`SELECT id, ip_address, mac_address, hostname, vendor, device_type`).
		WillReturnError(assertAnError("connection refused"))

	w := request(router, "GET", "/api/v1/devices", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestGetDeviceHandler_Success(t *testing.T) {
	router, mock, _ := setupTestRouter(t)
	deviceID := uuid.NewString()
	now := time.Now()

	deviceRows := sqlmock.NewRows([]string{
		"id", "ip_address", "mac_address", "hostname", "vendor", "device_type",
		"os_fingerprint", "firmware_version", "first_seen", "last_seen", "risk_score",
		"is_active", "tags", "raw_nmap",
	}).AddRow(
		deviceID, "10.0.0.5", nil, nil, nil, "camera",
		nil, nil, now, now, 7.5, true,
		pq.StringArray{}, []byte("null"),
	)

	mock.ExpectQuery(`SELECT id, ip_address, mac_address, hostname, vendor, device_type`).
		WithArgs(deviceID).
		WillReturnRows(deviceRows)

	scanRows := sqlmock.NewRows([]string{
		"id", "device_id", "started_at", "completed_at", "status", "scan_type",
		"open_ports", "services", "scan_output",
	})
	mock.ExpectQuery(`SELECT id, device_id, started_at, completed_at, status, scan_type`).
		WithArgs(deviceID).
		WillReturnRows(scanRows)

	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs(deviceID).
		WillReturnRows(sqlmock.NewRows([]string{""}).AddRow(3))

	w := request(router, "GET", "/api/v1/devices/"+deviceID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetDeviceHandler_NotFound(t *testing.T) {
	router, mock, _ := setupTestRouter(t)
	deviceID := uuid.NewString()

	mock.ExpectQuery(`SELECT id, ip_address, mac_address, hostname, vendor, device_type`).
		WithArgs(deviceID).
		WillReturnError(sql.ErrNoRows)

	w := request(router, "GET", "/api/v1/devices/"+deviceID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetDeviceHandler_DBError(t *testing.T) {
	router, mock, _ := setupTestRouter(t)

	mock.ExpectQuery(`SELECT id, ip_address, mac_address, hostname, vendor, device_type`).
		WithArgs("fail-id").
		WillReturnError(assertAnError("connection timeout"))

	w := request(router, "GET", "/api/v1/devices/fail-id", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestDeleteDeviceHandler_Success(t *testing.T) {
	router, mock, _ := setupTestRouter(t)
	deviceID := uuid.NewString()

	mock.ExpectExec(`UPDATE devices SET is_active`).
		WithArgs(deviceID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := request(router, "DELETE", "/api/v1/devices/"+deviceID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteDeviceHandler_NotFound(t *testing.T) {
	router, mock, _ := setupTestRouter(t)

	mock.ExpectExec(`UPDATE devices SET is_active`).
		WithArgs("nonexistent").
		WillReturnResult(sqlmock.NewResult(0, 0))

	w := request(router, "DELETE", "/api/v1/devices/nonexistent", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestListScansHandler_Success(t *testing.T) {
	router, mock, _ := setupTestRouter(t)
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "device_id", "started_at", "completed_at", "status", "scan_type",
		"open_ports", "services", "scan_output",
	}).AddRow(
		uuid.NewString(), nil, now, nil, "running", "full",
		[]byte("[]"), []byte("{}"), nil,
	)

	mock.ExpectQuery(`SELECT id, device_id, started_at, completed_at, status`).
		WillReturnRows(rows)

	w := request(router, "GET", "/api/v1/scans", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Data []models.ScanJSON `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("expected 1 scan, got %d", len(resp.Data))
	}
}

func TestGetScanHandler_Success(t *testing.T) {
	router, mock, _ := setupTestRouter(t)
	scanID := uuid.NewString()
	deviceID := uuid.NewString()
	now := time.Now()

	scanRows := sqlmock.NewRows([]string{
		"id", "device_id", "started_at", "completed_at", "status", "scan_type",
		"open_ports", "services", "scan_output",
	}).AddRow(
		scanID, deviceID, now, now, "complete", "full",
		[]byte("[80,443]"), []byte("{}"), nil,
	)

	mock.ExpectQuery(`SELECT id, device_id, started_at, completed_at, status`).
		WithArgs(scanID).
		WillReturnRows(scanRows)

	deviceRows := sqlmock.NewRows([]string{
		"id", "ip_address", "mac_address", "hostname", "vendor", "device_type",
		"os_fingerprint", "firmware_version", "first_seen", "last_seen", "risk_score",
		"is_active", "tags", "raw_nmap",
	}).AddRow(
		deviceID, "10.0.0.1", nil, nil, nil, "switch",
		nil, nil, now, now, 3.0, true,
		pq.StringArray{}, nil,
	)

	mock.ExpectQuery(`SELECT id, ip_address, mac_address, hostname, vendor`).
		WithArgs(deviceID).
		WillReturnRows(deviceRows)

	w := request(router, "GET", "/api/v1/scans/"+scanID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetScanHandler_NotFound(t *testing.T) {
	router, mock, _ := setupTestRouter(t)

	mock.ExpectQuery(`SELECT id, device_id, started_at, completed_at, status`).
		WithArgs("nonexistent").
		WillReturnError(sql.ErrNoRows)

	w := request(router, "GET", "/api/v1/scans/nonexistent", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestListVulnerabilitiesHandler_Success(t *testing.T) {
	router, mock, _ := setupTestRouter(t)
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "device_id", "scan_id", "cve_id", "cvss_score", "severity", "title",
		"description", "affected_component", "remediation", "is_kev", "discovered_at",
		"resolved_at", "is_resolved",
	}).AddRow(
		uuid.NewString(), nil, nil, "CVE-2024-1234", 9.8,
		"critical", "RCE Vulnerability", nil, nil, nil,
		false, now, nil, false,
	)

	mock.ExpectQuery(`SELECT id, device_id, scan_id, cve_id, cvss_score, severity, title`).
		WillReturnRows(rows)

	w := request(router, "GET", "/api/v1/vulnerabilities", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Data []models.VulnerabilityJSON `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(resp.Data))
	}
}

func TestResolveVulnerabilityHandler_Success(t *testing.T) {
	router, mock, _ := setupTestRouter(t)
	vulnID := uuid.NewString()

	mock.ExpectExec(`UPDATE vulnerabilities SET is_resolved`).
		WithArgs(vulnID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectQuery(`SELECT device_id FROM vulnerabilities`).
		WithArgs(vulnID).
		WillReturnRows(sqlmock.NewRows([]string{"device_id"}).AddRow(nil))

	w := request(router, "PATCH", "/api/v1/vulnerabilities/"+vulnID+"/resolve", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestResolveVulnerabilityHandler_NotFound(t *testing.T) {
	router, mock, _ := setupTestRouter(t)

	mock.ExpectExec(`UPDATE vulnerabilities SET is_resolved`).
		WithArgs("nonexistent").
		WillReturnResult(sqlmock.NewResult(0, 0))

	w := request(router, "PATCH", "/api/v1/vulnerabilities/nonexistent/resolve", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestListAlertsHandler_Success(t *testing.T) {
	router, mock, _ := setupTestRouter(t)
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "device_id", "severity", "alert_type", "title", "description",
		"triggered_at", "acknowledged_at", "is_acknowledged", "metadata",
	}	).AddRow(
		uuid.NewString(), nil, "high", "telnet_open", "Telnet exposed",
		nil, now, nil, false, []byte("null"),
	)

	mock.ExpectQuery(`SELECT id, device_id, severity, alert_type, title, description`).
		WillReturnRows(rows)

	w := request(router, "GET", "/api/v1/alerts", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Data []models.AlertJSON `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(resp.Data))
	}
}

func TestAckAlertHandler_Success(t *testing.T) {
	router, mock, _ := setupTestRouter(t)
	alertID := uuid.NewString()

	mock.ExpectExec(`UPDATE alerts SET is_acknowledged`).
		WithArgs(alertID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := request(router, "POST", "/api/v1/alerts/"+alertID+"/ack", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAckAlertHandler_NotFound(t *testing.T) {
	router, mock, _ := setupTestRouter(t)

	mock.ExpectExec(`UPDATE alerts SET is_acknowledged`).
		WithArgs("nonexistent").
		WillReturnResult(sqlmock.NewResult(0, 0))

	w := request(router, "POST", "/api/v1/alerts/nonexistent/ack", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestSafelistHandlers(t *testing.T) {
	t.Run("ListSafelist_Success", func(t *testing.T) {
		router, mock, _ := setupTestRouter(t)

		rows := sqlmock.NewRows([]string{
			"id", "entry_type", "value", "reason", "created_by", "created_at", "is_active",
		}).AddRow(
			uuid.NewString(), "ip", "10.0.0.1", nil, nil, time.Now().Format(time.RFC3339), true,
		)

		mock.ExpectQuery(`SELECT id, entry_type, value, reason, created_by, created_at, is_active`).
			WillReturnRows(rows)

		w := request(router, "GET", "/api/v1/safelists", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("CreateSafelist_Success", func(t *testing.T) {
		router, mock, _ := setupTestRouter(t)

		mock.ExpectQuery(`INSERT INTO safelists`).
			WithArgs("ip", "10.0.0.99", nil, "test-user-id").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.NewString()))

		w := request(router, "POST", "/api/v1/safelists", CreateSafelistRequest{
			EntryType: "ip",
			Value:     "10.0.0.99",
		})
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("DeleteSafelist_Success", func(t *testing.T) {
		router, mock, _ := setupTestRouter(t)
		id := uuid.NewString()

		mock.ExpectExec(`UPDATE safelists SET is_active`).
			WithArgs(id).
			WillReturnResult(sqlmock.NewResult(0, 1))

		w := request(router, "DELETE", "/api/v1/safelists/"+id, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("DeleteSafelist_NotFound", func(t *testing.T) {
		router, mock, _ := setupTestRouter(t)

		mock.ExpectExec(`UPDATE safelists SET is_active`).
			WithArgs("nonexistent").
			WillReturnResult(sqlmock.NewResult(0, 0))

		w := request(router, "DELETE", "/api/v1/safelists/nonexistent", nil)
		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", w.Code)
		}
	})
}

func TestScanScopeHandlers(t *testing.T) {
	t.Run("ListScanScopes_Success", func(t *testing.T) {
		router, mock, _ := setupTestRouter(t)

		rows := sqlmock.NewRows([]string{
			"id", "cidr", "label", "is_active",
		}).AddRow(
			uuid.NewString(), "10.0.0.0/24", nil, true,
		)

		mock.ExpectQuery(`SELECT id, cidr, label, is_active FROM scan_scopes`).
			WillReturnRows(rows)

		w := request(router, "GET", "/api/v1/scan-scopes", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("CreateScanScope_Success", func(t *testing.T) {
		router, mock, _ := setupTestRouter(t)

		mock.ExpectQuery(`INSERT INTO scan_scopes`).
			WithArgs("192.168.1.0/24", nil).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.NewString()))

		w := request(router, "POST", "/api/v1/scan-scopes", CreateScanScopeRequest{
			CIDR: "192.168.1.0/24",
		})
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("DeleteScanScope_Success", func(t *testing.T) {
		router, mock, _ := setupTestRouter(t)
		id := uuid.NewString()

		mock.ExpectExec(`UPDATE scan_scopes SET is_active`).
			WithArgs(id).
			WillReturnResult(sqlmock.NewResult(0, 1))

		w := request(router, "DELETE", "/api/v1/scan-scopes/"+id, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}

func TestWebhookHandlers(t *testing.T) {
	t.Run("ListWebhooks_Success", func(t *testing.T) {
		router, mock, _ := setupTestRouter(t)

		rows := sqlmock.NewRows([]string{
			"id", "name", "url", "webhook_type", "min_severity", "is_active", "last_triggered",
		}).AddRow(
			uuid.NewString(), "test-hook", "https://hooks.example.com", "slack", "high", true, nil,
		)

		mock.ExpectQuery(`SELECT id, name, url, webhook_type, min_severity, is_active, last_triggered`).
			WillReturnRows(rows)

		w := request(router, "GET", "/api/v1/webhooks", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("CreateWebhook_Success", func(t *testing.T) {
		router, mock, _ := setupTestRouter(t)

		mock.ExpectQuery(`INSERT INTO webhooks`).
			WithArgs("slack-alerts", "https://hooks.slack.com/test", "slack", "high").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.NewString()))

		w := request(router, "POST", "/api/v1/webhooks", CreateWebhookRequest{
			Name:        "slack-alerts",
			URL:         "https://hooks.slack.com/test",
			WebhookType: "slack",
		})
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("DeleteWebhook_Success", func(t *testing.T) {
		router, mock, _ := setupTestRouter(t)
		id := uuid.NewString()

		mock.ExpectExec(`DELETE FROM webhooks`).
			WithArgs(id).
			WillReturnResult(sqlmock.NewResult(0, 1))

		w := request(router, "DELETE", "/api/v1/webhooks/"+id, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("DeleteWebhook_NotFound", func(t *testing.T) {
		router, mock, _ := setupTestRouter(t)

		mock.ExpectExec(`DELETE FROM webhooks`).
			WithArgs("nonexistent").
			WillReturnResult(sqlmock.NewResult(0, 0))

		w := request(router, "DELETE", "/api/v1/webhooks/nonexistent", nil)
		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", w.Code)
		}
	})

	t.Run("TestWebhook_Success", func(t *testing.T) {
		router, mock, _ := setupTestRouter(t)
		id := uuid.NewString()

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		mock.ExpectQuery(`SELECT url FROM webhooks`).
			WithArgs(id).
			WillReturnRows(sqlmock.NewRows([]string{"url"}).
				AddRow(ts.URL))

		w := request(router, "POST", "/api/v1/webhooks/"+id+"/test", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("TestWebhook_NotFound", func(t *testing.T) {
		router, mock, _ := setupTestRouter(t)

	mock.ExpectQuery(`SELECT url FROM webhooks`).
		WithArgs("nonexistent").
		WillReturnError(sql.ErrNoRows)

		w := request(router, "POST", "/api/v1/webhooks/nonexistent/test", nil)
		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", w.Code)
		}
	})
}

func TestStatsHandler_Success(t *testing.T) {
	router, mock, _ := setupTestRouter(t)

	mock.ExpectQuery(`SELECT.*COUNT.*FILTER.*FROM devices`).
		WillReturnRows(sqlmock.NewRows([]string{
			"total_devices", "online_devices", "avg_risk_score",
		}).AddRow(10, 5, 3.5))

	mock.ExpectQuery(`SELECT.*COALESCE.*FROM vulnerabilities`).
		WillReturnRows(sqlmock.NewRows([]string{
			"critical_vulns", "high_vulns", "medium_vulns", "low_vulns", "kev_vulns", "open_alerts", "suspicious_firmware",
		}).AddRow(2, 5, 8, 3, 1, 12, 0))

	w := request(router, "GET", "/api/v1/stats", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Data struct {
			TotalDevices       int     `json:"total_devices"`
			OnlineDevices      int     `json:"online_devices"`
			AvgRiskScore       float64 `json:"avg_risk_score"`
			CriticalVulns      int     `json:"critical_vulns"`
			HighVulns          int     `json:"high_vulns"`
			MediumVulns        int     `json:"medium_vulns"`
			LowVulns           int     `json:"low_vulns"`
			KEVVulns           int     `json:"kev_vulns"`
			OpenAlerts         int     `json:"open_alerts"`
			SuspiciousFirmware int     `json:"suspicious_firmware"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Data.TotalDevices != 10 {
		t.Fatalf("expected 10 devices, got %d", resp.Data.TotalDevices)
	}
	if resp.Data.OnlineDevices != 5 {
		t.Fatalf("expected 5 online, got %d", resp.Data.OnlineDevices)
	}
}

func TestRiskBreakdownHandler_Success(t *testing.T) {
	router, mock, _ := setupTestRouter(t)
	deviceID := uuid.NewString()

	vulnRows := sqlmock.NewRows([]string{"title"}).
		AddRow("Telnet exposed").
		AddRow("Default credentials active")

	mock.ExpectQuery(`SELECT title FROM vulnerabilities`).
		WithArgs(deviceID).
		WillReturnRows(vulnRows)

	mock.ExpectQuery(`SELECT COUNT.*FROM vulnerabilities`).
		WithArgs(deviceID).
		WillReturnRows(sqlmock.NewRows([]string{""}).AddRow(2))
	mock.ExpectQuery(`SELECT COUNT.*FROM vulnerabilities`).
		WithArgs(deviceID).
		WillReturnRows(sqlmock.NewRows([]string{""}).AddRow(0))

	mock.ExpectQuery(`SELECT entropy_score FROM firmware`).
		WithArgs(deviceID).
		WillReturnRows(sqlmock.NewRows([]string{"entropy_score"}).AddRow(nil))

	// risk.BuildRiskFactors also reads the last scan age (factor the old
	// inline handler omitted).
	mock.ExpectQuery(`SELECT started_at FROM scans`).
		WithArgs(deviceID).
		WillReturnRows(sqlmock.NewRows([]string{"started_at"}).AddRow(nil))

	w := request(router, "GET", "/api/v1/devices/"+deviceID+"/risk-breakdown", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Data struct {
			TotalScore float64            `json:"total_score"`
			Severity   string             `json:"severity"`
			Breakdown  map[string]float64 `json:"score_breakdown"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Data.TotalScore < 6.0 {
		t.Fatalf("expected score >= 6.0 for default_creds+telnet, got %f", resp.Data.TotalScore)
	}
	if resp.Data.Severity != "critical" {
		t.Fatalf("expected severity critical (score >= 8), got %s (score=%.1f)", resp.Data.Severity, resp.Data.TotalScore)
	}
}

func TestScanProfileHandler_Success(t *testing.T) {
	router, mock, _ := setupTestRouter(t)

	rows := sqlmock.NewRows([]string{
		"id", "name", "description", "skip_credential_test", "skip_protocol_probe",
		"max_port_count", "timeout_seconds", "is_default",
	}).AddRow(
		uuid.NewString(), "Quick Scan", nil, false, false, 1000, 300, true,
	)

	mock.ExpectQuery(`SELECT id, name, description, skip_credential_test, skip_protocol_probe`).
		WillReturnRows(rows)

	w := request(router, "GET", "/api/v1/scan-profiles", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Data []ScanProfile `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Data) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(resp.Data))
	}
}

func TestListFirmwareHandler_Success(t *testing.T) {
	router, mock, _ := setupTestRouter(t)

	rows := sqlmock.NewRows([]string{
		"f.id", "f.device_id", "f.version", "f.vendor", "f.checksum",
		"f.file_path", "f.analyzed_at", "f.entropy_score", "f.has_default_creds",
		"f.has_telnet", "f.has_backdoor_indicators", "f.strings_of_interest",
		"f.cve_matches", "f.analysis_status", "f.analysis_report",
		"d.ip_address", "d.hostname",
	}).AddRow(
		uuid.NewString(), nil, nil, nil, nil,
		nil, nil, 0.0, false,
		false, false, pq.StringArray{},
		pq.StringArray{}, "pending", nil,
		nil, nil,
	)

	mock.ExpectQuery(`SELECT f.id, f.device_id, f.version, f.vendor, f.checksum`).
		WillReturnRows(rows)

	w := request(router, "GET", "/api/v1/firmware", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListVulnerabilitiesHandler_FilterBySeverity(t *testing.T) {
	router, mock, _ := setupTestRouter(t)
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "device_id", "scan_id", "cve_id", "cvss_score", "severity", "title",
		"description", "affected_component", "remediation", "is_kev", "discovered_at",
		"resolved_at", "is_resolved",
	}).AddRow(
		uuid.NewString(), nil, nil, nil, nil,
		"critical", "Critical issue", nil, nil, nil,
		false, now, nil, false,
	)

	mock.ExpectQuery(`SELECT id, device_id, scan_id, cve_id, cvss_score, severity, title`).
		WithArgs("critical").
		WillReturnRows(rows)

	w := request(router, "GET", "/api/v1/vulnerabilities?severity=critical", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestListAlertsHandler_FilterBySeverity(t *testing.T) {
	router, mock, _ := setupTestRouter(t)
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "device_id", "severity", "alert_type", "title", "description",
		"triggered_at", "acknowledged_at", "is_acknowledged", "metadata",
	}).AddRow(
		uuid.NewString(), nil, "high", "telnet_open", "Telnet",
		nil, now, nil, false, nil,
	)

	mock.ExpectQuery(`SELECT id, device_id, severity, alert_type, title, description`).
		WithArgs("high").
		WillReturnRows(rows)

	w := request(router, "GET", "/api/v1/alerts?severity=high", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestListFirmwareHandler_Empty(t *testing.T) {
	router, mock, _ := setupTestRouter(t)

	rows := sqlmock.NewRows([]string{
		"id", "device_id", "version", "vendor", "checksum", "file_path",
		"analyzed_at", "entropy_score", "has_default_creds",
		"has_telnet", "has_backdoor_indicators", "strings_of_interest",
		"cve_matches", "analysis_status", "analysis_report",
		"ip_address", "hostname",
	})

	mock.ExpectQuery(`SELECT f.id, f.device_id, f.version, f.vendor, f.checksum`).
		WillReturnRows(rows)

	w := request(router, "GET", "/api/v1/firmware", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func assertAnError(msg string) error {
	return &testError{msg: msg}
}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

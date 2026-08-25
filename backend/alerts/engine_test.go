package alerts

import (
	"database/sql"
	"encoding/json"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

func newMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, mock
}

func TestSeverityLevel(t *testing.T) {
	tests := []struct {
		sev   string
		level int
	}{
		{"critical", 4},
		{"CRITICAL", 4},
		{"high", 3},
		{"medium", 2},
		{"low", 1},
		{"unknown", 0},
		{"", 0},
	}
	for _, tt := range tests {
		if got := severityLevel(tt.sev); got != tt.level {
			t.Errorf("severityLevel(%q) = %d, want %d", tt.sev, got, tt.level)
		}
	}
}

func TestSeverityCEF(t *testing.T) {
	tests := map[string]string{
		"critical": "10",
		"high":     "7",
		"medium":   "4",
		"low":      "1",
		"other":    "1",
	}
	for sev, want := range tests {
		if got := severityCEF(sev); got != want {
			t.Errorf("severityCEF(%q) = %q, want %q", sev, got, want)
		}
	}
}

func TestBuildSlackPayload(t *testing.T) {
	body, err := buildSlackPayload("critical", "Telnet open", "Port 23 exposed", "device-123")
	if err != nil {
		t.Fatalf("buildSlackPayload error: %v", err)
	}

	var msg map[string]interface{}
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	text, _ := msg["text"].(string)
	if text == "" {
		t.Error("expected non-empty text field")
	}
	if !regexp.MustCompile(`CRITICAL`).MatchString(text) {
		t.Errorf("expected severity in text, got %q", text)
	}

	blocks, _ := msg["blocks"].([]interface{})
	if len(blocks) != 3 {
		t.Fatalf("expected 3 blocks, got %d", len(blocks))
	}
}

func TestBuildSlackPayload_Emoji(t *testing.T) {
	cases := map[string]string{
		"critical": "\U0001F534",
		"high":     "\U0001F7E0",
		"medium":   "\U0001F535",
		"low":      "\u26AA",
	}
	for sev, emoji := range cases {
		body, err := buildSlackPayload(sev, "title", "desc", "dev")
		if err != nil {
			t.Fatalf("buildSlackPayload(%q) error: %v", sev, err)
		}
		if !regexp.MustCompile(regexp.QuoteMeta(emoji)).Match(body) {
			t.Errorf("payload for %q missing emoji %q", sev, emoji)
		}
	}
}

func TestBuildTeamsPayload(t *testing.T) {
	body, err := buildTeamsPayload("high", "ADB exposed", "port 5555", "device-9")
	if err != nil {
		t.Fatalf("buildTeamsPayload error: %v", err)
	}

	var msg map[string]interface{}
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if msg["@type"] != "MessageCard" {
		t.Errorf("unexpected @type: %v", msg["@type"])
	}
	color, _ := msg["themeColor"].(string)
	if color != "FF8C00" {
		t.Errorf("high severity color = %q, want FF8C00", color)
	}
	sections, _ := msg["sections"].([]interface{})
	if len(sections) != 1 {
		t.Fatalf("expected 1 section, got %d", len(sections))
	}
}

func TestBuildGenericPayload(t *testing.T) {
	body, err := buildGenericPayload("alert-1", "medium", "MQTT cleartext", "no TLS on 1883", "device-4")
	if err != nil {
		t.Fatalf("buildGenericPayload error: %v", err)
	}

	var msg struct {
		EventType string `json:"event_type"`
		Source    string `json:"source"`
		Version   string `json:"version"`
		Alert     struct {
			ID          string `json:"id"`
			Severity    string `json:"severity"`
			Title       string `json:"title"`
			Description string `json:"description"`
			DeviceID    string `json:"device_id"`
			Timestamp   string `json:"timestamp"`
		} `json:"alert"`
		CEF string `json:"cef"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if msg.EventType != "security_alert" || msg.Source != "seagles" {
		t.Errorf("unexpected envelope: %+v", msg)
	}
	if msg.Alert.ID != "alert-1" || msg.Alert.DeviceID != "device-4" || msg.Alert.Severity != "medium" {
		t.Errorf("unexpected alert body: %+v", msg.Alert)
	}
	if _, err := time.Parse(time.RFC3339, msg.Alert.Timestamp); err != nil {
		t.Errorf("timestamp not RFC3339: %q", msg.Alert.Timestamp)
	}
	if !regexp.MustCompile(`^CEF:0\|Seagles\|`).MatchString(msg.CEF) {
		t.Errorf("unexpected CEF string: %q", msg.CEF)
	}
}

func TestCreateAlert_Deduplicates(t *testing.T) {
	db, mock := newMockDB(t)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM alerts")).
		WithArgs("device-1", AlertDefaultCreds).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	err := CreateAlert(db, AlertRequest{
		DeviceID:  "device-1",
		AlertType: AlertDefaultCreds,
		Severity:  "critical",
		Title:     "Default credentials active",
	})
	if err != nil {
		t.Fatalf("CreateAlert error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestCreateAlert_Inserts(t *testing.T) {
	db, mock := newMockDB(t)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM alerts")).
		WithArgs("device-2", AlertTelnetOpen).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO alerts")).
		WithArgs("device-2", "critical", AlertTelnetOpen, "Telnet open", "port 23", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("alert-id-42"))

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, name, url, webhook_type, min_severity, secret, headers")).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "url", "webhook_type", "min_severity", "secret", "headers"}))

	err := CreateAlert(db, AlertRequest{
		DeviceID:    "device-2",
		AlertType:   AlertTelnetOpen,
		Severity:    "critical",
		Title:       "Telnet open",
		Description: "port 23",
	})
	if err != nil {
		t.Fatalf("CreateAlert error: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestCreateAlert_InsertFailure(t *testing.T) {
	db, mock := newMockDB(t)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM alerts")).
		WithArgs("device-3", AlertKEVMatch).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO alerts")).
		WithArgs("device-3", "critical", AlertKEVMatch, "KEV hit", "", sqlmock.AnyArg()).
		WillReturnError(sqlmock.ErrCancelled)

	if err := CreateAlert(db, AlertRequest{
		DeviceID:  "device-3",
		AlertType: AlertKEVMatch,
		Severity:  "critical",
		Title:     "KEV hit",
	}); err == nil {
		t.Fatal("expected insert failure to propagate")
	}
}

func TestCheckOfflineDevices(t *testing.T) {
	db, mock := newMockDB(t)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, ip_address FROM devices")).
		WillReturnRows(sqlmock.NewRows([]string{"id", "ip_address"}).
			AddRow("dev-a", "192.168.1.10").
			AddRow("dev-b", "192.168.1.11"))

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM alerts")).
		WithArgs("dev-a", AlertDeviceOffline).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO alerts")).
		WithArgs("dev-a", "medium", AlertDeviceOffline, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("a1"))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, name, url, webhook_type, min_severity, secret, headers")).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "url", "webhook_type", "min_severity", "secret", "headers"}))

	checkOfflineDevices(db)
	time.Sleep(150 * time.Millisecond)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestCheckOfflineDevices_QueryError(t *testing.T) {
	db, mock := newMockDB(t)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, ip_address FROM devices")).
		WillReturnError(sqlmock.ErrCancelled)

	checkOfflineDevices(db)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestCheckFirmwareOverdue(t *testing.T) {
	db, mock := newMockDB(t)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT device_id FROM firmware")).
		WillReturnRows(sqlmock.NewRows([]string{"device_id"}).AddRow("dev-c").AddRow(nil))

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM alerts")).
		WithArgs("dev-c", AlertFirmwareReview).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO alerts")).
		WithArgs("dev-c", "low", AlertFirmwareReview, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("a2"))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, name, url, webhook_type, min_severity, secret, headers")).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "url", "webhook_type", "min_severity", "secret", "headers"}))

	checkFirmwareOverdue(db)
	time.Sleep(150 * time.Millisecond)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestCheckUnresolvedCritical(t *testing.T) {
	db, mock := newMockDB(t)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT DISTINCT device_id FROM vulnerabilities")).
		WillReturnRows(sqlmock.NewRows([]string{"device_id"}).AddRow("dev-d"))

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM alerts")).
		WithArgs("dev-d", AlertCriticalUnresolved).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO alerts")).
		WithArgs("dev-d", "high", AlertCriticalUnresolved, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("a3"))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, name, url, webhook_type, min_severity, secret, headers")).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "url", "webhook_type", "min_severity", "secret", "headers"}))

	checkUnresolvedCritical(db)
	time.Sleep(150 * time.Millisecond)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestDispatchWebhooks_FiltersBySeverity(t *testing.T) {
	db, mock := newMockDB(t)

	rows := sqlmock.NewRows([]string{"id", "name", "url", "webhook_type", "min_severity", "secret", "headers"}).
		AddRow("wh-low", "low hook", "http://localhost/low", "generic", "high", nil, []byte(`{}`)).
		AddRow("wh-any", "any hook", "http://localhost/any", "generic", "low", nil, []byte(`{}`))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, name, url, webhook_type, min_severity, secret, headers")).
		WillReturnRows(rows)

	DispatchWebhooks(db, "alert-9", "medium", "Medium alert", "desc", "device-x")
	time.Sleep(100 * time.Millisecond)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestDispatchWebhooks_CustomHeaders(t *testing.T) {
	db, mock := newMockDB(t)

	rows := sqlmock.NewRows([]string{"id", "name", "url", "webhook_type", "min_severity", "secret", "headers"}).
		AddRow("wh-h", "header hook", "not a valid url", "generic", "low", nil,
			[]byte(`{"X-Custom":"abc"}`))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, name, url, webhook_type, min_severity, secret, headers")).
		WillReturnRows(rows)

	DispatchWebhooks(db, "alert-10", "critical", "t", "d", "dev")
	time.Sleep(250 * time.Millisecond)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

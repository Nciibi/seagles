package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/api/v1/health", "/api/v1/health"},
		{"/api/v1/devices", "/api/v1/devices"},
		{"/api/v1/devices/123", "/api/v1/devices/:id"},
		{"/api/v1/devices/550e8400-e29b-41d4-a716-446655440000", "/api/v1/devices/:id"},
		{"/api/v1/devices/550e8400-e29b-41d4-a716-446655440000/scan", "/api/v1/devices/:id/scan"},
	}

	for _, tt := range tests {
		result := normalizePath(tt.input)
		if result != tt.expected {
			t.Errorf("normalizePath(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestIsUUID(t *testing.T) {
	if !isUUID("550e8400-e29b-41d4-a716-446655440000") {
		t.Fatal("expected valid UUID to return true")
	}
	if isUUID("not-a-uuid") {
		t.Fatal("expected non-UUID to return false")
	}
	if isUUID("") {
		t.Fatal("expected empty string to return false")
	}
}

func TestIsNumeric(t *testing.T) {
	if !isNumeric("12345") {
		t.Fatal("expected numeric string to return true")
	}
	if isNumeric("12a45") {
		t.Fatal("expected non-numeric string to return false")
	}
	if isNumeric("") {
		t.Fatal("expected empty string to return false")
	}
}

func TestMetricsPrometheusOutput(t *testing.T) {
	handler := MetricsHandler()
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestMetricsHandlerEmitsQuantilesAndRuntime(t *testing.T) {
	gin.SetMode(gin.TestMode)

	globalMetrics.mu.Lock()
	originalSamples := globalMetrics.latencySamples
	originalCount := globalMetrics.latencyCount
	originalSum := globalMetrics.latencySum
	globalMetrics.latencySamples = map[string][]float64{"GET /test": {0.1, 0.2, 0.3, 0.4}}
	globalMetrics.latencyCount = map[string]int64{"GET /test": 4}
	globalMetrics.latencySum = map[string]float64{"GET /test": 1.0}
	globalMetrics.mu.Unlock()
	t.Cleanup(func() {
		globalMetrics.mu.Lock()
		globalMetrics.latencySamples = originalSamples
		globalMetrics.latencyCount = originalCount
		globalMetrics.latencySum = originalSum
		globalMetrics.mu.Unlock()
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	MetricsHandler()(c)

	body := w.Body.String()
	for _, want := range []string{
		`# TYPE seagles_request_latency_seconds summary`,
		`seagles_request_latency_seconds{endpoint="GET__test",quantile="0.5"} 0.200000`,
		`seagles_request_latency_seconds{endpoint="GET__test",quantile="0.95"} 0.400000`,
		`seagles_request_latency_seconds_count{endpoint="GET__test"} 4`,
		`seagles_go_goroutines`,
		`seagles_memory_heap_bytes`,
		`seagles_gc_collections_total`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
	if strings.Contains(body, "seagles_request_latency_seconds{endpoint=\"GET__test\"} ") {
		t.Error("latency still exposed as an unlabelled mean")
	}
}

package middleware

import (
	"testing"
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

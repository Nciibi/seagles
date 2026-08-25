package risk

import (
	"math"
	"testing"
)

func TestCalculateRiskScore_Empty(t *testing.T) {
	score := CalculateRiskScore(RiskFactors{})
	if score != 0.0 {
		t.Fatalf("expected 0, got %f", score)
	}
}

func TestCalculateRiskScore_DefaultCreds(t *testing.T) {
	score := CalculateRiskScore(RiskFactors{HasDefaultCreds: true})
	if score != 4.0 {
		t.Fatalf("expected 4.0, got %f", score)
	}
}

func TestCalculateRiskScore_Telnet(t *testing.T) {
	score := CalculateRiskScore(RiskFactors{HasTelnet: true})
	if score != 3.0 {
		t.Fatalf("expected 3.0, got %f", score)
	}
}

func TestCalculateRiskScore_ADB(t *testing.T) {
	score := CalculateRiskScore(RiskFactors{HasADB: true})
	if score != 3.5 {
		t.Fatalf("expected 3.5, got %f", score)
	}
}

func TestCalculateRiskScore_Modbus(t *testing.T) {
	score := CalculateRiskScore(RiskFactors{HasModbus: true})
	expected := 2.5
	if score != expected {
		t.Fatalf("expected %f, got %f", expected, score)
	}
}

func TestCalculateRiskScore_Combined(t *testing.T) {
	score := CalculateRiskScore(RiskFactors{
		HasDefaultCreds: true,
		HasTelnet:       true,
		HasModbus:       true,
	})
	expected := 4.0 + 3.0 + 2.5
	if score != expected {
		t.Fatalf("expected %f, got %f", expected, score)
	}
}

func TestCalculateRiskScore_ClampAt10(t *testing.T) {
	score := CalculateRiskScore(RiskFactors{
		HasDefaultCreds: true,
		HasTelnet:       true,
		HasADB:          true,
		HasModbus:       true,
		HasUnauthRTSP:   true,
		HasPlaintextMQTT: true,
		HasHTTPMgmt:     true,
		HasWeakTLS:      true,
		KnownCVECount:   100,
		KEVMatchCount:   50,
		FirmwareOutdated: true,
		HighEntropyFirmware: true,
		DaysSinceLastScan: 999,
	})
	if score != 10.0 {
		t.Fatalf("expected 10.0 (clamped), got %f", score)
	}
}

func TestCalculateRiskScore_CVECapping(t *testing.T) {
	score := CalculateRiskScore(RiskFactors{KnownCVECount: 10})
	if score != 3.0 {
		t.Fatalf("expected 3.0 (capped at 3), got %f", score)
	}
}

func TestCalculateRiskScore_KEVCapping(t *testing.T) {
	score := CalculateRiskScore(RiskFactors{KEVMatchCount: 10})
	if score != 4.0 {
		t.Fatalf("expected 4.0 (capped at 4), got %f", score)
	}
}

func TestCalculateRiskScore_ScanAge(t *testing.T) {
	score := CalculateRiskScore(RiskFactors{DaysSinceLastScan: 30})
	// 30/30 * 0.1 = 0.1
	if math.Abs(score-0.1) > 0.0001 {
		t.Fatalf("expected 0.1, got %f", score)
	}
}

func TestCalculateRiskScore_ScanAgeCapped(t *testing.T) {
	score := CalculateRiskScore(RiskFactors{DaysSinceLastScan: 999})
	if score != 1.0 {
		t.Fatalf("expected 1.0 (capped), got %f", score)
	}
}

func TestSeverityFromScore(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{0.0, "low"},
		{2.9, "low"},
		{3.0, "medium"},
		{5.9, "medium"},
		{6.0, "high"},
		{7.9, "high"},
		{8.0, "critical"},
		{10.0, "critical"},
	}

	for _, tt := range tests {
		result := SeverityFromScore(tt.score)
		if result != tt.expected {
			t.Errorf("SeverityFromScore(%f) = %s, want %s", tt.score, result, tt.expected)
		}
	}
}

func TestScoreBreakdown_Empty(t *testing.T) {
	b := ScoreBreakdown(RiskFactors{})
	if len(b) != 0 {
		t.Fatalf("expected empty breakdown, got %d entries", len(b))
	}
}

func TestScoreBreakdown_All(t *testing.T) {
	b := ScoreBreakdown(RiskFactors{
		HasDefaultCreds:      true,
		HasTelnet:            true,
		HasADB:               true,
		HasModbus:            true,
		HasUnauthRTSP:        true,
		HasPlaintextMQTT:     true,
		HasHTTPMgmt:          true,
		HasWeakTLS:           true,
		KnownCVECount:        6,
		KEVMatchCount:        2,
		FirmwareOutdated:     true,
		HighEntropyFirmware:  true,
		DaysSinceLastScan:    30,
	})

	expectedKeys := []string{
		"default_credentials", "telnet_exposed", "adb_exposed",
		"modbus_detected", "unauth_rtsp", "plaintext_mqtt",
		"http_management", "weak_tls", "known_cves",
		"kev_matches", "firmware_outdated", "high_entropy_firmware",
		"scan_age",
	}

	for _, key := range expectedKeys {
		if _, ok := b[key]; !ok {
			t.Errorf("expected key '%s' in breakdown", key)
		}
	}

	if b["known_cves"] != 3.0 {
		t.Errorf("expected known_cves=3.0, got %f", b["known_cves"])
	}
	if b["kev_matches"] != 4.0 {
		t.Errorf("expected kev_matches=4.0, got %f", b["kev_matches"])
	}
	if b["default_credentials"] != 4.0 {
		t.Errorf("expected default_credentials=4.0, got %f", b["default_credentials"])
	}
}

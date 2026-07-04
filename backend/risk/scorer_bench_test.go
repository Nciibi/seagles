package risk

import (
	"testing"
)

func BenchmarkCalculateRiskScore_Empty(b *testing.B) {
	factors := RiskFactors{}
	for i := 0; i < b.N; i++ {
		CalculateRiskScore(factors)
	}
}

func BenchmarkCalculateRiskScore_AllFactors(b *testing.B) {
	factors := RiskFactors{
		HasDefaultCreds:      true,
		HasTelnet:            true,
		HasADB:               true,
		HasModbus:            true,
		HasUnauthRTSP:        true,
		HasPlaintextMQTT:     true,
		HasHTTPMgmt:          true,
		HasWeakTLS:           true,
		KnownCVECount:        10,
		KEVMatchCount:        5,
		FirmwareOutdated:     true,
		HighEntropyFirmware:  true,
		DaysSinceLastScan:    90,
	}
	for i := 0; i < b.N; i++ {
		CalculateRiskScore(factors)
	}
}

func BenchmarkSeverityFromScore(b *testing.B) {
	scores := []float64{0.0, 2.9, 3.0, 5.9, 6.0, 7.9, 8.0, 10.0}
	for i := 0; i < b.N; i++ {
		SeverityFromScore(scores[i%len(scores)])
	}
}

func BenchmarkScoreBreakdown(b *testing.B) {
	factors := RiskFactors{
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
	}
	for i := 0; i < b.N; i++ {
		ScoreBreakdown(factors)
	}
}

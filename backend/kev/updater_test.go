package kev

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const testCatalogJSON = `{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2026-08-01",
  "dateReleased": "2026-08-01T00:00:00.0000Z",
  "count": 2,
  "vulnerabilities": [
    {
      "cveID": "CVE-2024-7029",
      "vendorProject": "AVTECH",
      "product": "Cameras",
      "vulnerabilityName": "AVTECH Camera RCE",
      "dateAdded": "2024-11-01",
      "shortDescription": "RCE in AVTECH cameras",
      "requiredAction": "Apply updates",
      "dueDate": "2024-11-22"
    },
    {
      "cveID": "cve-2023-1389",
      "vendorProject": "TP-Link",
      "product": "Routers",
      "vulnerabilityName": "TP-Link Command Injection",
      "dateAdded": "2023-04-10",
      "shortDescription": "Command injection in TP-Link routers",
      "requiredAction": "Apply updates",
      "dueDate": "2023-05-01"
    }
  ]
}`

func writeTestCache(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cisa-kev.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write cache file: %v", err)
	}
	return path
}

func TestLoadKEV(t *testing.T) {
	catalog, err := LoadKEV(writeTestCache(t, testCatalogJSON))
	if err != nil {
		t.Fatalf("LoadKEV error: %v", err)
	}

	if catalog.Count != 2 {
		t.Errorf("Count = %d, want 2", catalog.Count)
	}
	if len(catalog.Vulnerabilities) != 2 {
		t.Fatalf("got %d vulnerabilities, want 2", len(catalog.Vulnerabilities))
	}
	if catalog.Vulnerabilities[0].CVEID != "CVE-2024-7029" {
		t.Errorf("unexpected first entry: %+v", catalog.Vulnerabilities[0])
	}
}

func TestLoadKEV_RecalculatesCount(t *testing.T) {
	catalog, err := LoadKEV(writeTestCache(t, testCatalogJSON))
	if err != nil {
		t.Fatalf("LoadKEV error: %v", err)
	}
	if catalog.Count != len(catalog.Vulnerabilities) {
		t.Errorf("Count %d does not match entries %d", catalog.Count, len(catalog.Vulnerabilities))
	}
}

func TestLoadKEV_MissingFile(t *testing.T) {
	if _, err := LoadKEV(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Fatal("expected error for missing cache file")
	}
}

func TestLoadKEV_InvalidJSON(t *testing.T) {
	if _, err := LoadKEV(writeTestCache(t, "{not json")); err == nil {
		t.Fatal("expected parse error for invalid JSON")
	}
}

func TestIsKEV_CaseInsensitive(t *testing.T) {
	catalog, err := LoadKEV(writeTestCache(t, testCatalogJSON))
	if err != nil {
		t.Fatalf("LoadKEV error: %v", err)
	}

	if !IsKEV(catalog, "CVE-2024-7029") {
		t.Error("expected CVE-2024-7029 to be KEV")
	}
	if !IsKEV(catalog, "cve-2024-7029") {
		t.Error("expected lowercase lookup to match (index is uppercase)")
	}
	if !IsKEV(catalog, "CVE-2023-1389") {
		t.Error("expected lowercase stored entry to be found via uppercase query")
	}
	if IsKEV(catalog, "CVE-0000-0000") {
		t.Error("unknown CVE should not be KEV")
	}
}

func TestIsKEV_NilCatalogAndUnbuiltIndex(t *testing.T) {
	if IsKEV(nil, "CVE-2024-7029") {
		t.Error("nil catalog should never match")
	}
	empty := &KEVCatalog{}
	if IsKEV(empty, "CVE-2024-7029") {
		t.Error("catalog with unbuilt index should never match")
	}
}

func TestGetKEVEntry(t *testing.T) {
	catalog, err := LoadKEV(writeTestCache(t, testCatalogJSON))
	if err != nil {
		t.Fatalf("LoadKEV error: %v", err)
	}

	entry := GetKEVEntry(catalog, "cve-2024-7029")
	if entry == nil {
		t.Fatal("expected entry for cve-2024-7029")
	}
	if entry.VendorProject != "AVTECH" {
		t.Errorf("VendorProject = %q, want AVTECH", entry.VendorProject)
	}
	if GetKEVEntry(catalog, "CVE-9999-9999") != nil {
		t.Error("expected nil for unknown CVE")
	}
	if GetKEVEntry(nil, "CVE-2024-7029") != nil {
		t.Error("nil catalog should return nil entry")
	}
}

func TestFetchEPSSScores_EmptyInput(t *testing.T) {
	scores, err := FetchEPSSScores(nil)
	if err != nil {
		t.Fatalf("FetchEPSSScores(nil) error: %v", err)
	}
	if len(scores) != 0 {
		t.Errorf("expected empty map, got %d entries", len(scores))
	}
}

func TestEPSSResponseParsing(t *testing.T) {
	raw := `{"status":"OK","status-code":200,"version":"1.0",
		"data":[{"cve":"CVE-2024-7029","epss":0.91,"percentile":0.98}]}`
	var resp EPSSResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if resp.Status != "OK" || len(resp.Data) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.Data[0].CVE != "CVE-2024-7029" || resp.Data[0].EPSS != 0.91 {
		t.Errorf("unexpected score: %+v", resp.Data[0])
	}
}

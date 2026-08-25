"""Tests for cve_lookup.py — NVD API query and result filtering."""

import cve_lookup
from cve_lookup import lookup_cve


def nvd_payload(*vulns):
    """Build an NVD-shaped response from (id, cvss31, cvss2, description) tuples."""
    items = []
    for cve_id, v31, v2, desc in vulns:
        cve = {"id": cve_id, "descriptions": [{"lang": "en", "value": desc}]}
        metrics = {}
        if v31 is not None:
            metrics["cvssMetricV31"] = [{"cvssData": {"baseScore": v31}}]
        if v2 is not None:
            metrics["cvssMetricV2"] = [{"cvssData": {"baseScore": v2}}]
        cve["metrics"] = metrics
        items.append({"cve": cve})
    return {"vulnerabilities": items}


class FakeResponse:
    def __init__(self, data, status=200):
        self._data = data
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._data


def patch_no_sleep(monkeypatch):
    monkeypatch.setattr(cve_lookup.time, "sleep", lambda s: None)


class TestLookupCVE:
    def test_empty_keyword_returns_empty(self, monkeypatch):
        patch_no_sleep(monkeypatch)
        assert lookup_cve("", "") == []

    def test_filters_low_cvss(self, monkeypatch):
        patch_no_sleep(monkeypatch)

        captured = {}

        def fake_get(url, params=None, headers=None, timeout=None):
            captured["url"] = url
            captured["params"] = params
            return FakeResponse(nvd_payload(
                ("CVE-2024-1111", 9.8, None, "critical bug"),
                ("CVE-2024-2222", 3.1, None, "low bug - filtered"),
                ("CVE-2024-3333", None, None, "no score - filtered"),
            ))

        monkeypatch.setattr(cve_lookup.requests, "get", fake_get)
        results = lookup_cve("AVTECH", "5.4.3")

        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2024-1111"
        assert results[0]["cvss_score"] == 9.8
        assert results[0]["description"] == "critical bug"
        assert results[0]["url"].endswith("/CVE-2024-1111")

    def test_prefers_v31_over_v2(self, monkeypatch):
        patch_no_sleep(monkeypatch)
        monkeypatch.setattr(
            cve_lookup.requests, "get",
            lambda *a, **k: FakeResponse(nvd_payload(("CVE-2024-4444", 7.5, 5.0, "both scored")))
        )
        results = lookup_cve("vendor", "1.0")
        assert results[0]["cvss_score"] == 7.5

    def test_falls_back_to_v2(self, monkeypatch):
        patch_no_sleep(monkeypatch)
        monkeypatch.setattr(
            cve_lookup.requests, "get",
            lambda *a, **k: FakeResponse(nvd_payload(("CVE-2024-5555", None, 6.0, "v2 only")))
        )
        results = lookup_cve("vendor", "1.0")
        assert results[0]["cvss_score"] == 6.0

    def test_request_params_and_api_key_header(self, monkeypatch):
        patch_no_sleep(monkeypatch)
        captured = {}

        def fake_get(url, params=None, headers=None, timeout=None):
            captured.update({"url": url, "params": params, "headers": headers})
            return FakeResponse({"vulnerabilities": []})

        monkeypatch.setattr(cve_lookup.requests, "get", fake_get)
        lookup_cve("TP-Link", "v2.1", api_key="secret-key")

        assert captured["url"] == cve_lookup.NVD_API_URL
        assert captured["params"]["keywordSearch"] == "TP-Link v2.1"
        assert captured["headers"]["apiKey"] == "secret-key"

    def test_no_api_key_omits_header(self, monkeypatch):
        patch_no_sleep(monkeypatch)
        captured = {}

        def fake_get(url, params=None, headers=None, timeout=None):
            captured["headers"] = headers
            return FakeResponse({"vulnerabilities": []})

        monkeypatch.setattr(cve_lookup.requests, "get", fake_get)
        lookup_cve("vendor", "1.0")
        assert "apiKey" not in captured["headers"]

    def test_rate_limit_delays(self, monkeypatch):
        delays = []
        monkeypatch.setattr(cve_lookup.time, "sleep", delays.append)
        monkeypatch.setattr(
            cve_lookup.requests, "get",
            lambda *a, **k: FakeResponse({"vulnerabilities": []})
        )

        lookup_cve("vendor", "1.0")
        assert delays == [6.0]

        lookup_cve("vendor", "1.0", api_key="k")
        assert delays[-1] == 0.6

    def test_request_failure_returns_error_entry(self, monkeypatch):
        patch_no_sleep(monkeypatch)

        def fail(*a, **k):
            raise ConnectionError("network down")

        monkeypatch.setattr(cve_lookup.requests, "get", fail)
        results = lookup_cve("vendor", "1.0")
        assert len(results) == 1
        assert "network down" in results[0]["error"]

    def test_http_error_returns_error_entry(self, monkeypatch):
        patch_no_sleep(monkeypatch)
        monkeypatch.setattr(
            cve_lookup.requests, "get",
            lambda *a, **k: FakeResponse({}, status=503)
        )
        results = lookup_cve("vendor", "1.0")
        assert "HTTP 503" in results[0]["error"]

    def test_truncates_long_descriptions(self, monkeypatch):
        patch_no_sleep(monkeypatch)
        long_desc = "A" * 2000
        monkeypatch.setattr(
            cve_lookup.requests, "get",
            lambda *a, **k: FakeResponse(nvd_payload(("CVE-2024-6666", 9.0, None, long_desc)))
        )
        results = lookup_cve("vendor", "1.0")
        assert len(results[0]["description"]) == 500

    def test_non_english_description_skipped(self, monkeypatch):
        patch_no_sleep(monkeypatch)
        payload = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-7777",
                    "descriptions": [
                        {"lang": "es", "value": "descripcion en espanol"},
                        {"lang": "en", "value": "english description"},
                    ],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.0}}]},
                }
            }]
        }
        monkeypatch.setattr(
            cve_lookup.requests, "get", lambda *a, **k: FakeResponse(payload)
        )
        results = lookup_cve("vendor", "1.0")
        assert results[0]["description"] == "english description"

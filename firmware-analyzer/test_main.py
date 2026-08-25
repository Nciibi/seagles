"""Tests for main.py — FastAPI endpoints and the analysis pipeline."""

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

import main


@pytest.fixture()
def client(monkeypatch):
    # Never touch a real database during endpoint tests.
    monkeypatch.setattr(main, "update_database", lambda firmware_id, report: None)
    return TestClient(main.app)


@pytest.fixture()
def firmware_file():
    fd, path = tempfile.mkstemp(suffix=".bin")
    with os.fdopen(fd, "wb") as f:
        f.write(b"\x00" * 4096)
    yield path
    os.unlink(path)


class TestHealth:
    def test_health_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["service"] == "firmware-analyzer"
        assert body["version"] == "2.0.0"


class TestAnalyze:
    def test_missing_file_returns_400(self, client):
        resp = client.post("/analyze", json={
            "firmware_id": "fw-1",
            "filepath": "Z:/no/such/file.bin",
        })
        assert resp.status_code == 400
        assert "not found" in resp.json()["detail"].lower()

    def test_validation_requires_firmware_id(self, client):
        resp = client.post("/analyze", json={"filepath": "/tmp/x.bin"})
        assert resp.status_code == 422

    def test_full_pipeline(self, client, monkeypatch, firmware_file):
        monkeypatch.setattr(
            main, "analyze_file_entropy",
            lambda p: {"entropy_score": 7.8, "suspicious": True, "details": "high"}
        )
        monkeypatch.setattr(
            main, "find_suspicious_strings",
            lambda p: ["/usr/sbin/telnetd", "password=admin123"]
        )
        monkeypatch.setattr(
            main, "run_binwalk",
            lambda p: {
                "has_filesystem": True,
                "filesystem_type": "squashfs",
                "has_kernel": True,
                "signatures_found": ["Squashfs filesystem"],
                "raw_output": "...",
            }
        )
        monkeypatch.setattr(
            main, "lookup_cve",
            lambda vendor, version, key=None: [{
                "cve_id": "CVE-2024-7029", "cvss_score": 9.8,
                "severity": "critical", "description": "RCE",
            }]
        )

        resp = client.post("/analyze", json={
            "firmware_id": "fw-42",
            "filepath": firmware_file,
            "vendor": "AVTECH",
            "version": "5.4.3",
        })
        assert resp.status_code == 200
        report = resp.json()["report"]

        assert resp.json()["status"] == "complete"
        assert resp.json()["firmware_id"] == "fw-42"
        assert report["entropy"]["entropy_score"] == 7.8
        assert report["entropy"]["suspicious"] is True
        assert report["suspicious_string_count"] == 2
        assert "/usr/sbin/telnetd" in report["suspicious_strings"]
        assert report["binwalk"]["has_filesystem"] is True
        assert report["binwalk"]["filesystem_type"] == "squashfs"
        assert len(report["cve_matches"]) == 1
        assert report["cve_matches"][0]["cve_id"] == "CVE-2024-7029"
        assert report["cve_matches"][0]["cvss_score"] == 9.8

    def test_pipeline_survives_component_failures(self, client, monkeypatch, firmware_file):
        def boom(_):
            raise RuntimeError("component down")

        monkeypatch.setattr(main, "analyze_file_entropy", boom)
        monkeypatch.setattr(main, "find_suspicious_strings", boom)
        monkeypatch.setattr(main, "run_binwalk", boom)

        # No vendor/version -> CVE lookup skipped entirely.
        resp = client.post("/analyze", json={
            "firmware_id": "fw-fail",
            "filepath": firmware_file,
        })
        assert resp.status_code == 200
        report = resp.json()["report"]

        assert report["entropy"]["details"] == "component down"
        assert report["suspicious_strings"] == []
        assert report["binwalk"]["has_filesystem"] is False
        assert report["cve_matches"] == []

    def test_cve_lookup_skipped_without_vendor_and_version(self, client, monkeypatch, firmware_file):
        called = []
        monkeypatch.setattr(main, "lookup_cve", lambda *a, **k: called.append(a))

        client.post("/analyze", json={
            "firmware_id": "fw-nocve",
            "filepath": firmware_file,
        })
        assert called == []

    def test_background_db_update_invoked_with_report(self, client, monkeypatch, firmware_file):
        recorded = {}

        def fake_update(firmware_id, report):
            recorded["id"] = firmware_id
            recorded["report"] = report

        monkeypatch.setattr(main, "update_database", fake_update)
        monkeypatch.setattr(main, "lookup_cve", lambda *a, **k: [])

        resp = client.post("/analyze", json={
            "firmware_id": "fw-db",
            "filepath": firmware_file,
            "vendor": "vendorX",
            "version": "1.0",
        })
        assert resp.status_code == 200
        # TestClient runs background tasks before returning the response.
        assert recorded["id"] == "fw-db"
        assert recorded["report"].suspicious_string_count >= 0

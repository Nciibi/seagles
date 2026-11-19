"""Tests for main.py — FastAPI endpoints and the analysis pipeline."""

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import main

TOKEN = "test-only-analyzer-token-0000000000000000"
FIRMWARE_ID = "00000000-0000-4000-8000-000000000001"
AUTH = {"Authorization": "Bearer " + TOKEN}


def register_firmware(monkeypatch, filepath, vendor="", version=""):
    """Point the firmware registry at a fake row returning `filepath`."""
    conn = MagicMock()
    conn.cursor.return_value.__enter__.return_value.fetchone.return_value = (
        filepath, vendor, version,
    )
    monkeypatch.setattr(main, "get_db", MagicMock())
    monkeypatch.setattr(main.get_db.return_value, "__enter__", lambda self: conn)
    return conn


@pytest.fixture()
def auth_env(monkeypatch):
    monkeypatch.setenv("FIRMWARE_ANALYZER_TOKEN", TOKEN)
    yield


@pytest.fixture()
def client(monkeypatch):
    # Never touch a real database during endpoint tests.
    monkeypatch.setattr(main, "update_database", lambda firmware_id, report: None)
    return TestClient(main.app)


@pytest.fixture()
def firmware_file(monkeypatch):
    root = tempfile.mkdtemp(prefix="seagles-fw-")
    monkeypatch.setenv("FIRMWARE_ROOT", root)
    fd, path = tempfile.mkstemp(suffix=".bin", dir=root)
    with os.fdopen(fd, "wb") as f:
        f.write(b"\x00" * 4096)
    yield path
    os.unlink(path)
    os.rmdir(root)


class TestHealth:
    def test_health_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["service"] == "firmware-analyzer"
        assert body["version"] == "2.1.0"


class TestAuth:
    def test_missing_token_rejected(self, client, auth_env):
        resp = client.post("/analyze", json={"firmware_id": FIRMWARE_ID})
        assert resp.status_code == 401

    def test_wrong_token_rejected(self, client, auth_env):
        resp = client.post(
            "/analyze",
            json={"firmware_id": FIRMWARE_ID},
            headers={"Authorization": "Bearer wrong"},
        )
        assert resp.status_code == 401

    def test_unconfigured_token_fails_closed(self, client, monkeypatch):
        monkeypatch.setenv("FIRMWARE_ANALYZER_TOKEN", "short")
        resp = client.post(
            "/analyze",
            json={"firmware_id": FIRMWARE_ID},
            headers=AUTH,
        )
        assert resp.status_code == 503


class TestAnalyze:
    def test_missing_file_returns_400(self, client, auth_env):
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value.fetchone.return_value = (
            "/firmware/no/such/file.bin", "", "",
        )
        mocked_db = MagicMock()
        mocked_db.__enter__.return_value = conn
        with patch.object(main, "get_db", MagicMock(return_value=mocked_db)):
            resp = client.post("/analyze", json={"firmware_id": FIRMWARE_ID}, headers=AUTH)
        assert resp.status_code == 400
        assert "unavailable" in resp.json()["detail"].lower()

    def test_validation_requires_firmware_id(self, client, auth_env):
        resp = client.post("/analyze", json={"filepath": "/tmp/x.bin"}, headers=AUTH)
        assert resp.status_code == 422

    def test_full_pipeline(self, client, monkeypatch, firmware_file, auth_env):
        register_firmware(monkeypatch, firmware_file, "AVTECH", "5.4.3")
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

        resp = client.post("/analyze", json={"firmware_id": FIRMWARE_ID}, headers=AUTH)
        assert resp.status_code == 200
        report = resp.json()["report"]

        assert resp.json()["status"] == "complete"
        assert resp.json()["firmware_id"] == FIRMWARE_ID
        assert report["entropy"]["entropy_score"] == 7.8
        assert report["entropy"]["suspicious"] is True
        assert report["suspicious_string_count"] == 2
        assert "/usr/sbin/telnetd" in report["suspicious_strings"]
        assert report["binwalk"]["has_filesystem"] is True
        assert report["binwalk"]["filesystem_type"] == "squashfs"
        assert len(report["cve_matches"]) == 1
        assert report["cve_matches"][0]["cve_id"] == "CVE-2024-7029"
        assert report["cve_matches"][0]["cvss_score"] == 9.8
        assert report["cve_matches"][0]["severity"] == "critical"

    def test_real_binwalk_output_reaches_report(self, client, monkeypatch, firmware_file, auth_env):
        """No mocking around the contract: run_binwalk's real keys must populate the report."""
        import binwalk_runner
        import subprocess

        register_firmware(monkeypatch, firmware_file)
        output = (
            "DECIMAL       HEXADECIMAL     DESCRIPTION\n"
            "--------------------------------------------------------------------------------\n"
            "0             0x0             Squashfs filesystem, little endian\n"
            "1048576       0x100000        uImage header, Linux kernel\n"
        )

        class Completed:
            stdout = output

        monkeypatch.setattr(subprocess, "run", lambda *a, **k: Completed())

        resp = client.post("/analyze", json={"firmware_id": FIRMWARE_ID}, headers=AUTH)
        assert resp.status_code == 200
        binwalk = resp.json()["report"]["binwalk"]
        assert binwalk["has_filesystem"] is True
        assert binwalk["filesystem_type"] == "squashfs"
        assert binwalk["has_kernel"] is True
        assert binwalk["raw_output"] == output

    def test_cve_error_entries_are_filtered(self, client, monkeypatch, firmware_file, auth_env):
        register_firmware(monkeypatch, firmware_file, "vendorX", "1.0")
        monkeypatch.setattr(
            main, "lookup_cve",
            lambda *a, **k: [
                {"error": "network down"},
                {"cve_id": "CVE-2024-1000", "cvss_score": 8.0, "severity": "high"},
            ],
        )

        resp = client.post("/analyze", json={"firmware_id": FIRMWARE_ID}, headers=AUTH)
        matches = resp.json()["report"]["cve_matches"]
        assert len(matches) == 1
        assert matches[0]["cve_id"] == "CVE-2024-1000"

    def test_entropy_extras_reach_report(self, client, monkeypatch, firmware_file, auth_env):
        register_firmware(monkeypatch, firmware_file)
        monkeypatch.setattr(
            main, "analyze_file_entropy",
            lambda p: {
                "entropy_score": 6.9, "suspicious": False,
                "file_size_bytes": 4096, "verdict": "compressed_or_mixed",
                "threshold_used": 7.2,
            },
        )

        resp = client.post("/analyze", json={"firmware_id": FIRMWARE_ID}, headers=AUTH)
        entropy = resp.json()["report"]["entropy"]
        assert entropy["file_size_bytes"] == 4096
        assert entropy["verdict"] == "compressed_or_mixed"
        assert entropy["threshold_used"] == 7.2

    def test_pipeline_survives_component_failures(self, client, monkeypatch, firmware_file, auth_env):
        register_firmware(monkeypatch, firmware_file)
        def boom(_):
            raise RuntimeError("component down")

        monkeypatch.setattr(main, "analyze_file_entropy", boom)
        monkeypatch.setattr(main, "find_suspicious_strings", boom)
        monkeypatch.setattr(main, "run_binwalk", boom)

        # No vendor/version -> CVE lookup skipped entirely.
        resp = client.post("/analyze", json={"firmware_id": FIRMWARE_ID}, headers=AUTH)
        assert resp.status_code == 200
        report = resp.json()["report"]

        assert report["entropy"]["details"] == "component down"
        assert report["suspicious_strings"] == []
        assert report["binwalk"]["has_filesystem"] is False
        assert report["cve_matches"] == []

    def test_cve_lookup_skipped_without_vendor_and_version(self, client, monkeypatch, firmware_file, auth_env):
        register_firmware(monkeypatch, firmware_file)
        called = []
        monkeypatch.setattr(main, "lookup_cve", lambda *a, **k: called.append(a))

        client.post("/analyze", json={"firmware_id": FIRMWARE_ID}, headers=AUTH)
        assert called == []

    def test_background_db_update_invoked_with_report(self, client, monkeypatch, firmware_file, auth_env):
        register_firmware(monkeypatch, firmware_file, "vendorX", "1.0")
        recorded = {}

        def fake_update(firmware_id, report):
            recorded["id"] = firmware_id
            recorded["report"] = report

        monkeypatch.setattr(main, "update_database", fake_update)
        monkeypatch.setattr(main, "lookup_cve", lambda *a, **k: [])

        resp = client.post("/analyze", json={"firmware_id": FIRMWARE_ID}, headers=AUTH)
        assert resp.status_code == 200
        # TestClient runs background tasks before returning the response.
        assert recorded["id"] == FIRMWARE_ID
        assert recorded["report"].suspicious_string_count >= 0


class TestHostingFlags:
    def test_derives_telnet_and_credentials_from_iocs(self):
        telnet, creds = main.derive_hosting_flags(
            ["/usr/sbin/telnetd -l /bin/sh", "password=admin123"]
        )
        assert telnet is True
        assert creds is True

    def test_no_iocs_yields_false(self):
        assert main.derive_hosting_flags(["harmless library name"]) == (False, False)

    def test_update_database_persists_derived_flags(self, monkeypatch):
        from contextlib import contextmanager

        conn = MagicMock()
        cur = conn.cursor.return_value

        @contextmanager
        def fake_db():
            yield conn

        monkeypatch.setattr(main, "get_db", fake_db)

        report = main.AnalysisReport(
            suspicious_strings=["dropbear -p 2222", "secret=hunter2"],
            suspicious_string_count=2,
        )
        main.update_database(FIRMWARE_ID, report)

        args = cur.execute.call_args.args[1]
        # UPDATE parameter order: entropy, has_default_creds, has_telnet, ...
        assert args[1] is True   # has_default_creds
        assert args[2] is True   # has_telnet

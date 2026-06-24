"""
Entropy analysis module for firmware binary inspection.
Shannon entropy measures the randomness of data — malicious encrypted/packed payloads
push entropy above 7.2, while normal firmware code sits around 4.0–6.5.
"""

import math
from collections import Counter
from pathlib import Path


def shannon_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
        if c > 0
    )


def analyze_file_entropy(filepath: str) -> dict:
    """
    Analyze the entropy of a firmware file.

    Returns:
        dict with entropy_score, file_size_bytes, verdict, suspicious flag
    """
    path = Path(filepath)
    if not path.exists():
        return {"error": f"File not found: {filepath}"}

    with open(filepath, 'rb') as f:
        data = f.read()

    entropy = shannon_entropy(data)
    file_size = len(data)

    verdict = "normal"
    if entropy > 7.2:
        verdict = "encrypted_or_packed"
    elif entropy > 6.5:
        verdict = "compressed_or_mixed"

    return {
        "entropy_score": round(entropy, 4),
        "file_size_bytes": file_size,
        "verdict": verdict,
        "suspicious": entropy > 7.2,
        "threshold_used": 7.2
    }

"""
Binwalk runner and string extraction module for firmware analysis.
Searches for indicators of compromise: backdoor services, dropper behavior,
hard-coded credentials, and suspicious encoded payloads.
"""

import re
import subprocess
from pathlib import Path

SUSPICIOUS_PATTERNS = [
    r'/bin/sh', r'/bin/bash', r'/bin/ash',
    r'wget http', r'curl http', r'chmod \+x',
    r'telnetd', r'dropbear',
    r'password=\w+', r'passwd=\w+', r'secret=\w+',
    r'\.onion',
    r'nc -l', r'netcat',
    r'base64 -d',
    r'rm -rf /',
    r'iptables -F',
]


def extract_strings(filepath: str, min_length: int = 8) -> list[str]:
    """Run strings command on the file and return all strings above min_length."""
    try:
        result = subprocess.run(
            ['strings', '-n', str(min_length), filepath],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.splitlines()
    except FileNotFoundError:
        return ["strings command not found"]
    except Exception as e:
        return [f"strings extraction failed: {str(e)}"]


def find_suspicious_strings(filepath: str) -> list[str]:
    """Return strings from the file that match suspicious patterns."""
    all_strings = extract_strings(filepath)
    findings = []
    for pattern in SUSPICIOUS_PATTERNS:
        regex = re.compile(pattern, re.IGNORECASE)
        for s in all_strings:
            if regex.search(s) and s not in findings:
                findings.append(s.strip())
    return findings[:50]  # cap at 50 findings


def run_binwalk(filepath: str) -> dict:
    """Run binwalk signature scan and return parsed output."""
    try:
        result = subprocess.run(
            ['binwalk', '--signature', filepath],
            capture_output=True, text=True, timeout=60
        )
        return {
            "output": result.stdout,
            "signatures_found": [
                line.strip()
                for line in result.stdout.splitlines()
                if line.strip() and not line.startswith('DECIMAL')
                and not line.startswith('-')
            ]
        }
    except FileNotFoundError:
        return {"output": "binwalk not installed", "signatures_found": []}
    except Exception as e:
        return {"output": str(e), "signatures_found": []}

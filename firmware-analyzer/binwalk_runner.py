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


FILESYSTEM_SIGNATURES = (
    "squashfs", "jffs2", "cramfs", "ubifs", "yaffs", "romfs",
    "ext2", "ext3", "ext4", "filesystem",
)
KERNEL_SIGNATURES = ("uimage", "linux kernel", "kernel image")


def _classify_signatures(signatures: list[str]) -> dict:
    """Derive filesystem/kernel facts from binwalk signature description lines."""
    has_filesystem = False
    filesystem_type = None
    has_kernel = False
    for line in signatures:
        lowered = line.lower()
        for kind in FILESYSTEM_SIGNATURES:
            if kind in lowered:
                has_filesystem = True
                if filesystem_type is None and kind != "filesystem":
                    filesystem_type = kind
                break
        if any(kind in lowered for kind in KERNEL_SIGNATURES):
            has_kernel = True
    return {
        "has_filesystem": has_filesystem,
        "filesystem_type": filesystem_type,
        "has_kernel": has_kernel,
    }


def run_binwalk(filepath: str) -> dict:
    """Run binwalk signature scan and return parsed output plus derived facts."""
    try:
        result = subprocess.run(
            ['binwalk', '--signature', filepath],
            capture_output=True, text=True, timeout=60
        )
        signatures = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip() and not line.startswith('DECIMAL')
            and not line.startswith('-')
        ]
        parsed = _classify_signatures(signatures)
        return {
            "output": result.stdout,
            "raw_output": result.stdout,
            "signatures_found": signatures,
            **parsed,
        }
    except FileNotFoundError:
        return {
            "output": "binwalk not installed", "raw_output": "binwalk not installed",
            "signatures_found": [], "has_filesystem": False,
            "filesystem_type": None, "has_kernel": False,
        }
    except Exception as e:
        return {
            "output": str(e), "raw_output": str(e), "signatures_found": [],
            "has_filesystem": False, "filesystem_type": None, "has_kernel": False,
        }

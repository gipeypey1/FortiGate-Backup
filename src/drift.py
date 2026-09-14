"""
Drift Detection and Smart ENC Noise Filter.
Addresses Gotcha #3: Distinguishing real configuration changes from
FortiOS/FortiWeb dynamic IV re-encryption noise (ENC ...).
"""

import difflib
import hashlib
import re
from dataclasses import dataclass
from typing import List, Tuple


# Regex pattern to identify encrypted fields in FortiOS and FortiWeb configs:
# Examples:
#   set password ENC xxxxx
#   set pre-shared-key-local ENC xxxxx
#   set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----..."
#   set secret ENC xxxxx
ENC_PATTERN = re.compile(r'^\s*(set\s+[\w\-]+)\s+ENC\s+[A-Za-z0-9+/=]+', re.IGNORECASE)
ENC_TOKEN_RE = re.compile(r'ENC\s+[A-Za-z0-9+/=]+', re.IGNORECASE)


@dataclass
class DriftAnalysis:
    has_raw_diff: bool
    has_real_drift: bool
    raw_diff: str
    filtered_diff: str
    real_changes: List[str]
    enc_noise_count: int


def calculate_sha256(data: bytes) -> str:
    """Computes SHA-256 hex digest of configuration bytes."""
    return hashlib.sha256(data).hexdigest()


def normalize_enc_line(line: str) -> str:
    """Replaces dynamic ENC token with a placeholder to check if line structure changed."""
    return ENC_TOKEN_RE.sub("ENC <NORMALIZED>", line)


def analyze_drift(
    old_content: str,
    new_content: str,
    old_label: str = "Previous Backup",
    new_label: str = "Current Backup"
) -> DriftAnalysis:
    """
    Compares two configurations and filters out benign dynamic IV changes (ENC noise).
    Returns a DriftAnalysis object indicating whether genuine config drift occurred.
    """
    old_lines = old_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)

    # 1. Generate full unified diff
    raw_diff_lines = list(difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=old_label,
        tofile=new_label,
        n=3
    ))

    if not raw_diff_lines:
        return DriftAnalysis(
            has_raw_diff=False,
            has_real_drift=False,
            raw_diff="",
            filtered_diff="",
            real_changes=[],
            enc_noise_count=0
        )

    raw_diff = "".join(raw_diff_lines)

    # 2. Inspect modified lines to isolate pure ENC re-encryption noise
    # We pair - and + lines that differ solely in their ENC token
    enc_noise_count = 0
    real_changes = []
    filtered_diff_lines = []

    # Process diff line by line
    i = 0
    while i < len(raw_diff_lines):
        line = raw_diff_lines[i]

        # Keep headers
        if line.startswith(("---", "+++", "@@")):
            filtered_diff_lines.append(line)
            i += 1
            continue

        # Look for paired - and + changes
        if line.startswith("-") and (i + 1 < len(raw_diff_lines)) and raw_diff_lines[i + 1].startswith("+"):
            old_stripped = line[1:].strip()
            new_stripped = raw_diff_lines[i + 1][1:].strip()

            # Check if both lines match the ENC pattern and only differ by the ENC token
            if (ENC_PATTERN.match(old_stripped) and ENC_PATTERN.match(new_stripped) and
                    normalize_enc_line(old_stripped) == normalize_enc_line(new_stripped)):
                enc_noise_count += 1
                i += 2
                continue

        # Single modified line or non-paired change
        if line.startswith(("-", "+")):
            stripped = line[1:].strip()
            # If it's a standalone line with ENC, still check if it's benign
            if ENC_PATTERN.match(stripped):
                enc_noise_count += 1
            else:
                real_changes.append(line.rstrip())
                filtered_diff_lines.append(line)
        else:
            # Context line (unmodified)
            filtered_diff_lines.append(line)

        i += 1

    # Cleanup filtered diff: remove orphaned hunk headers if no real diff remains
    has_real_drift = len(real_changes) > 0
    filtered_diff = "".join(filtered_diff_lines) if has_real_drift else ""

    return DriftAnalysis(
        has_raw_diff=True,
        has_real_drift=has_real_drift,
        raw_diff=raw_diff,
        filtered_diff=filtered_diff,
        real_changes=real_changes,
        enc_noise_count=enc_noise_count
    )


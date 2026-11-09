"""Core audit logic: check one password you own, locally.

Findings are deliberately specific so the owner can act on them:
common-password match, too short, missing character classes, repeated
characters / obvious sequences. No finding ever involves contacting a
service or trying the password anywhere.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .common_passwords import is_common
from .entropy import estimate_entropy_bits, strength_label

MIN_RECOMMENDED_LENGTH = 12
SEQUENCES = ("0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop")


@dataclass
class AuditResult:
    label: str  # caller-supplied label, e.g. "demo-1" -- never the password
    length: int
    entropy_bits: float
    strength: str
    is_common: bool
    findings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """Pass = not common, long enough, and at least Moderate."""
        return (
            not self.is_common
            and self.length >= MIN_RECOMMENDED_LENGTH
            and self.strength in ("Moderate", "Strong", "Very strong")
            and not self.findings
        )


def _has_sequence(password: str) -> bool:
    lowered = password.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - 3):
            if seq[i : i + 4] in lowered or seq[i : i + 4][::-1] in lowered:
                return True
    return False


def audit_password(label: str, password: str, common: set[str]) -> AuditResult:
    """Audit a single password. The password itself is never stored or logged
    by this function -- only its length, entropy and findings are returned."""
    findings: list[str] = []
    entropy = estimate_entropy_bits(password)

    if is_common(password, common):
        findings.append("Appears in the common-passwords list -- change it immediately.")
    if len(password) < 8:
        findings.append("Shorter than 8 characters -- below every minimum standard.")
    elif len(password) < MIN_RECOMMENDED_LENGTH:
        findings.append(f"Shorter than the recommended {MIN_RECOMMENDED_LENGTH} characters.")
    if password.isdigit():
        findings.append("Digits only -- trivially guessable.")
    if password.isalpha():
        findings.append("Letters only -- add digits and symbols.")
    if re.search(r"(.)\1{2,}", password):
        findings.append("Contains a character repeated 3+ times in a row.")
    if _has_sequence(password):
        findings.append("Contains an obvious keyboard / numeric sequence.")
    if password.lower() in ("password", "letmein", "admin", "welcome"):
        findings.append("Uses a well-known default / placeholder word.")

    return AuditResult(
        label=label,
        length=len(password),
        entropy_bits=entropy,
        strength=strength_label(entropy, len(password)),
        is_common=is_common(password, common),
        findings=findings,
    )

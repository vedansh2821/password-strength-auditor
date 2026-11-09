"""Local common-password list handling.

The bundled list (``data/common-passwords-sample.txt``) is a *small demo
sample* of famously common passwords, for local testing only. It is not
a cracking wordlist and must not be used to guess anyone else's password.

For a serious audit, replace it with a proper local breach/compromised
list (e.g. the Have I Been Pwned Pwned Passwords list, used offline via
hash ranges) and pass it with ``--common-passwords``.
"""

from __future__ import annotations

from pathlib import Path

DEFAULT_LIST = Path(__file__).resolve().parents[2] / "data" / "common-passwords-sample.txt"


def load_common_passwords(path: str | Path = DEFAULT_LIST) -> set[str]:
    """Load a newline-separated list of common passwords (lower-cased)."""
    passwords: set[str] = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            entry = line.strip()
            if entry:
                passwords.add(entry.lower())
    return passwords


def is_common(password: str, common: set[str]) -> bool:
    """True if the password (case-insensitive) is in the common list."""
    return password.lower() in common

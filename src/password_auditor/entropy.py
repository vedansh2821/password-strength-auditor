"""Entropy estimation for a single password.

Entropy here is a *rough* strength signal, not a security guarantee:
``log2(pool_size ** length)`` where the pool is the set of character
classes actually used. A long passphrase of ordinary words can be strong
despite a modest per-character pool, and a short random string is weak
despite a large pool -- length dominates. We therefore report both the
bit estimate and the raw length, and never call a password "safe" on
entropy alone.
"""

import math
import string


def character_pool(password: str) -> int:
    """Size of the character set the password draws from."""
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    if any(c not in string.printable or ord(c) > 127 for c in password):
        pool += 100  # non-ASCII / unicode adds real search space
    return pool


def estimate_entropy_bits(password: str) -> float:
    """Estimated entropy in bits. Returns 0.0 for an empty password."""
    if not password:
        return 0.0
    pool = character_pool(password)
    if pool <= 1:
        return 0.0
    return round(len(password) * math.log2(pool), 1)


def strength_label(entropy_bits: float, length: int) -> str:
    """Human-readable band. Deliberately conservative at the top end."""
    if length < 8 or entropy_bits < 28:
        return "Very weak"
    if entropy_bits < 36:
        return "Weak"
    if entropy_bits < 60:
        return "Moderate"
    if entropy_bits < 80:
        return "Strong"
    return "Very strong"

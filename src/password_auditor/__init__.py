"""Local-only password strength auditor.

Audits passwords *you own* against a small local list of common passwords
and scores their entropy. No network access, no login attempts, no
credential submission anywhere. See README.md.
"""

from .auditor import AuditResult, audit_password
from .entropy import estimate_entropy_bits, strength_label

__all__ = ["AuditResult", "audit_password", "estimate_entropy_bits", "strength_label"]
__version__ = "1.0.0"

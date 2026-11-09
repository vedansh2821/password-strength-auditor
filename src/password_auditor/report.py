"""Plain-text audit report rendering.

The report never prints a password -- only its label, length, entropy,
strength band and findings. That is deliberate: an audit report is often
shared or filed, and it must never become a password leak.
"""

from __future__ import annotations

from .auditor import AuditResult


def render_report(results: list[AuditResult]) -> str:
    lines = ["Password Strength Audit  (local only -- no network, no logins)", "=" * 64]
    weak = sum(1 for r in results if not r.passed)
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        lines.append(
            f"[{status}] {result.label}: {result.length} chars, "
            f"{result.entropy_bits} bits entropy, {result.strength}"
            + ("  -- COMMON PASSWORD" if result.is_common else "")
        )
        for finding in result.findings:
            lines.append(f"        - {finding}")
    lines.append("-" * 64)
    lines.append(f"Audited: {len(results)}  Passed: {len(results) - weak}  Failed: {weak}")
    if weak:
        lines.append("Remediation: use a password manager, unique 16+ character")
        lines.append("passphrases per account, and enable MFA everywhere it is offered.")
    return "\n".join(lines) + "\n"

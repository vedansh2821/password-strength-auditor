"""Command-line entry point.

Usage:
    python3 -m password_auditor --passwords-file data/sample-passwords-to-audit.txt
    python3 -m password_auditor --password "hunter2" --label demo   # demo only

Passwords are read from a file you own (one per line, ``label:password``
or bare passwords labelled ``entry-N``), or from a single ``--password``
argument for a quick check. Passwords are audited in memory and never
written to the report, never sent anywhere, and never tried against any
service. Do not paste real passwords into a shared terminal or a file
you will commit -- use this on your own machine with your own credentials.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from password_auditor.auditor import audit_password  # noqa: E402
from password_auditor.common_passwords import load_common_passwords  # noqa: E402
from password_auditor.report import render_report  # noqa: E402


def read_passwords_file(path: Path) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            label, password = line.split(":", 1)
            entries.append((label.strip(), password.strip()))
        else:
            entries.append((f"entry-{number}", line))
    return entries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Local-only password strength auditor. No network, no logins."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--passwords-file", type=Path, help="File of passwords you own, one per line.")
    group.add_argument("--password", help="A single password to check (demo / quick check).")
    parser.add_argument("--label", default="cli-entry", help="Label for a --password check.")
    parser.add_argument(
        "--common-passwords",
        type=Path,
        default=None,
        help="Optional local common-passwords list (default: bundled sample).",
    )
    args = parser.parse_args(argv)

    common = load_common_passwords(args.common_passwords) if args.common_passwords else load_common_passwords()

    if args.password is not None:
        entries = [(args.label, args.password)]
    else:
        if not args.passwords_file.exists():
            parser.error(f"passwords file not found: {args.passwords_file}")
        entries = read_passwords_file(args.passwords_file)
    if not entries:
        parser.error("no passwords to audit")

    results = [audit_password(label, pwd, common) for label, pwd in entries]
    print(render_report(results), end="")
    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

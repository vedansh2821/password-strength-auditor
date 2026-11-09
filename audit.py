#!/usr/bin/env python3
"""Thin wrapper so the auditor runs from the repo root: ``python3 audit.py ...``.

See ``src/password_auditor/__main__.py`` for usage. Local only, stdlib only.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from password_auditor.__main__ import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())

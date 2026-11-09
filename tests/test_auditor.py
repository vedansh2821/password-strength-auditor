"""Unit tests for the local password auditor (stdlib unittest only)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from password_auditor.auditor import audit_password  # noqa: E402
from password_auditor.common_passwords import load_common_passwords  # noqa: E402
from password_auditor.entropy import estimate_entropy_bits  # noqa: E402


class TestAuditor(unittest.TestCase):
    def setUp(self):
        self.common = load_common_passwords()

    def test_common_password_flagged(self):
        result = audit_password("t", "password", self.common)
        self.assertTrue(result.is_common)
        self.assertFalse(result.passed)

    def test_strong_passphrase_passes(self):
        result = audit_password("t", "Tr0pic@l-River-88-Mango!", self.common)
        self.assertTrue(result.passed)
        self.assertGreater(result.entropy_bits, 80)

    def test_short_password_fails(self):
        result = audit_password("t", "abc123", self.common)
        self.assertFalse(result.passed)
        self.assertIn("8 characters", " ".join(result.findings))

    def test_entropy_grows_with_length(self):
        self.assertLess(
            estimate_entropy_bits("aaaa"), estimate_entropy_bits("aaaaaaaaaaaa")
        )

    def test_no_network_usage(self):
        # The auditor modules must not import any networking library.
        import password_auditor.auditor as auditor_mod
        import password_auditor.common_passwords as common_mod
        import password_auditor.entropy as entropy_mod

        for mod in (auditor_mod, common_mod, entropy_mod):
            source = Path(mod.__file__).read_text(encoding="utf-8")
            for banned in ("import requests", "import socket", "urllib", "http.client"):
                self.assertNotIn(banned, source)


if __name__ == "__main__":
    unittest.main()

"""Regression tests preventing GUI configuration secrets from reaching logs."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUI = ROOT / "gui"
for entry in (str(GUI), str(ROOT)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from utils.ui_helpers import (  # noqa: E402
    default_secret_warnings as _default_secret_warnings,
    redacted_env_export_message as _redacted_env_export_message,
    redacted_env_skip_message as _redacted_env_skip_message,
)


class SecretRedactionTests(unittest.TestCase):
    def test_environment_export_message_never_contains_value(self):
        secret = "do-not-print-this-password"
        message = _redacted_env_export_message("BKPS_DB_PASSWORD")

        self.assertIn("BKPS_DB_PASSWORD", message)
        self.assertIn("value hidden", message)
        self.assertNotIn(secret, message)
        self.assertNotIn("=", message)

    def test_malformed_environment_entry_does_not_echo_content(self):
        message = _redacted_env_skip_message(7)

        self.assertEqual(
            message,
            "[env] ignored malformed entry on line 7 (content hidden)",
        )

    def test_default_secret_warnings_name_fields_but_not_values(self):
        values = {
            "ssl_password": "ssl_password",
            "pkcs11_password": "pkcs11_password",
            "keystore_password": "keystore_password",
            "db_password": "bkps_password",
            "pg_superuser_password": "postgres",
            "aes_passphrase": "aes_passphrase",
            "programmer_cert_password": "programmer_cert_password",
            "softhsm_user_pin": "12345678",
            "softhsm_so_pin": "12345678",
            "bc_keystore_password": "bc_keystore_password",
        }

        warnings = _default_secret_warnings(values, "bouncycastle")
        rendered = "\n".join(warnings)

        self.assertEqual(len(warnings), 10)
        self.assertIn("SSL password is set to its default value", rendered)
        self.assertIn("SoftHSM user PIN is set to its default value", rendered)
        for raw_value in set(values.values()):
            self.assertNotIn(raw_value, rendered)

    def test_changed_secrets_do_not_generate_default_warning(self):
        values = {
            "ssl_password": "changed-ssl-secret",
            "pkcs11_password": "changed-pkcs11-secret",
        }

        self.assertEqual(_default_secret_warnings(values, "luna"), [])


if __name__ == "__main__":
    unittest.main()

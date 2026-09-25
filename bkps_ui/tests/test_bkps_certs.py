"""Unit tests for bkps_certs."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))

import bkps_certs as certs  # noqa: E402


class CertsTests(unittest.TestCase):
    def test_list_trusted_certs(self):
        cfg = SimpleNamespace(bkps_dir="/tmp")
        with patch.object(certs, "_runner") as runner:
            certs.list_trusted_certs(cfg)
            runner.assert_called_once_with(cfg, "communication", "list")

    def test_delete_trusted_cert_success_and_failure(self):
        cfg = SimpleNamespace(bkps_dir="/tmp")
        with patch.object(certs, "_runner", return_value=MagicMock(returncode=0)), \
             patch.object(certs, "audit_log"):
            certs.delete_trusted_cert(cfg, "alias1")
        with patch.object(certs, "_runner", return_value=MagicMock(returncode=1)), \
             patch.object(certs, "audit_log"):
            with self.assertRaises(RuntimeError):
                certs.delete_trusted_cert(cfg, "alias1")

    def test_delete_prompts_or_requires_alias(self):
        cfg = SimpleNamespace(bkps_dir="/tmp")
        with patch.object(certs, "_runner"), \
             patch.object(certs, "audit_log"), \
             patch.object(sys.stdin, "isatty", return_value=False):
            with self.assertRaises(ValueError):
                certs.delete_trusted_cert(cfg, "")
        with patch.object(certs, "_runner", return_value=MagicMock(returncode=0)), \
             patch.object(certs, "audit_log"), \
             patch.object(sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value=""):
            with self.assertRaises(ValueError):
                certs.delete_trusted_cert(cfg, "")
        with patch.object(certs, "_runner", return_value=MagicMock(returncode=0)) as runner, \
             patch.object(certs, "audit_log"), \
             patch.object(sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="a1"):
            certs.delete_trusted_cert(cfg, "")
            self.assertIn("a1", runner.call_args[0])

    def test_import_root_cert_paths(self):
        cfg = SimpleNamespace(bkps_dir="/tmp")
        with self.assertRaises(ValueError):
            certs.import_root_cert(cfg, "")
        with self.assertRaises(FileNotFoundError):
            certs.import_root_cert(cfg, "/no/such/cert.pem")
        with tempfile.TemporaryDirectory() as root:
            pem = Path(root) / "ca.pem"
            pem.write_text("CERT")
            with patch.object(certs, "_runner", return_value=MagicMock(returncode=0, stderr="")):
                certs.import_root_cert(cfg, str(pem))
            with patch.object(
                certs, "_runner",
                return_value=MagicMock(returncode=2, stderr="boom\n"),
            ):
                with self.assertRaises(RuntimeError):
                    certs.import_root_cert(cfg, str(pem))


if __name__ == "__main__":
    unittest.main()

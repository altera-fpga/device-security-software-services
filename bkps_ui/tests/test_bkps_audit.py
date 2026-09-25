"""Unit tests for bkps_audit."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))

import bkps_audit as audit  # noqa: E402


class AuditLogTests(unittest.TestCase):
    def test_writes_json_line_with_details_and_username(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = SimpleNamespace(bkps_dir=root, username="tester")
            audit.audit_log(cfg, "create_super_admin", details="id=1", outcome="success")
            log_path = Path(root) / "logs" / "audit.log"
            self.assertTrue(log_path.is_file())
            entry = json.loads(log_path.read_text(encoding="utf-8").strip())
            self.assertEqual(entry["action"], "create_super_admin")
            self.assertEqual(entry["outcome"], "success")
            self.assertEqual(entry["details"], "id=1")
            self.assertEqual(entry["user"], "tester")
            self.assertIn("ts", entry)

    def test_falls_back_to_getpass_user_without_details(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = SimpleNamespace(bkps_dir=root)
            with patch.object(audit.getpass, "getuser", return_value="osuser"):
                audit.audit_log(cfg, "rotate_key")
            entry = json.loads((Path(root) / "logs" / "audit.log").read_text().strip())
            self.assertEqual(entry["user"], "osuser")
            self.assertEqual(entry["outcome"], "started")
            self.assertNotIn("details", entry)

    def test_never_raises_on_io_failure(self):
        cfg = SimpleNamespace(bkps_dir="/proc/does-not-exist-for-audit")
        with patch.object(audit.os, "makedirs", side_effect=OSError("boom")):
            audit.audit_log(cfg, "noop")


if __name__ == "__main__":
    unittest.main()

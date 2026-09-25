#!/usr/bin/env python3
"""Regression tests for BKPS server runtime preflight validation."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


TOOL_DIR = Path(__file__).resolve().parents[1]
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

import bkps_server


class BkpsServerPreflightTests(unittest.TestCase):
    def _config(self, root: Path) -> SimpleNamespace:
        return SimpleNamespace(bkps_dir=str(root), profile_name="agilex5")

    def test_missing_keystore_blocks_start_preflight(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "bkps-1.0.jar").touch()
            (root / "config").mkdir()
            (root / "config" / "application-agilex5.yml").touch()

            with self.assertRaisesRegex(
                FileNotFoundError, "bkps_keystore.p12"
            ):
                bkps_server._validate_bkps_server_runtime(self._config(root))

    def test_complete_runtime_returns_executable_jar(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "bkps-1.0.jar").touch()
            (root / "config").mkdir()
            (root / "config" / "application-agilex5.yml").touch()
            (root / "keys").mkdir()
            (root / "keys" / "bkps_keystore.p12").touch()

            jar = bkps_server._validate_bkps_server_runtime(self._config(root))

        self.assertEqual(jar, "bkps-1.0.jar")


if __name__ == "__main__":
    unittest.main()

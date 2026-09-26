#!/usr/bin/env python3
"""Regression tests for the Config-tab BKPS release selector."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
GUI = ROOT / "gui"
for entry in (str(GUI), str(ROOT)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

try:
    from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QComboBox  # noqa: E402
    from tabs.tab_config import ConfigTab  # noqa: E402

    HAS_QT = True
except ImportError:
    HAS_QT = False


@unittest.skipUnless(HAS_QT, "PySide6/Qt native libraries unavailable")
class ReleaseFetchComboTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._app = QApplication.instance() or QApplication([])

    @staticmethod
    def _host(current: str = ""):
        combo = QComboBox()
        combo.setEditable(True)
        if current:
            combo.setEditText(current)
        return SimpleNamespace(
            _combo_release=combo,
            _btn_fetch_release=QPushButton(),
            _lbl_release_status=QLabel(),
        )

    def test_first_fetch_selects_first_release_without_line_edit_error(self):
        host = self._host()

        ConfigTab._on_releases_fetched(host, ["master", "release/26.1.1"])

        self.assertEqual(host._combo_release.currentText(), "master")
        self.assertTrue(host._btn_fetch_release.isEnabled())
        self.assertFalse(host._combo_release.signalsBlocked())

    def test_custom_release_is_preserved_when_not_returned_by_github(self):
        host = self._host("feature/local-test")

        ConfigTab._on_releases_fetched(host, ["master", "release/26.1.1"])

        self.assertEqual(host._combo_release.currentText(), "feature/local-test")
        self.assertFalse(host._combo_release.signalsBlocked())

    def test_failed_fetch_preserves_manual_release(self):
        host = self._host("release/offline")

        ConfigTab._on_releases_fetched(host, [])

        self.assertEqual(host._combo_release.currentText(), "release/offline")
        self.assertIn("enter release manually", host._lbl_release_status.text())


if __name__ == "__main__":
    unittest.main()

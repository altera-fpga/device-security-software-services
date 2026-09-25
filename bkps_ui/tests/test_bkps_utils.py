#!/usr/bin/env python3
"""Unit tests for bkps_utils.py (PySide6 GUI helpers, offscreen)."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

TOOL_DIR = Path(__file__).resolve().parents[1]
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

try:
    from PySide6.QtWidgets import QApplication, QLineEdit, QPushButton, QWidget  # noqa: E402

    import utils.bkps_utils as uu  # noqa: E402

    HAS_QT = True
except ImportError:
    HAS_QT = False


@unittest.skipUnless(HAS_QT, "PySide6/Qt native libraries unavailable")
class BkpsUtilsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_btn_variants(self):
        b = uu._btn("Go", primary=True, tip="t", width=80)
        self.assertEqual(b.objectName(), "primaryButton")
        self.assertEqual(b.toolTip(), "t")
        self.assertEqual(b.width(), 80)

        d = uu._btn("Del", danger=True)
        self.assertEqual(d.objectName(), "dangerButton")

        s = uu._btn("Ok", success=True, object_name="customOk")
        self.assertEqual(s.objectName(), "customOk")

    def test_password_eye_icons(self):
        open_icon = uu._password_eye_icon(open_eye=True)
        closed_icon = uu._password_eye_icon(open_eye=False)
        self.assertFalse(open_icon.isNull())
        self.assertFalse(closed_icon.isNull())

    def test_attach_password_revealer_native_toggle(self):
        le = QLineEdit()
        le.setPasswordVisibilityToggleEnabled = mock.Mock()  # type: ignore[attr-defined]
        with mock.patch(
            "utils.bkps_utils.hasattr",
            side_effect=lambda obj, name: True
            if name == "setPasswordVisibilityToggleEnabled"
            else hasattr(obj, name),
        ):
            uu._attach_password_revealer(le)
        le.setPasswordVisibilityToggleEnabled.assert_called_once_with(True)

    def test_attach_password_revealer_action_path(self):
        le = QLineEdit()
        # Ensure hasattr(..., setPasswordVisibilityToggleEnabled) is False.
        with mock.patch(
            "utils.bkps_utils.hasattr",
            side_effect=lambda obj, name: False
            if name == "setPasswordVisibilityToggleEnabled"
            else hasattr(obj, name),
        ):
            uu._attach_password_revealer(le)
        actions = le.actions()
        self.assertEqual(len(actions), 1)
        actions[0].setChecked(True)
        self.assertEqual(le.echoMode(), QLineEdit.EchoMode.Normal)
        actions[0].setChecked(False)
        self.assertEqual(le.echoMode(), QLineEdit.EchoMode.Password)

    def test_le_variants(self):
        fields = {}
        parent = QWidget()
        a = uu._le("ph", text="hi", parent=parent, tip="tip", style="color:red", attr="x", fields=fields)
        self.assertEqual(a.text(), "hi")
        self.assertIs(fields["x"], a)

        b = uu._le(text="only")
        self.assertEqual(b.text(), "only")

        c = uu._le(parent=parent)
        self.assertIsInstance(c, QLineEdit)

        d = uu._le(password=True, read_only=True, max_width=50, max_length=8)
        self.assertEqual(d.echoMode(), QLineEdit.EchoMode.Password)
        self.assertTrue(d.isReadOnly())

    def test_combo_editable_and_plain(self):
        c1 = uu._combo(tip="t")
        self.assertEqual(c1.toolTip(), "t")
        c2 = uu._combo(editable=True, minimum_width=120)
        self.assertTrue(c2.isEditable())
        self.assertIsNotNone(c2.lineEdit())
        with mock.patch.object(uu.QComboBox, "lineEdit", return_value=None):
            c3 = uu._combo(editable=True)
        self.assertTrue(c3.isEditable())

    def test_hrow_and_file_row(self):
        le = QLineEdit()
        btn = QPushButton("x")
        row = uu._hrow(le, btn)
        self.assertEqual(row.count(), 3)  # two widgets + stretch

        called = []
        layout = uu._file_row(QLineEdit(), lambda: called.append(1))
        browse = layout.itemAt(1).widget()
        browse.click()
        self.assertEqual(called, [1])

        extra = QPushButton("e")
        wrapped = uu._file_row(QLineEdit(), lambda: None, extra=extra, widget=True)
        self.assertIsInstance(wrapped, QWidget)

    def test_pick_dialogs(self):
        parent = QWidget()
        with mock.patch.object(
            uu.QFileDialog, "getOpenFileName", return_value=("/a/b", "flt")
        ):
            self.assertEqual(uu._pick_file(parent, "t"), "/a/b")
        with mock.patch.object(
            uu.QFileDialog, "getSaveFileName", return_value=("/s", "")
        ):
            self.assertEqual(uu._pick_save_file(parent, "t"), "/s")
        with mock.patch.object(
            uu.QFileDialog, "getExistingDirectory", return_value="/d"
        ):
            self.assertEqual(uu._pick_dir(parent, "t"), "/d")


if __name__ == "__main__":
    unittest.main()

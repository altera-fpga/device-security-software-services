"""Unit tests for bkps_printer."""

from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))

import bkps_printer as printer  # noqa: E402


class PrinterOutputTests(unittest.TestCase):
    def test_message_helpers_emit_tags(self):
        buf = io.StringIO()
        with patch.object(sys, "stdout", buf):
            printer.print_header("Title")
            printer.print_step(1, "one")
            printer.print_step(2, "nested", parent=1)
            printer.print_info("i")
            printer.print_success("s")
            printer.print_warning("w")
            printer.print_error("e")
        text = buf.getvalue()
        self.assertIn("Title", text)
        self.assertIn("[STEP 1]", text)
        self.assertIn("[STEP 1.2]", text)
        self.assertIn("[INFO]", text)
        self.assertIn("[PASS]", text)
        self.assertIn("[WARNING]", text)
        self.assertIn("[ERROR]", text)

    def test_ask_confirmation_yes_flag(self):
        self.assertTrue(printer.ask_confirmation("Go?", yes=True))

    def test_ask_confirmation_non_tty_raises(self):
        with patch.object(sys.stdin, "isatty", return_value=False):
            with self.assertRaises(RuntimeError):
                printer.ask_confirmation("Go?", yes=False)

    def test_ask_confirmation_accept_and_reject(self):
        with patch.object(sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            self.assertTrue(printer.ask_confirmation("Go?"))
        with patch.object(sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="n"):
            self.assertFalse(printer.ask_confirmation("Go?"))


if __name__ == "__main__":
    unittest.main()

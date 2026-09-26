#!/usr/bin/env python3
"""Regression tests for log line framing, terminal control codes, and colour.

These cover three observed display faults:

  * consecutive messages rendered on one line, e.g.
    ``[INFO] Log monitoring stopped[PASS] BKPS server started in background``
  * a multi-line summary collapsed into one line, e.g. the auto-detected tool
    list printed as ``Auto-Detect Tools found: SoftHSM library: ... pkcs11-tool: ...``
  * Gradle's rich console leaking as literal text, e.g. ``[2A[1B> Starting Daemon[17D``
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOL_DIR = Path(__file__).resolve().parents[1]
GUI_DIR = TOOL_DIR / "gui"
for entry in (str(GUI_DIR), str(TOOL_DIR)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import bkps_build  # noqa: E402
import bkps_runner  # noqa: E402

try:
    from PySide6.QtGui import QTextCursor  # noqa: E402
    from PySide6.QtWidgets import QApplication  # noqa: E402

    import stdout_capture  # noqa: E402
    from log_panel import LogPanel  # noqa: E402

    HAS_QT = True
except ImportError:  # PySide6 is absent in CLI-only installs
    HAS_QT = False


class StreamLineFramingTests(unittest.TestCase):
    """A streamed chunk must never yield an unterminated fragment."""

    def test_only_complete_lines_are_returned(self):
        lines, remainder = bkps_runner.split_stream_chunk("first\nsecond\nthi")

        self.assertEqual(["first", "second"], lines)
        self.assertEqual("thi", remainder)

    def test_a_progress_update_is_not_emitted_without_its_newline(self):
        """The partial write is what glued the next message onto the line.

        The old reader wrote the tail after the last carriage return straight to
        stdout with no newline, so StdoutCapture held it and concatenated the
        following message onto its end.
        """
        lines, remainder = bkps_runner.split_stream_chunk("10%\r20%\r30")

        self.assertEqual(["20%"], lines)
        self.assertEqual("30", remainder)
        for line in lines:
            self.assertNotIn("\r", line)

    def test_a_carriage_return_inside_a_line_keeps_the_final_state(self):
        lines, remainder = bkps_runner.split_stream_chunk("10%\r20%\r100% done\n")

        self.assertEqual(["100% done"], lines)
        self.assertEqual("", remainder)

    def test_a_bare_carriage_return_produces_no_line(self):
        lines, remainder = bkps_runner.split_stream_chunk("\r")

        self.assertEqual([], lines)
        self.assertEqual("", remainder)

    def test_blank_lines_survive(self):
        lines, remainder = bkps_runner.split_stream_chunk("a\n\nb\n")

        self.assertEqual(["a", "", "b"], lines)
        self.assertEqual("", remainder)

    def test_messages_arriving_in_separate_chunks_stay_separate(self):
        buffer = ""
        collected = []
        for chunk in ("[INFO] Log monitoring stopped\n", "[PASS] BKPS server started\n"):
            buffer += chunk
            lines, buffer = bkps_runner.split_stream_chunk(buffer)
            collected.extend(lines)

        self.assertEqual(
            ["[INFO] Log monitoring stopped", "[PASS] BKPS server started"],
            collected,
        )


class GradleConsoleTests(unittest.TestCase):
    """Plain console keeps the cursor codes from being produced at all."""

    def test_gradle_opts_request_the_plain_console(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.object(bkps_build, "_proxy_java_opts", return_value=""):
                opts = bkps_build._build_gradle_opts(temp_dir)

        self.assertIn("-Dorg.gradle.console=plain", opts.split())
        self.assertIn("-Dorg.gradle.daemon=false", opts.split())


@unittest.skipUnless(HAS_QT, "PySide6 is not installed")
class TerminalControlCodeTests(unittest.TestCase):
    """Only SGR colour survives; cursor movement and erasure are dropped."""

    def test_cursor_and_erase_sequences_do_not_reach_the_panel(self):
        raw = "\x1b[2A\x1b[1B> Starting Daemon\x1b[17D\x1b[0K"

        rendered = stdout_capture._ansi_to_html(raw)

        self.assertEqual("&gt; Starting Daemon", rendered)
        for leak in ("[2A", "[1B", "[17D", "[0K", "\x1b"):
            self.assertNotIn(leak, rendered)

    def test_a_gradle_progress_bar_line_is_reduced_to_its_text(self):
        raw = "\x1b[2A<=------------> 9% CONFIGURING [1s]\x1b[35D\x1b[1B"

        rendered = stdout_capture._ansi_to_html(raw)

        self.assertEqual("&lt;=------------&gt; 9% CONFIGURING [1s]", rendered)

    def test_colour_sequences_are_still_converted(self):
        rendered = stdout_capture._ansi_to_html("\x1b[0;32m[PASS]\x1b[0m done")

        self.assertIn('<span style="color:#50fa7b">', rendered)
        self.assertIn("[PASS]", rendered)
        self.assertIn("done", rendered)

    def test_a_carriage_return_resolves_to_the_final_state(self):
        rendered = stdout_capture._ansi_to_html("Downloading 10%\rDownloading 100%")

        self.assertEqual("Downloading 100%", rendered)


@unittest.skipUnless(HAS_QT, "PySide6 is not installed")
class LogPanelLineSeparationTests(unittest.TestCase):
    """Every logical line must occupy its own paragraph."""

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def _panel_lines(self, panel: LogPanel) -> list[str]:
        # Indentation is held open with &nbsp;, which reads back as \xa0.
        return panel._text.toPlainText().replace("\xa0", " ").split("\n")

    def test_separate_batches_do_not_merge_at_the_boundary(self):
        """insertHtml merges its first block into the block the cursor is in.

        With one <div> per line that merge put the first line of each drain on
        the end of the previous drain's last line.
        """
        panel = LogPanel("Boundary")
        panel.append_batch(["Access URLs:"])
        panel.append_batch(["[INFO] Log monitoring stopped"])
        panel.append_batch(["[PASS] BKPS server started in background"])

        self.assertEqual(
            [
                "Access URLs:",
                "[INFO] Log monitoring stopped",
                "[PASS] BKPS server started in background",
            ],
            self._panel_lines(panel),
        )

    def test_successive_colored_messages_stay_on_their_own_lines(self):
        panel = LogPanel("Colored")
        panel.append_success("Config loaded: D:/bkps_demo/agx5_full/config.conf")
        panel.append_success("Auto-Detect Tools found:")

        self.assertEqual(
            [
                "Config loaded: D:/bkps_demo/agx5_full/config.conf",
                "Auto-Detect Tools found:",
            ],
            self._panel_lines(panel),
        )

    def test_an_embedded_newline_becomes_a_real_line_break(self):
        panel = LogPanel("Multiline")
        panel.append_success(
            "Auto-Detect Tools found:\n  SoftHSM library: a.dll\n  pkcs11-tool: b.exe"
        )

        self.assertEqual(
            [
                "Auto-Detect Tools found:",
                "  SoftHSM library: a.dll",
                "  pkcs11-tool: b.exe",
            ],
            self._panel_lines(panel),
        )

    def test_indentation_is_not_collapsed_by_the_renderer(self):
        """Build output is read by its alignment, and HTML collapses spaces."""
        panel = LogPanel("Indent")
        panel.append_plain("> Task :bkps:compileJava")
        panel.append_plain("      warning: nested detail")

        self.assertEqual(
            ["> Task :bkps:compileJava", "      warning: nested detail"],
            self._panel_lines(panel),
        )

    def test_plain_text_also_splits_on_newlines(self):
        panel = LogPanel("Plain")
        panel.append_plain("one\ntwo")

        self.assertEqual(["one", "two"], self._panel_lines(panel))

    def test_a_multiline_message_is_written_to_the_log_file_line_by_line(self):
        with tempfile.TemporaryDirectory(dir=TOOL_DIR) as root:
            panel = LogPanel("Persisted", log_root=root)
            panel.append_warning("first\nsecond")

            logged = Path(panel._log_file).read_text(encoding="utf-8")

        body = logged.replace(os.linesep, "\n").split("\n")
        self.assertIn("first", body)
        self.assertIn("second", body)

    def test_colour_does_not_bleed_into_the_following_line(self):
        """A block opened after a coloured line must start from a clean format."""
        panel = LogPanel("Bleed")
        panel.append_error("failed")
        panel.append_plain("neutral")

        document = panel._text.document()
        cursor = QTextCursor(document.findBlockByNumber(document.blockCount() - 1))
        cursor.movePosition(
            QTextCursor.MoveOperation.EndOfBlock,
            QTextCursor.MoveMode.KeepAnchor,
        )

        self.assertEqual("neutral", cursor.selectedText())
        self.assertNotEqual(
            "#ff5555", cursor.charFormat().foreground().color().name()
        )


if __name__ == "__main__":
    unittest.main()

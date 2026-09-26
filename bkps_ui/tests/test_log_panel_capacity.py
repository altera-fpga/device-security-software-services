"""Regression tests for log panel rendering cost during long builds."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUI = ROOT / "gui"
for entry in (str(GUI), str(ROOT)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

try:
    from PySide6.QtWidgets import QApplication  # noqa: E402

    from log_panel import MAX_LIVE_LOG_LINES, LogPanel  # noqa: E402

    HAS_QT = True
except ImportError:
    HAS_QT = False


def _app():
    return QApplication.instance() or QApplication([])


@unittest.skipUnless(HAS_QT, "PySide6/Qt native libraries unavailable")
class LogPanelCapacityTests(unittest.TestCase):
    def setUp(self):
        self.app = _app()

    def test_the_live_document_is_bounded(self):
        """An unbounded document makes every later repaint lay out the build."""
        panel = LogPanel("Capacity")

        self.assertEqual(
            MAX_LIVE_LOG_LINES, panel._text.document().maximumBlockCount()
        )

    def test_output_beyond_the_cap_trims_the_oldest_lines(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as root:
            panel = LogPanel("Trim", log_root=root)
            overflow = MAX_LIVE_LOG_LINES + 500
            panel.append_batch([f"line {index}" for index in range(overflow)])

            document = panel._text.document()
            self.assertLessEqual(document.blockCount(), MAX_LIVE_LOG_LINES)
            visible = panel._text.toPlainText()
            self.assertIn(f"line {overflow - 1}", visible)
            self.assertNotIn("line 0\n", visible)

            # The complete output still reaches the panel's log file.
            logged = Path(panel._log_file).read_text(
                encoding="utf-8", errors="replace"
            )
            self.assertIn("line 0", logged)
            self.assertIn(f"line {overflow - 1}", logged)

    def test_new_output_follows_the_tail(self):
        panel = LogPanel("Tail")
        panel.resize(400, 200)
        panel.show()
        panel.append_batch([f"line {index}" for index in range(500)])
        self.app.processEvents()

        scrollbar = panel._text.verticalScrollBar()
        self.assertEqual(scrollbar.maximum(), scrollbar.value())
        panel.close()

    def test_scrolling_up_is_not_yanked_back_by_new_output(self):
        panel = LogPanel("Scrollback")
        panel.resize(400, 200)
        panel.show()
        panel.append_batch([f"line {index}" for index in range(500)])
        self.app.processEvents()

        scrollbar = panel._text.verticalScrollBar()
        parked = scrollbar.maximum() // 2
        scrollbar.setValue(parked)
        panel.append_batch([f"later {index}" for index in range(100)])
        self.app.processEvents()

        self.assertEqual(parked, scrollbar.value())
        panel.close()


if __name__ == "__main__":
    unittest.main()

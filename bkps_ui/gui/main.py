#!/usr/bin/env python3
"""
main.py - Entry point for the BKPS Demo Automation GUI.

Usage:
    python main.py [config_file]

If *config_file* is provided it will be loaded automatically on startup.
"""

import signal
import sys
import os

# Ensure bkps/gui/ itself is on sys.path so sibling imports work
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

# Ensure bkps/ (parent) is on sys.path so tool imports (bkps_config etc.) work
_parent = os.path.dirname(_here)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon, QFont, QPalette, QColor
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QToolTip

from stdout_capture import StdoutCapture
from config_store import ConfigStore
from app_window import AppWindow


def main():
    """Application entry point.

    Configures the Qt application (style, fonts, palette, high-DPI),
    creates the singleton ConfigStore and StdoutCapture, optionally
    pre-loads a config file passed on the command line, then opens
    AppWindow and enters the Qt event loop.

    Returns:
        Exits via sys.exit() — does not return normally.
    """
    # Allow Ctrl+C to kill the Qt process on all platforms.
    # SIG_DFL restores default SIGINT → process terminates.
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    # High-DPI support (PySide6 6.x enables it by default, but be explicit)
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("BKPS Demo Automation")
    app.setOrganizationName("Intel")

    # Use Fusion style so Qt renders all widgets itself (no native Windows controls).
    # This makes QSS rules — including QToolTip { } — apply reliably on all platforms.
    app.setStyle("Fusion")

    # Apply stylesheet
    qss_path = os.path.join(_here, "resources", "style.qss")
    if os.path.isfile(qss_path):
        with open(qss_path) as f:
            app.setStyleSheet(f.read())

    # Global font
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    QToolTip.setFont(QFont("Segoe UI", 9))

    # Force tooltip colors via palette (bypasses QSS inheritance on Linux)
    palette = app.palette()
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#2d2d2d"))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#e0e0e0"))
    app.setPalette(palette)

    # ── stdout capture ────────────────────────────────────────────────────
    # Redirect stdout BEFORE creating any tabs (so all print() is captured)
    # from imports, config loading, and tab __init__ calls.
    capture = StdoutCapture()
    sys.stdout = capture

    # ── config ────────────────────────────────────────────────────────────
    store = ConfigStore()

    # Prefer an explicit config passed on the command line.  Otherwise restore
    # the last config the operator successfully loaded or saved.  Persisting
    # only that file path keeps source and project directories independent and
    # avoids hard-wired machine/user locations.
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if args:
        if os.path.isfile(args[0]):
            try:
                store.load(args[0])
            except Exception as e:
                print(f"Warning: could not load config '{args[0]}': {e}")
        else:
            print(f"Warning: config file not found: '{args[0]}'")
    else:
        try:
            restored = store.restore_last()
            if restored:
                print(f"Restored project config: {restored}")
        except Exception as e:
            print(f"Warning: could not restore the previous project config: {e}")

    # ── window ────────────────────────────────────────────────────────────
    window = AppWindow(store, capture)
    window.show()

    # ── signal-delivery workaround ────────────────────────────────────────
    # Periodic no-op timer so Python can process OS signals (e.g. SIGINT/Ctrl+C)
    # inside the Qt event loop — without this, Qt blocks signal delivery on Windows.
    # The lambda does nothing; it just gives the Python interpreter a chance to run.
    _sig_timer = QTimer()
    _sig_timer.setInterval(200)
    _sig_timer.timeout.connect(lambda: None)
    _sig_timer.start()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()

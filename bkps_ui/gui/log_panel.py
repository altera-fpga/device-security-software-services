#!/usr/bin/env python3
"""
log_panel.py - Reusable log display widget.

LogPanel is a dark-background QTextEdit that displays HTML-formatted
log lines emitted by StdoutCapture. Each tab gets its own LogPanel
so output is scoped per-operation.

Each LogPanel also persists output to a deterministic per-tab log file:
    <workspace>/bkps_gui_logs/<tab_name>.log
The file is append-only so repeated actions in the same tab accumulate.
"""

import html
import os
import re
from pathlib import Path
from datetime import datetime

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QFont, QTextBlockFormat, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QPushButton, QLabel,
)

# Lines retained in the live widget. Every line is still written to the
# panel's log file, so this bounds rendering cost rather than history.
MAX_LIVE_LOG_LINES = 20_000

# Scrollbar slack, in pixels, still treated as "following the tail".
_TAIL_SLACK = 4


class LogPanel(QWidget):
    """Dark log panel with auto-scroll and a Clear button.

    Displays HTML-formatted log lines produced by StdoutCapture.  Each
    tab has its own LogPanel so output is isolated per operation.  Lines
    are also written to an append-only file under the project's logs/
    directory so they survive widget clears.
    """

    def __init__(self, title: str = "Output", parent=None, log_root: str | None = None):
        """Create a LogPanel.

        Args:
            title:    Display title shown in the panel header and used as
                      the log file's base name (sanitised to be filesystem-safe).
            parent:   Optional Qt parent widget.
            log_root: Absolute path to the directory where the log file is
                      written.  If None or empty, file logging is disabled
                      until set_log_root() is called.
        """
        super().__init__(parent)
        self._title = title
        self._log_root = log_root
        self._log_file = self._build_log_path(title, log_root)
        # Ensure file exists immediately and mark session start (only when log root is configured).
        if self._log_file:
            self._append_file_line(f"===== {self._title} session started: {datetime.now().isoformat(timespec='seconds')} =====")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

    # ── Header row ─────────────────────────────────────────────────────
        header = QHBoxLayout()
        self._title_label = QLabel(title)
        self._title_label.setStyleSheet(
            "color: #888; font-size: 11px; font-weight: bold;"
        )
        header.addWidget(self._title_label)
        header.addStretch()

        self._clear_btn = QPushButton("Clear")
        self._clear_btn.setFixedSize(50, 20)
        self._clear_btn.setStyleSheet(
            "QPushButton { background: #333; color: #aaa; border: 1px solid #555; border-radius: 3px; font-size: 11px; }"
            "QPushButton:hover { background: #444; }"
        )
        self._clear_btn.clicked.connect(self.clear)
        header.addWidget(self._clear_btn)

        layout.addLayout(header)

    # ── Text area ──────────────────────────────────────────────────────
        self._text = QTextEdit()
        self._text.setReadOnly(True)
        self._text.setObjectName("logPanel")
        # Bound the live document. A full repository build emits container
        # image builds, cross-compiles, and whole-repo test output, and an
        # unbounded document makes every later repaint lay out all of it, so
        # the window degrades as the build proceeds. The complete log is kept
        # on disk under logs/, which is where long history belongs.
        self._text.document().setMaximumBlockCount(MAX_LIVE_LOG_LINES)
        # Disable undo history — the log is read-only and never needs it,
        # and keeping an undo stack for tens of thousands of insertHtml
        # calls quietly bloats memory and slows rendering.
        self._text.setUndoRedoEnabled(False)
        # Word-wrap long lines so extra-wide Quartus output stays visible
        # even without a horizontal scrollbar.
        self._text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        mono = QFont("Consolas", 9)
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self._text.setFont(mono)
        self._text.setStyleSheet(
            "QTextEdit#logPanel {"
            "  background-color: #0d0d0d;"
            "  color: #cccccc;"
            "  border: 1px solid #333;"
            "  border-radius: 4px;"
            "}"
        )
        layout.addWidget(self._text)

    def set_log_root(self, log_root: str | None) -> None:
        """Update target log directory (used when cfg.bkps_dir changes at runtime).

        Args:
            log_root: New directory path.  Pass None to disable file logging.
        """
        self._log_root = log_root
        new_path = self._build_log_path(self._title, self._log_root)
        if new_path != self._log_file:
            self._log_file = new_path
            if self._log_file:
                self._append_file_line(
                    f"===== {self._title} session switched: {datetime.now().isoformat(timespec='seconds')} ====="
                )

    def set_title(self, title: str) -> None:
        """Switch the display title and deterministic persisted log file."""
        title = title.strip() or "Output"
        if title == self._title:
            return
        self._title = title
        self._title_label.setText(title)
        self._log_file = self._build_log_path(title, self._log_root)
        if self._log_file:
            self._append_file_line(
                f"===== {self._title} session switched: "
                f"{datetime.now().isoformat(timespec='seconds')} ====="
            )

    def _insert_lines(self, html_lines: list) -> None:
        """Append each line as its own paragraph, following the tail.

        One paragraph per line is what makes the document's line cap effective
        and keeps layout incremental: ``<br>`` separators would place a whole
        build's output in a single paragraph, which the cap cannot trim and
        which has to be laid out in full on every repaint.

        Each block is opened explicitly instead of relying on block-level HTML.
        ``insertHtml`` merges the first block of its fragment into the block the
        cursor sits in, so a ``<div>`` per line still ran the first line of every
        batch onto the end of the previous batch's last line. A fresh character
        format is set with each block so a colour left open by one line cannot
        bleed into the next.

        A local cursor is used instead of the widget's own text cursor so a
        large document is not re-laid-out for a selection change, and the view
        scrolls only when it already sits at the bottom, so output arriving
        during a build cannot yank the view away from an operator who scrolled
        up to read.
        """
        if not html_lines:
            return
        scrollbar = self._text.verticalScrollBar()
        following_tail = scrollbar.value() >= scrollbar.maximum() - _TAIL_SLACK
        document = self._text.document()
        cursor = QTextCursor(document)
        cursor.movePosition(QTextCursor.MoveOperation.End)
        for line in html_lines:
            if not document.isEmpty():
                cursor.insertBlock(QTextBlockFormat(), QTextCharFormat())
            if line:
                cursor.insertHtml(line)
        if following_tail:
            scrollbar.setValue(scrollbar.maximum())

    @Slot(str)
    def append_html(self, html: str) -> None:
        """Append one HTML-formatted line and auto-scroll to bottom.

        Args:
            html: An HTML fragment; it becomes its own paragraph.
        """
        self._insert_lines([html])
        self._append_file_line(_html_to_text(html))

    @Slot(list)
    def append_batch(self, html_lines: list) -> None:
        """Append multiple HTML-formatted lines in a single insert.

        Args:
            html_lines: List of HTML fragments to append in order.
        """
        if not html_lines:
            return
        self._insert_lines(html_lines)
        self._append_file_lines([_html_to_text(line) for line in html_lines])

    def append_plain(self, text: str) -> None:
        """Append text that is displayed literally, markup and all."""
        lines = _split_lines(text)
        self._insert_lines([_esc(line) for line in lines])
        self._append_file_lines(lines)

    def _append_colored(self, text: str, color: str) -> None:
        """Append *text* in *color*, one paragraph per embedded newline.

        Callers pass multi-line summaries, such as a detected-tool list, as a
        single string. HTML collapses a newline, so without this split the whole
        summary renders as one run-on line.

        Args:
            text:  Plain text; may contain newlines.
            color: CSS colour applied to every resulting line.
        """
        lines = _split_lines(text)
        self._insert_lines(
            [f'<span style="color:{color}">{_esc(line)}</span>' for line in lines]
        )
        self._append_file_lines(lines)

    def append_info(self, text: str) -> None:
        """Append *text* in cyan (informational message)."""
        self._append_colored(text, "#8be9fd")

    def append_success(self, text: str) -> None:
        """Append *text* in green (successful result)."""
        self._append_colored(text, "#50fa7b")

    def append_error(self, text: str) -> None:
        """Append *text* in red (error or failure)."""
        self._append_colored(text, "#ff5555")

    def append_warning(self, text: str) -> None:
        """Append *text* in yellow (warning or non-fatal issue)."""
        self._append_colored(text, "#f1fa8c")

    @Slot()
    def clear(self) -> None:
        """Clear all text from the widget (does not truncate the log file)."""
        self._text.clear()

    def _build_log_path(self, title: str, log_root: str | None = None) -> str:
        """Return a deterministic per-tab log file path.

        Sanitises *title* to a safe filename component so every tab maps to
        a unique, predictable path.  Creates the log directory if needed.

        Args:
            title:    The LogPanel title string.
            log_root: Target directory for log files.  Empty / None → returns "".

        Returns:
            Absolute path to the .log file, or "" if log_root is not set.
        """
        if not log_root:
            return ""
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", title.strip().lower()).strip("_") or "output"
        root = Path(log_root)
        root.mkdir(parents=True, exist_ok=True)
        return str(root / f"{safe}.log")

    def _append_file_line(self, text: str) -> None:
        """Append a single plain-text line to the log file.

        Args:
            text: Plain text line (HTML tags already stripped).
        """
        if text is None:
            return
        self._append_file_lines([text])

    def _append_file_lines(self, lines: list[str]) -> None:
        """Append multiple plain-text lines to the log file atomically.

        Opens the file once per call to avoid excessive open/close overhead
        during high-throughput batch output.  File I/O errors are silently
        swallowed so a broken log path never interrupts the UI.

        Args:
            lines: Sequence of plain text lines to append.
        """
        if not self._log_file:
            return
        try:
            with open(self._log_file, "a", encoding="utf-8") as f:
                for line in lines:
                    f.write((line if line is not None else "") + os.linesep)
        except Exception:
            pass


def _split_lines(text) -> list[str]:
    """Split *text* into display lines, resolving carriage-return overwrites."""
    if text is None:
        return [""]
    lines = str(text).replace("\r\n", "\n").split("\n")
    return [
        line.rstrip("\r").split("\r")[-1] if "\r" in line else line
        for line in lines
    ]


def _preserve_spacing(text: str) -> str:
    """Keep indentation visible, since HTML collapses runs of whitespace.

    Build output is read by its alignment, so a nested Gradle task or a Quartus
    detail line losing its indent changes what the operator sees.
    """
    text = text.expandtabs(4)
    stripped = text.lstrip(" ")
    leading = len(text) - len(stripped)
    body = re.sub(
        r"  +", lambda m: "&nbsp;" * (len(m.group()) - 1) + " ", stripped
    )
    return "&nbsp;" * leading + body


def _esc(text: str) -> str:
    escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _preserve_spacing(escaped)


def _html_to_text(fragment: str) -> str:
    """Best-effort conversion from log HTML fragment to plain text."""
    if fragment is None:
        return ""
    text = fragment
    text = text.replace("<br>", "\n").replace("<br/>", "\n").replace("<br />", "\n")
    text = re.sub(r"<[^>]+>", "", text)
    # Indentation is carried as &nbsp; for the widget; the file wants real spaces.
    return html.unescape(text).replace("\xa0", " ")

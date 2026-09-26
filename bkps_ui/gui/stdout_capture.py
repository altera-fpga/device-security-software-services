#!/usr/bin/env python3
"""
stdout_capture.py - Redirect sys.stdout to Qt signals with per-tab routing.

StdoutCapture replaces sys.stdout so that all print() calls are forwarded
to the appropriate tab's LogPanel via thread registration.

Per-tab routing:
  Each worker thread calls register_thread(batch_cb) at the start of its work
  and unregister_thread() at the end. sys.stdout.write() in that thread is
  then routed to the thread's own pending list → batch_cb(html_lines).

  The drain timer (150 ms) drains all registered routes' pending lists,
  calling the appropriate callback for each. Because the timer runs on the
  main thread, all Qt widget calls are safe.

Unregistered threads:
  Output goes to the default batch_emitted signal (typically not connected
  or connected to a fallback log panel).
"""

import re
import sys
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

from PySide6.QtCore import QObject, Signal, QTimer, Qt


# ANSI color code → CSS color mapping
_ANSI_MAP = {
    "31": "color:#ff5555",   # RED
    "32": "color:#50fa7b",   # GREEN
    "33": "color:#f1fa8c",   # YELLOW
    "34": "color:#6699ff",   # BLUE
    "35": "color:#ff79c6",   # MAGENTA
    "36": "color:#8be9fd",   # CYAN
    "37": "color:#f8f8f2",   # WHITE
    "1":  "font-weight:bold",
}

_ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")
# Everything a terminal understands but a text widget does not. Gradle's rich
# console drives the cursor with CSI sequences such as \x1b[2A, \x1b[0K, and
# \x1b[39D; without this they reach the panel as the literal text "[2A[0K[39D".
# The SGR form is excluded here because _ansi_to_html turns it into colour.
_ANSI_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-ln-~]")
_ANSI_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_ANSI_OTHER_RE = re.compile(r"\x1b[@-Z\\-_]|\x1b\][^\x07\x1b]*$|\x1b$")
# High enough that a full Quartus programming burst drains inside a single
# tick — with the previous 100/tick cap the display consistently lagged
# multiple seconds behind the actual subprocess output and looked "clipped"
# to operators when a step finished before the tail caught up.
_MAX_LINES_PER_DRAIN = 2000


def _strip_terminal_controls(text: str) -> str:
    """Remove cursor-control escapes and resolve carriage-return overwrites.

    A text widget cannot act on cursor movement or line erasure, so those
    sequences are dropped rather than shown. Carriage returns are resolved to
    the final overwrite state, which is what the same output would look like
    on a terminal once the line settled.

    Args:
        text: One raw output line, possibly carrying terminal control codes.

    Returns:
        The same line with only SGR colour sequences left in place.
    """
    text = _ANSI_OSC_RE.sub("", text)
    text = _ANSI_CSI_RE.sub("", text)
    text = _ANSI_OTHER_RE.sub("", text)
    if "\r" in text:
        text = text.rstrip("\r").split("\r")[-1]
    return text


def _ansi_to_html(text: str) -> str:
    """Convert ANSI escape codes to HTML spans. Strips unsupported codes.

    Iterates over all ANSI SGR sequences (\\x1b[...m) in *text*, converts
    known colour/style codes to inline CSS, and HTML-escapes all literal
    text.  Unknown codes are silently dropped.

    Args:
        text: A raw string that may contain ANSI CSI SGR escape sequences.

    Returns:
        An HTML fragment with ANSI codes replaced by <span style="...">
        elements; all literal characters are HTML-escaped.
    """
    text = _strip_terminal_controls(text)
    result = []
    last = 0
    open_span = False

    for m in _ANSI_RE.finditer(text):
        # Append plain text before this match (HTML-escaped)
        plain = text[last:m.start()]
        if plain:
            result.append(_escape(plain))

        code = m.group(1).strip()
        last = m.end()

        if code in ("0", ""):
            # Reset
            if open_span:
                result.append("</span>")
                open_span = False
        else:
            # Handle compound codes like "1;32"
            styles = []
            for part in code.split(";"):
                if part in _ANSI_MAP:
                    styles.append(_ANSI_MAP[part])
            if styles:
                if open_span:
                    result.append("</span>")
                result.append(f'<span style="{";".join(styles)}">')
                open_span = True

    # Remaining text
    tail = text[last:]
    if tail:
        result.append(_escape(tail))
    if open_span:
        result.append("</span>")

    return "".join(result)


def _escape(text: str) -> str:
    """HTML-escape the three characters that break inline HTML: & < >.

    Args:
        text: Plain text that may contain HTML-special characters.

    Returns:
        The same text with & → &amp;, < → &lt;, > → &gt;, and runs of spaces
        held open with &nbsp; so indentation is not collapsed by the renderer.
    """
    escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    escaped = escaped.expandtabs(4)
    stripped = escaped.lstrip(" ")
    leading = len(escaped) - len(stripped)
    body = re.sub(
        r"  +", lambda m: "&nbsp;" * (len(m.group()) - 1) + " ", stripped
    )
    return "&nbsp;" * leading + body


# ── Per-thread route descriptor ────────────────────────────────────────────

@dataclass
class _Route:
    """State kept per registered worker thread."""
    buffer:   str  = ""                           # partial line accumulator
    pending:  list = field(default_factory=list)  # raw text lines
    batch_cb: Optional[Callable] = None           # called with [html,...] on main thread
    finished: bool = False                        # set when thread unregisters


# ── StdoutCapture ──────────────────────────────────────────────────────────

class StdoutCapture(QObject):
    """
    Replaces sys.stdout with per-thread routing.

    Registered thread:
      writes → route.pending → route.batch_cb(html_lines) → tab's LogPanel

    Unregistered thread:
      writes → self._pending → batch_emitted signal (fallback)

    The 150 ms timer drains ALL pending lists on the main thread so all Qt
    widget calls are thread-safe.
    """
    line_emitted  = Signal(str)   # single line (legacy, not used with routing)
    batch_emitted = Signal(list)  # fallback for unregistered threads

    def __init__(self, parent=None):
        """Initialise and start the 50 ms drain timer.

        After construction, assign the instance to sys.stdout so that
        all subsequent print() calls are intercepted.
        """
        super().__init__(parent)
        self._original = sys.stdout
        # Default path (unregistered workers)
        self._buffer = ""
        self._pending: list = []
        # Per-thread routes keyed on threading.get_ident()
        self._routes: dict[int, _Route] = {}
        self._lock = threading.Lock()  # guards _routes, _pending, _buffer

        # Drain timer runs on main thread - increased frequency for more responsive output
        self._timer = QTimer(self)
        self._timer.setInterval(50)  # Drain every 50ms for more responsive output
        self._timer.timeout.connect(self._drain_all, Qt.ConnectionType.DirectConnection)
        self._timer.start()

    def cleanup(self) -> None:
        """Stop the drain timer and flush any remaining buffered output.

        Call this before the application exits to ensure no lines are lost.
        """
        if self._timer:
            self._timer.stop()
        self._drain_all()

    # ── Thread registration (per-tab routing) ──────────────────────────────

    def register_thread(self, batch_cb: Callable) -> None:
        """
        Register the *calling* thread to route its stdout to *batch_cb*.

        Must be called from within the worker thread (not from the main thread)
        so that threading.get_ident() returns the worker's ID.

        batch_cb(html_lines: list[str]) will be invoked from the main-thread
        drain timer — safe to call Qt widget methods directly.
        """
        route = _Route(batch_cb=batch_cb)
        with self._lock:
            self._routes[threading.get_ident()] = route

    def unregister_thread(self) -> None:
        """Unregister the calling thread. Call in finally / teardown."""
        tid = threading.get_ident()
        with self._lock:
            route = self._routes.get(tid)
            if route is not None:
                # Flush buffer to pending
                if route.buffer:
                    route.pending.append(route.buffer)
                    route.buffer = ""
                # Mark as finished so drain timer can clean it up after draining
                route.finished = True

    # ── sys.stdout interface ───────────────────────────────────────────────

    def write(self, text: str) -> int:
        """Accept a string written to sys.stdout and buffer it by thread.

        Splits *text* on newlines so complete lines are queued for the
        drain timer while incomplete lines accumulate in the buffer.

        Args:
            text: The string passed to print() or sys.stdout.write().

        Returns:
            Number of characters received (standard file-object interface).
        """
        tid = threading.get_ident()
        with self._lock:
            route = self._routes.get(tid)
            if route is not None:
                # Registered thread → go to route's pending list
                route.buffer += text
                while "\n" in route.buffer:
                    line, route.buffer = route.buffer.split("\n", 1)
                    route.pending.append(line)
            else:
                # Unregistered thread → go to default pending list
                self._buffer += text
                while "\n" in self._buffer:
                    line, self._buffer = self._buffer.split("\n", 1)
                    self._pending.append(line)
        return len(text)

    def flush(self):
        """Flush any partial (non-newline-terminated) buffer to the pending list.

        Also flushes the original stdout so external tools that check for
        a real flush don't block.
        """
        tid = threading.get_ident()
        with self._lock:
            route = self._routes.get(tid)
            if route is not None and route.buffer:
                route.pending.append(route.buffer)
                route.buffer = ""
            elif route is None and self._buffer:
                self._pending.append(self._buffer)
                self._buffer = ""
        try:
            self._original.flush()
        except Exception:
            pass

    def fileno(self):
        """Delegate fileno() to the original stdout for subprocess compatibility."""
        return self._original.fileno()

    def isatty(self):
        """Always return False; StdoutCapture is not a TTY."""
        return False

    # ── Drain timer (runs on main thread) ─────────────────────────────────

    def _drain_all(self) -> None:
        """Drain pending lists and call callbacks. Called from main thread."""
        finished_routes = []

        with self._lock:
            # Drain per-thread routes
            for tid, route in list(self._routes.items()):
                if route.pending and route.batch_cb:
                    lines = route.pending[: _MAX_LINES_PER_DRAIN]
                    route.pending = route.pending[_MAX_LINES_PER_DRAIN:]
                    html_lines = [_ansi_to_html(ln) for ln in lines]
                    try:
                        route.batch_cb(html_lines)
                    except Exception as e:
                        # Don't let callback errors break the timer
                        try:
                            self._original.write(f"Error in batch_cb: {e}\n")
                            self._original.flush()
                        except:
                            pass

                # Clean up finished routes that have no more pending output
                if route.finished and not route.pending:
                    finished_routes.append(tid)

            # Remove finished routes
            for tid in finished_routes:
                self._routes.pop(tid, None)

            # Drain default pending list
            if self._pending:
                lines = self._pending[:_MAX_LINES_PER_DRAIN]
                self._pending = self._pending[_MAX_LINES_PER_DRAIN:]
                html_lines = [_ansi_to_html(ln) for ln in lines]
                self.batch_emitted.emit(html_lines)

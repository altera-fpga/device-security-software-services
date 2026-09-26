#!/usr/bin/env python3
"""
tabs/__init__.py - BaseTab base class for all BKPS GUI tabs.

Provides:
- A consistent layout: top controls area (QGroupBox) + bottom LogPanel
- run_worker() helper to fire a BkpsWorker without boilerplate
- on_error() / on_finished() default handlers tabs can override
- busy-state management (disable buttons while a worker is running)
"""

from __future__ import annotations

from typing import Callable, List
from pathlib import Path

from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QSplitter, QPushButton, QScrollArea,
)

from log_panel import LogPanel
from worker import BkpsWorker
from config_store import ConfigStore
from stdout_capture import StdoutCapture


def _escape_tb(tb: str) -> str:
    """HTML-escape a Python traceback string for safe insertion into a <pre> block.

    Args:
        tb: Raw traceback string from traceback.format_exc().

    Returns:
        The same string with &, < and > replaced by HTML entities.
    """
    return tb.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class BaseTab(QWidget):
    """
    Base class for every tab widget in the BKPS Demo Automation AppWindow.

    Provides a consistent two-panel layout (scrollable controls above a
    LogPanel), a run_worker() helper that wires stdout routing and signal
    connections automatically, and default on_finished() / on_error()
    handlers that subclasses may override for custom behaviour.

    Subclasses must implement build_controls(), which returns a QWidget
    (typically a QGroupBox) containing the tab's buttons and input fields.
    """

    def __init__(
        self,
        store: ConfigStore,
        capture: StdoutCapture,
        log_title: str = "Output",
        parent=None,
    ):
        """Initialise the base tab layout.

        Args:
            store:     Shared ConfigStore instance.
            capture:   Active StdoutCapture; workers register their thread
                       here for per-tab stdout routing.
            log_title: Title for this tab's LogPanel (also used as the log
                       file base name).
            parent:    Optional Qt parent widget.
        """
        super().__init__(parent)
        self._store = store
        self._capture = capture
        self._workers: List[BkpsWorker] = []
        # Maps id(worker) -> (worker, buttons) for the @Slot handlers below.
        # Using @Slot methods (bound to this QObject) instead of closures
        # is the only reliable way to use QueuedConnection in PySide6 —
        # plain Python callables have no thread affinity and their delivery
        # is silently dropped in some PySide6 versions.
        self._button_map: dict = {}

        # Main layout: splitter → controls (top) + log (bottom)
        # ── Layout: vertical splitter with scrollable controls above log ───
        outer = QVBoxLayout(self)
        outer.setContentsMargins(6, 6, 6, 6)
        outer.setSpacing(4)

        self._splitter = QSplitter(Qt.Orientation.Vertical)

        controls_widget = self.build_controls()
        _scroll = QScrollArea()
        _scroll.setWidget(controls_widget)
        _scroll.setWidgetResizable(True)
        _scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._splitter.addWidget(_scroll)

        cfg = self._store.cfg
        # Resolve log directory from cfg at construction time; may be updated
        # later via set_log_root() when the user changes bkps_dir in Config tab.
        project_logs_dir = None
        if getattr(cfg, "bkps_dir", ""):
            project_logs_dir = str(Path(cfg.bkps_dir) / "logs")
        self._log = LogPanel(log_title, log_root=project_logs_dir)
        self._splitter.addWidget(self._log)

        # Default split: 40% controls, 60% log
        self._splitter.setSizes([300, 450])
        self._splitter.setHandleWidth(4)

        outer.addWidget(self._splitter)

        # Note: stdout routing is done per-worker via thread registration
        # in run_worker(), not via a global signal connection

    # ── Subclass interface ─────────────────────────────────────────────────

    def build_controls(self) -> QWidget:
        """Override in subclasses to return the controls widget for this tab.

        The returned widget is wrapped in a QScrollArea and displayed above
        the LogPanel.  Typically a QGroupBox with buttons and input fields.

        Returns:
            A QWidget (default: empty placeholder used when not overridden).
        """
        placeholder = QWidget()
        return placeholder

    # ── Worker helpers ─────────────────────────────────────────────────────

    def run_worker(self, fn: Callable, *args, **kwargs) -> BkpsWorker:
        """Run *fn* in a BkpsWorker background thread.

        Handles the full worker lifecycle:
        - Disables buttons listed in _buttons while the task is running.
        - Registers the worker thread with StdoutCapture so its print() output
          is routed exclusively to this tab's LogPanel.
        - Connects task_done / error signals to bound @Slot methods so Qt
          guarantees main-thread delivery.

        Args:
            fn:       Callable to run on the background thread.
            *args:    Positional arguments forwarded to fn.
            **kwargs: Keyword arguments forwarded to fn.  Special key:
                      _buttons (list[QPushButton]) — disabled while running.

        Returns:
            The started BkpsWorker instance.
        """
        buttons: list[QPushButton] = kwargs.pop("_buttons", [])

        # Refresh file-log destination in case cfg.bkps_dir changed after startup.
        cfg = self._store.cfg
        project_logs_dir = None
        if getattr(cfg, "bkps_dir", ""):
            project_logs_dir = str(Path(cfg.bkps_dir) / "logs")
        try:
            self._log.set_log_root(project_logs_dir)
        except OSError as exc:
            # File logging is auxiliary and must not crash the GUI. Configuration
            # validation normally catches this; retain a runtime fallback for a
            # stale Config object loaded before validation was introduced.
            self._log.set_log_root(None)
            self._log.append_warning(
                f"Project log directory is unavailable; file logging disabled: {exc}"
            )

        # Closures for thread registration (routes stdout to this tab's log panel)
        # _setup/_teardown are closures capturing log_panel so concurrent workers
        # in different tabs each route to their own LogPanel.
        capture = self._capture
        log_panel = self._log

        def _setup():
            capture.register_thread(log_panel.append_batch)

        def _teardown():
            capture.unregister_thread()

        worker = BkpsWorker(fn, *args, _setup=_setup, _teardown=_teardown, **kwargs)
        self._workers.append(worker)
        self._button_map[id(worker)] = (worker, buttons)

        for btn in buttons:
            btn.setEnabled(False)

        # Connect to @Slot methods on this QObject (not closures).
        # QueuedConnection with @Slot on a QWidget is guaranteed to run on
        # the main thread and is reliably kept alive by PySide6.
        worker.task_done.connect(self._on_worker_task_done, Qt.ConnectionType.QueuedConnection)
        worker.error.connect(self._on_worker_error, Qt.ConnectionType.QueuedConnection)
        # Keep the QThread alive until Qt has finished tearing it down.
        # Previously ``_on_worker_task_done`` popped the worker from
        # ``self._workers``, which could drop the last Python reference to
        # the QThread while its C++ ``run()`` was still on the stack (we
        # ``emit`` inside ``run()``).  Python GC would then destroy the
        # QObject and the next step would touch stale Qt thread-local
        # state → SIGSEGV in libQt6Gui.so.6 at offset 0x10.  Deferring
        # cleanup to ``finished`` (fired AFTER ``run()`` returns) and
        # scheduling ``deleteLater`` keeps the destruction on Qt's own
        # timeline instead of Python GC.
        worker.finished.connect(lambda w=worker: self._final_cleanup_worker(w))
        worker.finished.connect(worker.deleteLater)
        worker.start()
        return worker

    def _final_cleanup_worker(self, worker: BkpsWorker) -> None:
        """Drop the strong reference to *worker* once Qt has fully finished it.

        Runs on the main thread via the ``QThread.finished`` signal — which
        Qt only emits after ``run()`` has returned and the thread has been
        joined internally. Removing the reference here is safe; removing it
        earlier (inside ``_on_worker_task_done``, which is invoked from a
        signal emitted *inside* ``run()``) is not.
        """
        if worker in self._workers:
            self._workers.remove(worker)

    @Slot(object)
    def _on_worker_task_done(self, result) -> None:
        """Receive task_done from any BkpsWorker owned by this tab.

        Uses sender() identity to locate the matching entry in _button_map so
        the correct set of buttons is re-enabled even if workers overlap.
        """
        sender = self.sender()
        worker, buttons = self._button_map.pop(id(sender), (sender, []))
        self._cleanup(worker, buttons)
        self.on_finished(result)

    @Slot(str)
    def _on_worker_error(self, tb: str) -> None:
        """Receive an error traceback from any BkpsWorker owned by this tab."""
        sender = self.sender()
        worker, buttons = self._button_map.pop(id(sender), (sender, []))
        self._cleanup(worker, buttons)
        self.on_error(tb)

    def _cleanup(self, worker: BkpsWorker, buttons: list) -> None:
        """Re-enable buttons after a worker completes.

        The worker itself is NOT removed from ``self._workers`` here — that
        happens later in ``_final_cleanup_worker`` when Qt fires
        ``QThread.finished``. Dropping the last Python reference to the
        QThread from inside a signal that was emitted inside ``run()``
        used to crash Qt (SIGSEGV in libQt6Gui.so.6 at offset 0x10).

        Args:
            worker:  The completed or failed BkpsWorker.
            buttons: Buttons that were disabled at worker start.
        """
        for btn in buttons:
            btn.setEnabled(True)

    # ── Default result handlers (override in subclasses as needed) ─────────

    @Slot(object)
    def on_finished(self, result) -> None:
        """Handle a successful worker result and print a banner to the log.

        Args:
            result: The value returned by the worker callable.  Pass False
                (not an exception) to indicate a non-zero exit code or
                other soft failure — a warning banner is shown instead.
        """
        if result is False:
            self._log.append_warning("\n═══════════════════════════════════════")
            self._log.append_warning("Operation did not complete successfully")
            self._log.append_warning("═══════════════════════════════════════\n")
            return
        self._log.append_success("\n═══════════════════════════════════════")
        self._log.append_success("Operation completed successfully")
        self._log.append_success("═══════════════════════════════════════\n")

    @Slot(str)
    def on_error(self, tb: str) -> None:
        """Handle a worker exception by printing a formatted traceback to the log.

        Args:
            tb: Formatted traceback string from traceback.format_exc().
        """
        self._log.append_error("\n═══════════════════════════════════════")
        self._log.append_error("ERROR:")
        self._log.append_error("═══════════════════════════════════════")
        # NOTE: DO NOT wrap the traceback in <pre>...</pre>. Qt6's rich-text
        # HTML importer occasionally crashes inside QTextDocumentLayout
        # (libQt6Gui.so.6 +0x10, null d-pointer) when a block-level <pre>
        # element is inserted at a mid-document cursor position. Using an
        # inline <span> with CSS ``white-space: pre`` gives us the same
        # monospace + preserved-whitespace rendering without triggering
        # the block-level PRE path. The <br>-per-newline preserves the
        # traceback's visual line breaks inside the inline flow.
        tb_html = _escape_tb(tb).replace("\n", "<br>")
        self._log.append_html(
            '<span style="color:#ff5555; white-space:pre; '
            f'font-family: Consolas, monospace;">{tb_html}</span>'
        )
        self._log.append_error("═══════════════════════════════════════\n")

    # ── Convenience accessors ──────────────────────────────────────────────

    @property
    def cfg(self):
        """Shortcut to self._store.cfg — the shared live Config object."""
        return self._store.cfg

    @property
    def log(self) -> LogPanel:
        """This tab's LogPanel widget."""
        return self._log
    # NOTE: stdout routing is per-worker (registered in run_worker()),
    # not a global connection, so concurrent workers on different tabs
    # never write to each other's LogPanels.

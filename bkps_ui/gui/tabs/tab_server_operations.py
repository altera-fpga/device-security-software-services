#!/usr/bin/env python3
"""Dedicated BKPS server controls and live server-output terminal."""

from __future__ import annotations

import os

from PySide6.QtCore import Qt, QUrl, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGroupBox,
    QLabel,
    QPushButton,
)

from tabs import BaseTab
from config_store import ConfigStore
from stdout_capture import StdoutCapture
from worker import BkpsWorker
from bkps_monitoring import show_logs
from bkps_printer import print_warning
from bkps_server import (
    check_bkps_health,
    diagnose_bkps_jar,
    is_bkps_server_running,
    start_bkps_server,
    stop_bkps_server,
)
from pipeline_widgets import (
    apply_server_env_vars,
    read_server_launch_settings,
)


def start_server_if_needed(
    cfg,
    extra_flags: str = "",
    env_text: str = "",
) -> bool:
    """Start BKPS unless its configured local port is already listening.

    ``extra_flags`` / ``env_text`` come from the Setup pipeline Settings box
    (Extra JVM Flags / Extra Env Vars) so Server Control Panel inherits them
    without duplicating those fields.
    """
    if is_bkps_server_running(cfg):
        print_warning(
            f"BKPS server is already listening on port {cfg.bkps_server_port}; "
            "leaving the running process unchanged."
        )
        return True
    apply_server_env_vars(env_text)
    return start_bkps_server(cfg, extra_flags)


class ServerOperationsTab(BaseTab):
    """Start/stop BKPS and follow ``logs/bkps.log`` in a dedicated terminal."""

    def __init__(self, store: ConfigStore, capture: StdoutCapture, parent=None):
        self._config_applied = False
        self._util_buttons: list[QPushButton] = []
        self._live_worker: BkpsWorker | None = None
        self._operation_workers: set[BkpsWorker] = set()
        super().__init__(
            store,
            capture,
            log_title="BKPS Server Live Output",
            parent=parent,
        )
        self._splitter.setSizes([185, 650])

    def _pipeline_launch_settings(self) -> tuple[str, str]:
        """Read Extra JVM Flags / Env Vars from the Setup pipeline Settings."""
        window = self.window()
        setup = getattr(window, "_tab_setup", None) if window is not None else None
        if setup is None:
            return "", ""
        return read_server_launch_settings(setup)
    def build_controls(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(8)

        heading = QLabel("BKPS Server Control Panel")
        font = heading.font()
        font.setBold(True)
        font.setPointSizeF(font.pointSizeF() + 3)
        heading.setFont(font)
        layout.addWidget(heading)

        explanation = QLabel(
            "Start or stop the local BKPS server and follow its live Logback "
            "output below. Starting the server attaches the terminal "
            "automatically; closing the studio leaves the server running. "
            "Start Server reuses Extra JVM Flags / Extra Env Vars from "
            "BKPS Setup → Database + BKP Service Initialization → Settings."
        )
        explanation.setWordWrap(True)
        explanation.setStyleSheet("color:#aaa;")
        layout.addWidget(explanation)

        controls = QGroupBox("Server Controls")
        controls_layout = QVBoxLayout(controls)
        controls_layout.setContentsMargins(8, 8, 8, 8)
        controls_layout.setSpacing(8)
        primary_row = QHBoxLayout()
        primary_row.setSpacing(8)
        secondary_row = QHBoxLayout()
        secondary_row.setSpacing(8)

        self._status = QLabel("Server: unknown")
        self._status.setMinimumWidth(140)
        self._set_server_status(None)
        primary_row.addWidget(self._status)

        self._btn_start = QPushButton("Start Server")
        self._btn_start.setToolTip(
            "Start the BKPS server if it is stopped, then attach live output. "
            "Uses Extra JVM Flags and Extra Env Vars from the Setup pipeline "
            "Settings (same fields as Start Server there)."
        )
        self._btn_start.setStyleSheet(
            "QPushButton { background:#218c53; color:white; font-weight:bold; "
            "padding:7px 14px; border-radius:3px; }"
            "QPushButton:disabled { background:#333; color:#777; }"
        )

        self._btn_stop = QPushButton("Stop Server")
        self._btn_stop.setToolTip("Stop the local process listening on the BKPS port.")
        self._btn_stop.setStyleSheet(
            "QPushButton { background:#b83b32; color:white; font-weight:bold; "
            "padding:7px 14px; border-radius:3px; }"
            "QPushButton:disabled { background:#333; color:#777; }"
        )

        self._btn_health = QPushButton("Detailed Health")
        self._btn_health.setToolTip(
            "Run runner.py health --detailed and show the complete response "
            "in the terminal below."
        )
        self._btn_health.setStyleSheet(
            "QPushButton { background:#55acee; color:#10202c; font-weight:bold; "
            "padding:7px 14px; border-radius:3px; }"
            "QPushButton:hover { background:#70baf0; }"
            "QPushButton:disabled { background:#333; color:#777; }"
        )

        self._btn_live = QPushButton("Attach Live Output")
        self._btn_live.setToolTip(
            "Follow <BKPS project>/logs/bkps.log in the terminal below."
        )
        self._btn_refresh = QPushButton("Refresh Status")
        self._btn_refresh.setToolTip("Probe the configured local BKPS port.")
        self._btn_open_log = QPushButton("Open Log File")
        self._btn_open_log.setToolTip("Open logs/bkps.log in the default editor.")
        self._btn_diagnose_jar = QPushButton("Diagnose JAR")
        self._btn_diagnose_jar.setToolTip("Verify the installed BKPS JAR.")
        self._btn_clear_logs = QPushButton("Clear Logs")
        self._btn_clear_logs.setToolTip(
            "Clear this panel's live output without changing on-disk log files."
        )

        for button in (
            self._btn_start,
            self._btn_stop,
            self._btn_health,
            self._btn_diagnose_jar,
            self._btn_live,
            self._btn_refresh,
            self._btn_open_log,
            self._btn_clear_logs,
        ):
            button.setEnabled(False)
            self._util_buttons.append(button)

        for button in (
            self._btn_start,
            self._btn_stop,
            self._btn_health,
            self._btn_diagnose_jar,
        ):
            primary_row.addWidget(button)
        primary_row.addStretch()
        for button in (
            self._btn_live,
            self._btn_refresh,
            self._btn_open_log,
            self._btn_clear_logs,
        ):
            secondary_row.addWidget(button)
        secondary_row.addStretch()
        controls_layout.addLayout(primary_row)
        controls_layout.addLayout(secondary_row)
        layout.addWidget(controls)

        self._terminal_path = QLabel("Terminal source: apply Config to resolve the log path")
        self._terminal_path.setStyleSheet("color:#777; font-family:Consolas,monospace;")
        self._terminal_path.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        layout.addWidget(self._terminal_path)
        layout.addStretch()

        self._btn_start.clicked.connect(self._start_server)
        self._btn_stop.clicked.connect(self._stop_server)
        self._btn_health.clicked.connect(self._check_health)
        self._btn_diagnose_jar.clicked.connect(self._diagnose_jar)
        self._btn_live.clicked.connect(self._toggle_live_output)
        self._btn_refresh.clicked.connect(self.refresh_status)
        self._btn_open_log.clicked.connect(self._open_log_file)
        self._btn_clear_logs.clicked.connect(self._clear_logs)
        return container

    def on_config_applied(self) -> None:
        """Enable controls after Config has been validated and applied."""
        self._config_applied = True
        for button in self._util_buttons:
            button.setEnabled(True)
        self._terminal_path.setText(f"Terminal source: {self._server_log_path()}")
        self.refresh_status()

    def on_config_cleared(self) -> None:
        """Detach from the old project before AppWindow loads another one."""
        self.shutdown()
        self._config_applied = False
        for button in self._util_buttons:
            button.setEnabled(False)
        self._terminal_path.setText(
            "Terminal source: apply Config to resolve the log path"
        )
        self._set_server_status(None)

    def set_server_running(self, running: bool) -> None:
        """Accept the AppWindow health check result for the status badge."""
        self._set_server_status(running)

    def refresh_status(self) -> None:
        """Probe localhost with the existing short TCP check."""
        if not self._config_applied:
            self._set_server_status(None)
            return
        self._set_server_status(is_bkps_server_running(self.cfg))

    def _set_server_status(self, running: bool | None) -> None:
        if running is True:
            text, colour = "Server: running", "#50fa7b"
        elif running is False:
            text, colour = "Server: stopped", "#ff7777"
        else:
            text, colour = "Server: unknown", "#aaa"
        self._status.setText(text)
        self._status.setStyleSheet(
            f"color:{colour}; font-weight:bold; padding:4px 8px;"
        )

    def _start_server(self) -> None:
        self._set_operation_buttons_enabled(False)
        extra_flags, env_text = self._pipeline_launch_settings()
        worker = self.run_worker(
            start_server_if_needed, self.cfg, extra_flags, env_text
        )
        self._track_operation_worker(worker)
        worker.task_done.connect(self._on_start_done, Qt.ConnectionType.QueuedConnection)
        worker.error.connect(self._on_start_error, Qt.ConnectionType.QueuedConnection)

    @Slot(object)
    def _on_start_done(self, result) -> None:
        self._set_operation_buttons_enabled(True)
        running = bool(result) or is_bkps_server_running(self.cfg)
        self._set_server_status(running)
        if running:
            self._start_live_output()

    @Slot(str)
    def _on_start_error(self, _traceback: str) -> None:
        self._set_operation_buttons_enabled(True)
        self.refresh_status()

    def _stop_server(self) -> None:
        self._set_operation_buttons_enabled(False)
        worker = self.run_worker(stop_bkps_server, self.cfg)
        self._track_operation_worker(worker)
        worker.task_done.connect(self._on_stop_done, Qt.ConnectionType.QueuedConnection)
        worker.error.connect(self._on_stop_error, Qt.ConnectionType.QueuedConnection)

    def _check_health(self) -> None:
        """Request the server's detailed health report in this tab's terminal."""
        self.run_worker(
            check_bkps_health,
            self.cfg,
            _buttons=[self._btn_health],
        )

    def _diagnose_jar(self) -> None:
        """Verify the installed BKPS JAR and show results in this terminal."""
        self.run_worker(
            diagnose_bkps_jar,
            self.cfg,
            _buttons=[self._btn_diagnose_jar],
        )

    def _clear_logs(self) -> None:
        """Clear this terminal without deleting the server's log file."""
        self.log.clear()

    @Slot(object)
    def _on_stop_done(self, _result) -> None:
        self._set_operation_buttons_enabled(True)
        self._set_server_status(False)
        self._stop_live_output()

    @Slot(str)
    def _on_stop_error(self, _traceback: str) -> None:
        self._set_operation_buttons_enabled(True)
        self.refresh_status()

    def _track_operation_worker(self, worker: BkpsWorker) -> None:
        self._operation_workers.add(worker)
        worker.finished.connect(
            lambda w=worker: self._operation_workers.discard(w),
            Qt.ConnectionType.QueuedConnection,
        )

    def _set_operation_buttons_enabled(self, enabled: bool) -> None:
        enabled = enabled and self._config_applied
        self._btn_start.setEnabled(enabled)
        self._btn_stop.setEnabled(enabled)
        self._btn_health.setEnabled(enabled)
        self._btn_diagnose_jar.setEnabled(enabled)
        self._btn_refresh.setEnabled(enabled)

    def _toggle_live_output(self) -> None:
        if self._live_worker is not None and self._live_worker.isRunning():
            self._stop_live_output()
        else:
            self._start_live_output()

    def _start_live_output(self) -> None:
        if self._live_worker is not None and self._live_worker.isRunning():
            return

        log_path = self._server_log_path()
        if not os.path.isfile(log_path):
            self.log.append_warning(
                f"BKPS server log does not exist yet: {log_path}\n"
                "Start the server first, or wait for it to create the log file."
            )
            return

        capture = self._capture
        log_panel = self.log

        def _setup() -> None:
            capture.register_thread(log_panel.append_batch)

        def _teardown() -> None:
            capture.unregister_thread()

        worker = BkpsWorker(
            show_logs,
            self.cfg,
            stop_control_label="Detach Live Output",
            _setup=_setup,
            _teardown=_teardown,
        )
        self._live_worker = worker
        self._btn_live.setText("Detach Live Output")
        self._btn_live.setEnabled(True)
        worker.error.connect(self._on_live_error, Qt.ConnectionType.QueuedConnection)
        worker.finished.connect(self._on_live_finished, Qt.ConnectionType.QueuedConnection)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _stop_live_output(self) -> None:
        worker = self._live_worker
        if worker is None or not worker.isRunning():
            self._reset_live_button()
            return
        self._btn_live.setText("Detaching...")
        self._btn_live.setEnabled(False)
        worker.request_cancel()

    @Slot(str)
    def _on_live_error(self, traceback_text: str) -> None:
        self.on_error(traceback_text)

    @Slot()
    def _on_live_finished(self) -> None:
        self._live_worker = None
        self._reset_live_button()

    def _reset_live_button(self) -> None:
        self._btn_live.setText("Attach Live Output")
        self._btn_live.setEnabled(self._config_applied)

    def _open_log_file(self) -> None:
        log_path = self._server_log_path()
        if not os.path.isfile(log_path):
            self.log.append_warning(f"BKPS server log not found: {log_path}")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(log_path))

    def _server_log_path(self) -> str:
        return os.path.join(self.cfg.bkps_dir, "logs", "bkps.log")

    def shutdown(self) -> None:
        """Detach the terminal without stopping the independently running server."""
        worker = self._live_worker
        if worker is not None and worker.isRunning():
            worker.request_cancel()
            worker.wait(3000)

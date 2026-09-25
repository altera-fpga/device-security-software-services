#!/usr/bin/env python3
"""
tab_debug.py - Debug & Maintenance tab.

Home for:
    * Setup Validation (unchanged)
    * Maintenance     (unchanged)
    * Device Status  (moved from the Programming tab: JTAG check, read
      fuse info, view fuse report, PROV / CONFIG status)
"""

import os
from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QPushButton, QLabel,
)

from tabs import BaseTab
from config_store import ConfigStore
from stdout_capture import StdoutCapture
from utils.bkps_utils import *
from bkps_status import validate_setup, backup_setup, cleanup
from keystore_viewer import KeystoreViewerDialog
from bkps_monitoring import show_logs, export_logs
from bkps_device import check_jtag_connection, check_jtag_status, read_fuse_info



class DebugTab(BaseTab):
    """Debug & Maintenance tab.

    Attributes:
        _logs_worker: Currently running live-log worker, or ``None`` when
            idle.  The Show Live Logs button toggles this on/off.
    """

    def __init__(self, store: ConfigStore, capture: StdoutCapture, parent=None):
        self._logs_worker = None
        super().__init__(store, capture, log_title="Debug Log", parent=parent)

    def build_controls(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(6)

        # ── Setup validation ─────────────────────────────────────────
        status_box = QGroupBox("Setup Validation")
        status_layout = QVBoxLayout(status_box)
        self._btn_validate  = _btn("Validate Setup", primary=True, tip=(
            "Run a comprehensive validation of the BKPS installation."
        ))
        self._btn_keystores = _btn("Keystore Viewer",
            tip="Open the keystore viewer to inspect BKPS keystores.")
        status_layout.addLayout(_hrow(self._btn_validate, self._btn_keystores))
        self._btn_validate.clicked.connect(self._validate)
        self._btn_keystores.clicked.connect(self._show_keystores)
        layout.addWidget(status_box)

        # ── Device status (moved from Programming tab) ───────────────
        device_box = QGroupBox("Device Status  (JTAG diagnostics)")
        dl = QVBoxLayout(device_box)
        self._btn_check_jtag = _btn("Check JTAG Connection",
            tip="Verify the JTAG connection to the device (bkps_device.check_jtag_connection).")
        self._btn_read_fuse = _btn("Read Fuse Info",
            tip="Read eFuse state from the device (bkps_device.read_fuse_info); "
                "writes fuse_report.fuse in cm_provisioning_dir.")
        self._btn_view_fuse = _btn("View fuse_report",
            tip="Open fuse_report.fuse in the default text editor.")
        self._btn_prov_status = _btn("PROV Status",
            tip="Query the device provisioning status register (bkps_device.check_jtag_status 'PROV').")
        self._btn_cfg_status = _btn("CONFIG Status",
            tip="Query the device configuration status register (bkps_device.check_jtag_status 'CONFIG').")
        dl.addLayout(_hrow(self._btn_check_jtag, self._btn_read_fuse, self._btn_view_fuse))
        dl.addLayout(_hrow(self._btn_prov_status, self._btn_cfg_status))
        self._btn_check_jtag.clicked.connect(self._check_jtag)
        self._btn_read_fuse.clicked.connect(self._read_fuse)
        self._btn_view_fuse.clicked.connect(self._view_fuse)
        self._btn_prov_status.clicked.connect(self._prov_status)
        self._btn_cfg_status.clicked.connect(self._cfg_status)
        layout.addWidget(device_box)

        # ── Logs & maintenance ───────────────────────────────────────
        maint_box = QGroupBox("Maintenance")
        maint_layout = QVBoxLayout(maint_box)
        self._btn_show_logs   = _btn("Show Live Logs",
            tip="Stream the BKPS server log in real-time.  Click again to stop.")
        self._btn_export_logs = _btn("Export Logs",
            tip="Export the current BKPS log files to a timestamped archive.")
        self._btn_backup      = _btn("Backup Setup",
            tip="Create a timestamped backup of the BKPS configuration.")
        self._btn_cleanup     = _btn("Cleanup", danger=True,
            tip="Remove temporary files and clean up the BKPS working directory.")
        maint_layout.addLayout(_hrow(self._btn_show_logs, self._btn_export_logs))
        maint_layout.addLayout(_hrow(self._btn_backup, self._btn_cleanup))
        self._btn_show_logs.clicked.connect(self._show_logs)
        self._btn_export_logs.clicked.connect(self._export_logs)
        self._btn_backup.clicked.connect(self._backup)
        self._btn_cleanup.clicked.connect(self._run_cleanup)
        layout.addWidget(maint_box)

        layout.addStretch()
        return container

    # ── Setup validation ────────────────────────────────────────────
    def _validate(self):
        self.run_worker(validate_setup, self.cfg, _buttons=[self._btn_validate])

    def _show_keystores(self):
        dialog = KeystoreViewerDialog(self._store, self)
        dialog.exec()

    # ── Device status ───────────────────────────────────────────────
    def _check_jtag(self):
        self.run_worker(check_jtag_connection, self.cfg, _buttons=[self._btn_check_jtag])

    def _read_fuse(self):
        self.run_worker(read_fuse_info, self.cfg, _buttons=[self._btn_read_fuse])

    def _view_fuse(self):
        fuse_path = os.path.join(self.cfg.cm_provisioning_dir, "fuse_report.fuse")
        if not os.path.isfile(fuse_path):
            self.log.append_warning(
                f"fuse_report.fuse not found: {fuse_path}\nRun Read Fuse Info first."
            )
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(fuse_path))

    def _prov_status(self):
        self.run_worker(check_jtag_status, self.cfg, "PROV", _buttons=[self._btn_prov_status])

    def _cfg_status(self):
        self.run_worker(check_jtag_status, self.cfg, "CONFIG", _buttons=[self._btn_cfg_status])

    # ── Maintenance / live logs ─────────────────────────────────────
    def _show_logs(self):
        if self._logs_worker is not None and self._logs_worker.isRunning():
            self._logs_worker.request_cancel()
            self._btn_show_logs.setText("Stopping…")
            self._btn_show_logs.setEnabled(False)
        else:
            self._logs_worker = self.run_worker(show_logs, self.cfg)
            self._btn_show_logs.setText("■ Stop Live Logs")
            self._btn_show_logs.setEnabled(True)

    def on_finished(self, result) -> None:
        self._reset_logs_btn_if_done()
        super().on_finished(result)

    def on_error(self, tb: str) -> None:
        self._reset_logs_btn_if_done()
        super().on_error(tb)

    def _reset_logs_btn_if_done(self) -> None:
        if self._logs_worker is not None and not self._logs_worker.isRunning():
            self._btn_show_logs.setText("Show Live Logs")
            self._btn_show_logs.setEnabled(True)
            self._logs_worker = None

    def _export_logs(self):
        self.run_worker(export_logs, self.cfg, _buttons=[self._btn_export_logs])

    def _backup(self):
        self.run_worker(backup_setup, self.cfg, _buttons=[self._btn_backup])

    def _run_cleanup(self):
        self.run_worker(cleanup, self.cfg, _buttons=[self._btn_cleanup])

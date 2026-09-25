#!/usr/bin/env python3
"""tab_configuration_utilities.py - Manual configuration-file operations.

Reload From Template / Update Configuration / View bkp_options.txt.
Delegates the AES-config table state to the BKP tab via a
``config_bridge`` object that AppWindow injects at startup.
"""
from PySide6.QtWidgets import QWidget

from tabs import BaseTab
from config_store import ConfigStore
from stdout_capture import StdoutCapture
from utility_widgets import build_configuration_utilities


class ConfigurationUtilitiesTab(BaseTab):
    """Non-pipeline configuration manual operations."""

    def __init__(self, store: ConfigStore, capture: StdoutCapture, parent=None):
        self._util_buttons: list = []
        self._config_applied = False
        self.config_bridge = None  # injected by AppWindow after BkpTab exists
        super().__init__(store, capture, log_title="Configuration Utilities Log", parent=parent)

    def build_controls(self) -> QWidget:
        return build_configuration_utilities(self)

    def on_config_applied(self) -> None:
        self._config_applied = True
        for b in self._util_buttons:
            b.setEnabled(True)

    def showEvent(self, event) -> None:
        # Refresh our own copy of the AES-configuration table from the
        # shared working file so edits made on the BKP Config tab are
        # picked up here (and vice versa on the next visit).  Both tabs
        # read + write the same file, so the two tables converge as
        # long as either operator saves before switching.
        super().showEvent(event)
        reload = getattr(self, "_config_reload_family", None)
        if reload is not None:
            try:
                reload()
            except Exception:
                # Silent: family may not be resolvable yet (fresh app,
                # Config never applied).  The next showEvent will retry.
                pass

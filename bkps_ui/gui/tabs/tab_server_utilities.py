#!/usr/bin/env python3
"""tab_server_utilities.py - Manual server / admin operations."""
from PySide6.QtWidgets import QWidget

from tabs import BaseTab
from config_store import ConfigStore
from stdout_capture import StdoutCapture
from utility_widgets import build_server_utilities


class ServerUtilitiesTab(BaseTab):
    """Non-pipeline server + BKPS-administration operations.

    Every button here is disabled until Config → Apply Changes is
    clicked at least once.  After that the operator can trigger any
    action independently — none of these participate in the guided
    pipeline chain or in the tab-level gating.
    """

    def __init__(self, store: ConfigStore, capture: StdoutCapture, parent=None):
        self._util_buttons: list = []
        self._config_applied = False
        super().__init__(store, capture, log_title="Server Utilities Log", parent=parent)

    def build_controls(self) -> QWidget:
        return build_server_utilities(self)

    # Called by AppWindow when Config → Apply Changes fires.
    def on_config_applied(self) -> None:
        self._config_applied = True
        for b in self._util_buttons:
            b.setEnabled(True)

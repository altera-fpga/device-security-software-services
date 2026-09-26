#!/usr/bin/env python3
"""tab_aes_utilities.py - Manual SoftHSM / AES-key operations."""
from PySide6.QtWidgets import QWidget

from tabs import BaseTab
from config_store import ConfigStore
from stdout_capture import StdoutCapture
from utility_widgets import build_aes_utilities, refresh_aes_utility_visibility


class AesUtilitiesTab(BaseTab):
    """Non-pipeline AES-ccert manual operations (Agilex 5 only)."""

    def __init__(self, store: ConfigStore, capture: StdoutCapture, parent=None):
        self._util_buttons: list = []
        self._config_applied = False
        super().__init__(store, capture, log_title="AES Utilities Log", parent=parent)

    def build_controls(self) -> QWidget:
        return build_aes_utilities(self)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        refresh_aes_utility_visibility(self)

    def on_config_applied(self) -> None:
        self._config_applied = True
        for b in self._util_buttons:
            b.setEnabled(True)

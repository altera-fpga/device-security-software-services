#!/usr/bin/env python3
"""tab_bkp_config.py - Guided setup phase between Setup and BKP Programming.

Hosts the AES compact-certificate pipeline followed by the AES
configuration + ``bkp_options.txt`` pipeline.  Once every step of
both flows is green, the operator moves on to the (final)
:class:`BkpTab`, which now hosts only the JTAG-programming pipeline.

Also owns the ``config_bridge`` object consumed by the Configuration
Utilities tab so utilities can operate on the shared JSON table.
"""
from PySide6.QtCore import Qt, Signal, Slot
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel

from tabs import BaseTab
from config_store import ConfigStore
from stdout_capture import StdoutCapture
from pipeline_gating import PipelineHost
from pipeline_widgets import (
    build_aes_pipeline_box, build_configuration_pipeline_box,
    refresh_aes_pipeline_visibility, make_flow_link,
)


class _ConfigBridge:
    """Bridge exposing the shared Configuration table to the utilities tab."""

    def __init__(self, host):
        self._host = host

    def get_working_file(self) -> str:
        return self._host._config_working_file_path()

    def get_template(self) -> str:
        return self._host._config_template_path()

    def save_table_to_file(self, path: str) -> bool:
        return self._host._config_save_table_to_file(path)

    def load_from_file(self, path: str) -> None:
        self._host._config_load_table_from_file(path)

    def reload_family(self) -> None:
        self._host._config_reload_family()


class BkpConfigTab(PipelineHost, BaseTab):
    """Guided-setup tab hosting the AES ccert + AES configuration flows."""

    # Emitted (from the AES worker thread) after Create QEK + ccert
    # completes.  The queued connection below marshals the refresh to
    # the Qt main thread so we can safely touch the Configuration table.
    aes_hex_updated = Signal()

    def __init__(self, store: ConfigStore, capture: StdoutCapture, parent=None):
        self._flow_order: list[str] = ["aes", "configuration"]
        self._pipe_buttons: dict = {}
        self._step_dispatch: dict = {}
        self._config_applied: bool = False
        self._optional_steps: set[tuple[str, str]] = set()
        # Every button here stays disabled until the previous phase
        # (SetupTab: installation + server) is fully green.
        self._prereq_groups: list[str] = ["installation", "server"]
        super().__init__(store, capture,
                         log_title="BKP Config (AES + Configuration) Log",
                         parent=parent)
        # Lazily build the utilities bridge — the ``_config_*`` helpers
        # only exist after ``build_controls`` has run.
        self.config_bridge = _ConfigBridge(self)
        # Queued so the AES worker thread can emit safely; the slot
        # then runs on the Qt main thread and can touch widgets.
        self.aes_hex_updated.connect(
            self._on_aes_hex_updated,
            Qt.ConnectionType.QueuedConnection,
        )

    def build_controls(self) -> QWidget:
        container = QWidget()
        v = QVBoxLayout(container)
        v.setContentsMargins(4, 4, 4, 4); v.setSpacing(6)

        header = QLabel(
            "BKP Config — AES ccert + AES configuration.  "
            "Create signed AES ccert -> Create AES configuration -> Generate bkp_options.txt"
        )
        header.setStyleSheet("color:#aaa; font-size:9pt;")
        header.setWordWrap(True)
        v.addWidget(header)

        v.addWidget(build_aes_pipeline_box(self))
        v.addWidget(make_flow_link("then build the AES configuration"))
        v.addWidget(build_configuration_pipeline_box(self))
        v.addStretch()
        return container

    def showEvent(self, event) -> None:
        super().showEvent(event)
        refresh_aes_pipeline_visibility(self)
        # Reload the JSON table for the current family.  Config ID is
        # intentionally NOT auto-filled — leave it blank so the operator
        # explicitly enters the value (or lets Step 2 fall back to
        # config_id.txt on disk).
        try:
            self._config_reload_family()
        except Exception:
            pass
        # Auto-succeed SIGMA no-op AES steps so the gating mixin unlocks
        # the right buttons.
        pl = getattr(self.window(), "pipeline", None)
        if pl is not None:
            profile = getattr(self.cfg, "profile_name", "") or ""
            from pipeline import StepStatus
            if profile in ("agilex", "stratix10"):
                for sid in ("init_token", "create_key"):
                    if pl.status("aes", sid) != StepStatus.SUCCESS:
                        pl.set_status("aes", sid, StepStatus.SUCCESS)
        self.refresh_pipeline_gating()

    @Slot()
    def _on_aes_hex_updated(self) -> None:
        """Refresh the Configuration table + log after AES ccert/QEK create.

        Fires (via queued connection) on the Qt main thread once the AES
        pipeline's Create QEK + ccert step succeeds, so it's safe to
        touch widgets.  Re-primes the ``confidentialData.aes[Key].value``
        and ``confidentialData.qek.value`` cells from the on-disk hex
        files, then prints an operator-facing notice.  The fields remain
        editable — the operator can still overwrite them manually before
        Create Configuration.
        """
        try:
            if hasattr(self, "_config_load_table_from_file") and \
                    hasattr(self, "_config_working_file_path"):
                self._config_load_table_from_file(
                    self._config_working_file_path()
                )
        except Exception as exc:
            self.log.append_error(f"Config table refresh warning: {exc!r}")
            return
        self.log.append_info(
            "Configuration table updated: confidentialData.aes(Key).value, "
            "confidentialData.qek.value, and corimUrl were updated. All three "
            "fields remain editable — type over them if you need a manual "
            "override before Create Configuration."
        )

#!/usr/bin/env python3
"""tab_bkp.py - BKP Onboarding / Provisioning tab.

Now hosts ONLY the JTAG-programming pipeline.  The AES compact-cert
and AES-configuration pipelines have been moved to :mod:`tab_bkp_config`
so the operator can pre-fill every setting on that earlier tab before
returning here to run the final device-programming flow.
"""
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel

from tabs import BaseTab
from config_store import ConfigStore
from stdout_capture import StdoutCapture
from pipeline_gating import PipelineHost
from pipeline_widgets import (
    build_programming_pipeline_box,
    refresh_programming_pipeline_visibility,
)


class BkpTab(PipelineHost, BaseTab):
    """Final guided-setup tab: the JTAG programming pipeline only."""

    def __init__(self, store: ConfigStore, capture: StdoutCapture, parent=None):
        self._flow_order: list[str] = ["programming"]
        self._pipe_buttons: dict = {}
        self._step_dispatch: dict = {}
        self._config_applied: bool = False
        # Steps we've auto-marked SUCCESS because they are hidden by
        # the current family / ccert combo.  Tracked separately from
        # PipelineState so we know which SUCCESS entries are safe to
        # revert to PENDING when the operator flips ccert back to a
        # PUF-backed type (see showEvent).  Real successes produced by
        # actually clicking the button are NOT recorded here.
        self._auto_success_steps: set[str] = set()
        # BKP PUF Activate is optional: failing it still unlocks the
        # post-PUF repeats (Program Helper Image / Root Key Hash) and
        # the chain-runner keeps going instead of aborting.
        self._optional_steps: set[tuple[str, str]] = {
            ("programming", "puf_activate"),
        }
        # After PUF activation the device MUST be power-cycled before
        # the post-PUF helper image / RKH / Set Authority / Provision
        # steps can talk to it.  (The pre-JIC helper + RKH already ran
        # earlier.)  The PipelineHost mixin stops the chain on
        # ``puf_activate`` success and shows this message so the
        # operator power-cycles and then clicks the next step.
        self._halt_after_steps: dict[tuple[str, str], str] = {
            ("programming", "puf_activate"):
                "PUF activation complete.  Please POWER CYCLE the device "
                "now, then click '7. Program Helper Image (post-PUF)' to "
                "continue the provisioning flow.",
        }
        # Every button here stays disabled until the previous phase
        # (BkpConfigTab: aes + configuration) is fully green.
        self._prereq_groups: list[str] = [
            "installation", "server", "aes", "configuration",
        ]
        super().__init__(store, capture,
                         log_title="BKP Programming Log", parent=parent)

    def build_controls(self) -> QWidget:
        container = QWidget()
        v = QVBoxLayout(container)
        v.setContentsMargins(4, 4, 4, 4); v.setSpacing(6)

        header = QLabel("BKP Onboarding/Provisioning")
        header.setStyleSheet("color:#aaa; font-size:9pt;")
        header.setWordWrap(True)
        v.addWidget(header)

        v.addWidget(build_programming_pipeline_box(self))
        v.addStretch()
        return container

    def on_config_applied(self) -> None:
        """Unlock gating and re-sync programming defaults from Config."""
        super().on_config_applied()
        refresh_programming_pipeline_visibility(self)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        refresh_programming_pipeline_visibility(self)
        # Reconcile the shared PipelineState with the CURRENT visibility
        # rules so switching AES ccert type mid-session correctly
        # reflects on the steps:
        #
        #   * A step that is HIDDEN by the current family/ccert combo is
        #     auto-marked SUCCESS so the gating mixin doesn't treat it
        #     as a blocker (its button is invisible, so the operator
        #     could never satisfy it manually).  We remember every such
        #     step in ``self._auto_success_steps``.
        #
        #   * A step that becomes VISIBLE again (e.g. operator switched
        #     from EFUSE_WRAPPED to UDS_INTEL_PUF_WRAPPED) AND is in our
        #     auto-success set gets reverted to PENDING so it shows
        #     grey/default and blocks the chain until it's actually run.
        #     Real successes (a previous manual click that produced a
        #     green button) are NOT tracked in the auto-success set, so
        #     they survive a ccert switch.
        pl = getattr(self.window(), "pipeline", None)
        if pl is not None:
            from pipeline import StepStatus
            from bkps_config import PUF_TYPES
            from pipeline_widgets import _ccert_puf_hint
            profile = getattr(self.cfg, "profile_name", "") or ""
            puf = PUF_TYPES.get(profile, {})
            is_internal = _ccert_puf_hint(self.cfg) == "INTERNAL"

            def _auto_success(sid: str) -> None:
                self._auto_success_steps.add(sid)
                if pl.status("programming", sid) != StepStatus.SUCCESS:
                    pl.set_status("programming", sid, StepStatus.SUCCESS)

            def _revert_if_auto(sid: str) -> None:
                # Only reset steps WE previously auto-succeeded — a step
                # that shows SUCCESS because the operator actually ran
                # it (not in our set) must not be silently wiped.
                if sid in self._auto_success_steps:
                    self._auto_success_steps.discard(sid)
                    if pl.status("programming", sid) == StepStatus.SUCCESS:
                        pl.set_status("programming", sid, StepStatus.PENDING)

            puf_activate_needed = (
                "puf_activate" in puf and not is_internal
            )
            if puf_activate_needed:
                _revert_if_auto("puf_activate")
                _revert_if_auto("program_helper_image")
                _revert_if_auto("provision_rkh")
            else:
                _auto_success("puf_activate")
                _auto_success("program_helper_image")
                _auto_success("provision_rkh")


                

            if "set_authority" in puf:
                _revert_if_auto("set_authority")
            else:
                _auto_success("set_authority")
        self.refresh_pipeline_gating()

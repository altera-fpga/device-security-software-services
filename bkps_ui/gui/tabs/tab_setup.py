#!/usr/bin/env python3
"""tab_setup.py - Combined Installation + Server pipelines."""
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel

from tabs import BaseTab
from config_store import ConfigStore
from stdout_capture import StdoutCapture
from pipeline_gating import PipelineHost
from pipeline_widgets import (
    build_installation_pipeline_box, build_server_pipeline_box,
    make_flow_link,
)
from bkps_config import DEVICE_FAMILIES


class SetupTab(PipelineHost, BaseTab):
    """BKPS Setup tab hosting the installation and bootstrap pipelines.

    The first button (Installation) is the only clickable pipeline
    control at launch.  Each successful step enables the next; when the
    whole Installation flow succeeds, the first button of the Server
    flow becomes enabled and the same chain-runner picks it up.

    Environment gates that make the very first step impossible to run
    (for example, SIGMA without a bundle ZIP or a pre-built JAR) force
    the Installation button to stay
    disabled — which cascades: because the mixin only enables the next
    step after the previous one succeeds, the whole Server flow stays
    locked too and a red banner explains what to fix.
    """

    def __init__(self, store: ConfigStore, capture: StdoutCapture, parent=None):
        # Pipeline host state must exist before build_controls() runs.
        self._flow_order: list[str] = ["installation", "server"]
        self._pipe_buttons: dict = {}
        self._step_dispatch: dict = {}
        self._config_applied: bool = False
        # Set by ``_evaluate_env`` — when non-empty, ``refresh_pipeline_gating``
        # force-disables ``installation.dependency_setup`` which in turn keeps
        # every downstream pipeline button locked.
        self._env_block_reasons: list[str] = []
        super().__init__(store, capture, log_title="Setup", parent=parent)

    def select_pipeline_log(self, group: str) -> None:
        """Route Installation and database bootstrap output to separate files."""
        title = "Database Bootstrap" if group == "server" else "Setup"
        self._log.set_title(title)

    def build_controls(self) -> QWidget:
        container = QWidget()
        v = QVBoxLayout(container)
        v.setContentsMargins(4, 4, 4, 4); v.setSpacing(6)

        header = QLabel(
            "BKPS Setup — install BKPS, initialize its database, and prepare the BKP Service.  "
            "Click the first button of each pipeline to automatically run everything "
            "below it.  Green = success, orange = running, red = failure (retry from that step)."
        )
        header.setStyleSheet("color:#aaa; font-size:9pt;")
        header.setWordWrap(True)
        v.addWidget(header)

        # Environment warning banner for missing device-family inputs.
        self._env_banner = QLabel("")
        self._env_banner.setStyleSheet(
            "background:#4a1e14; color:#ffb08a; border:1px solid #822015; "
            "border-radius:3px; padding:8px; font-size:9pt;"
        )
        self._env_banner.setWordWrap(True)
        self._env_banner.hide()
        v.addWidget(self._env_banner)

        v.addWidget(build_installation_pipeline_box(self))
        v.addWidget(make_flow_link(
            "Continue to Database + BKP Service Initialization"
        ))
        v.addWidget(build_server_pipeline_box(self))
        v.addStretch()
        return container

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._evaluate_env()
        self.refresh_pipeline_gating()

    # ------------------------------------------------------------------
    # Environment gate (device-family installation inputs)
    # ------------------------------------------------------------------

    def _evaluate_env(self) -> None:
        """Recompute ``self._env_block_reasons`` from the current Config."""
        cfg = self.cfg
        reasons: list[str] = []

        # SIGMA devices need a bundle ZIP (or a pre-built JAR path)
        #    since they can't build from source.
        entry = DEVICE_FAMILIES.get(getattr(cfg, "profile_name", "") or "")
        protocol = entry[1] if entry else ""
        is_sigma = (protocol == "SIGMA")
        has_zip = bool(getattr(cfg, "bundle_zip", "") or "")
        has_prebuilt_jar = bool(getattr(cfg, "bkps_jar_path", "") or "")
        from_src = cfg.build_from_source
        blocked = (not from_src) and (not has_zip) and (not has_prebuilt_jar)
        if is_sigma:
            blocked = (not has_zip) and (not has_prebuilt_jar)
        if blocked:
            device_label = (
                getattr(cfg, "device_family", "")
                or getattr(cfg, "profile_name", "")
                or "SIGMA device"
            )
            reasons.append(
                f"Installation disabled for {device_label}: no BKPS bundle "
                "ZIP configured.\nOpen the Config tab, set 'bundle ZIP' "
                "(and password if any), then click Apply Changes."
            )

        self._env_block_reasons = reasons
        if reasons:
            self._env_banner.setText("\n\n".join(reasons))
            self._env_banner.show()
        else:
            self._env_banner.hide()
            self._env_banner.clear()

    # ------------------------------------------------------------------
    # Gating override — apply env-block on top of the mixin's rules
    # ------------------------------------------------------------------

    def refresh_pipeline_gating(self) -> None:
        # Delegate the normal Config-applied + progressive-enable rules
        # to the mixin first...
        super().refresh_pipeline_gating()
        # ...then, if the environment gate is red, hard-lock the very
        # first Installation button.  Because the mixin only enables the
        # next step when its predecessor is SUCCESS, this single guard
        # keeps the whole Setup flow (Installation + Server) frozen
        # until the user fixes the environment.
        if self._env_block_reasons:
            first = self._pipe_buttons.get("installation", {}).get("dependency_setup")
            if first is not None:
                first.setEnabled(False)
                first.setToolTip(
                    "Installation blocked by an environment issue — see the "
                    "red banner at the top of the tab for details."
                )
            # Wipe any tooltip nudge that might have been set earlier so
            # the banner is the single source of truth.

    # AppWindow calls this when Config → Apply Changes fires.  Re-evaluate
    # the environment (fields the operator just applied may have fixed
    # things) before letting the mixin flip the buttons on.
    def on_config_applied(self) -> None:
        self._config_applied = True
        self._evaluate_env()
        self.refresh_pipeline_gating()

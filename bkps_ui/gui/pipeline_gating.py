#!/usr/bin/env python3
"""
pipeline_gating.py - Shared pipeline gating & chain-runner for combined tabs.

Combined tabs (Setup, BKP Onboarding / Provisioning) host multiple pipeline
flows.  This module centralises:

* button styling for the four StepStatus values (pending/running/success/failed);
* the step-runner that dispatches a step to ``host.run_worker`` and mirrors
  the outcome onto the shared :class:`PipelineState`;
* the chain-runner that walks every step of a flow (and then every remaining
  flow) sequentially, auto-clicking the next button on success and aborting on
  the first failure;
* the enable/disable gating rules the user asked for:

  - Initially the first button of the first flow is the only clickable one;
    every other pipeline button is disabled.
  - When a step succeeds, the *next* step's button becomes enabled and the
    chain kicks it off.
  - When the last step of a flow succeeds, the first button of the next flow
    becomes enabled and (still part of the same chain) kicks itself off.
  - When a step FAILS the button stays enabled and coloured red so the
    operator can retry from that spot.  Downstream buttons remain disabled
    because the chain stopped there.
  - Every button is additionally gated by ``host._config_applied`` — the
    combined tab keeps its whole pipeline disabled until Config → Apply
    Changes has been clicked at least once, at which point the initial
    enable state above is applied.

To adopt this in a combined tab, subclass :class:`PipelineHost` alongside
:class:`BaseTab`, populate ``self._flow_order`` and ``self._pipe_buttons``
via the pipeline widget builders, then call :meth:`refresh_pipeline_gating`
after both are set up.
"""

from __future__ import annotations

from typing import Callable, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QPushButton

from pipeline import PIPELINE_STEPS, StepStatus


# ── Shared button stylesheets ──────────────────────────────────────────────
_PIPE_PAD = "padding: 6px 12px; min-height: 28px; border-radius: 4px;"
PIPE_STYLE_PENDING = ""
PIPE_STYLE_RUNNING = (
    f"QPushButton {{ background-color: #f39c12; color: white; font-weight: bold; "
    f"border: 1px solid #c87f0a; {_PIPE_PAD} }}"
    f"QPushButton:disabled {{ background-color: #f39c12; color: white; "
    f"border: 1px solid #c87f0a; {_PIPE_PAD} }}"
)
PIPE_STYLE_SUCCESS = (
    f"QPushButton {{ background-color: #27ae60; color: white; font-weight: bold; "
    f"border: 1px solid #1e7d3f; {_PIPE_PAD} }}"
    f"QPushButton:disabled {{ background-color: #1e7d3f; color: #ddd; "
    f"border: 1px solid #166330; {_PIPE_PAD} }}"
)
PIPE_STYLE_FAILED = (
    f"QPushButton {{ background-color: #c0392b; color: white; font-weight: bold; "
    f"border: 1px solid #922b21; {_PIPE_PAD} }}"
    f"QPushButton:disabled {{ background-color: #822015; color: #ddd; "
    f"border: 1px solid #5c170f; {_PIPE_PAD} }}"
)


def _style_for(status: str) -> str:
    if status == StepStatus.RUNNING:
        return PIPE_STYLE_RUNNING
    if status == StepStatus.SUCCESS:
        return PIPE_STYLE_SUCCESS
    if status == StepStatus.FAILED:
        return PIPE_STYLE_FAILED
    return PIPE_STYLE_PENDING


class PipelineHost:
    """Mixin providing pipeline chain-run + progressive enable gating.

    Expected attributes on the combining ``BaseTab`` subclass:

        * ``self._flow_order``    – list[str] of pipeline group ids run in
                                    top-to-bottom order (e.g. ``["installation", "server"]``).
        * ``self._pipe_buttons``  – dict[str, dict[str, QPushButton]] mapping
                                    group_id → step_id → button, populated
                                    by the widget factories.
        * ``self._step_dispatch`` – dict[(group, step_id) → Callable[[cfg], Any]]
                                    populated by the widget factories.  The
                                    callable is what the step runs on the
                                    worker thread.  Any exception aborts
                                    the chain; a return value of ``False``
                                    is treated as a soft failure.
        * ``self._config_applied`` – bool.  Set to True once Config → Apply
                                    Changes has been clicked; the mixin
                                    keeps every pipeline button disabled
                                    while False.
    """

    _flow_order: list[str]
    _pipe_buttons: dict[str, dict[str, QPushButton]]
    _step_dispatch: dict[tuple[str, str], Callable]
    _config_applied: bool
    # Steps whose failure is treated as "advance anyway".  The next step
    # unlocks whether the optional step SUCCEEDED or FAILED, and the
    # chain runner keeps going through a failure here instead of aborting.
    _optional_steps: set[tuple[str, str]] = set()
    # Steps that force the auto-chain to STOP after they succeed.  Maps
    # (group, sid) → operator-facing message shown in the log and via a
    # QMessageBox.  The next button in the flow still becomes enabled
    # (progressive gating unchanged); the operator just has to click it
    # manually — used e.g. after ``puf_activate`` so the operator can
    # power-cycle the device before the post-activation steps run.
    _halt_after_steps: dict[tuple[str, str], str] = {}
    # Cross-tab prerequisite groups: pipeline groups (from PIPELINE_STEPS)
    # that live on EARLIER guided-setup tabs and must all be fully green
    # before ANY button on this tab is enabled — including the very
    # first button of the first flow.  E.g. BkpConfigTab lists
    # ``["installation", "server"]`` so nothing on it unlocks until
    # SetupTab is done.
    _prereq_groups: list[str] = []

    def __init__(self, *args, **kwargs):
        # Cooperative pass-through so combined tabs can list us before
        # BaseTab (needed for our on_finished/on_error overrides to win
        # in the MRO) while still allowing BaseTab.__init__ to receive
        # its expected (store, capture, log_title=..., parent=...) args.
        super().__init__(*args, **kwargs)
        # Per-flow "manual mode" — when True, clicking a step's button
        # runs ONLY that step (no auto-chain to the next).  Populated
        # lazily by the manual-mode checkboxes in pipeline_widgets.
        self._manual_mode: dict[str, bool] = {}
        # While True the tab has one worker in flight; every pipeline
        # AND utility button is disabled so the operator can't stack
        # concurrent commands.  Flipped in _run_pipeline_step /
        # on_finished / on_error.
        self._is_running: bool = False

    # ── Manual-mode + running-lockout helpers ──────────────────────────
    def is_manual(self, group: str) -> bool:
        """Return True when the operator asked to run *group* step-by-step."""
        return bool(self._manual_mode.get(group, False))

    def set_manual(self, group: str, on: bool) -> None:
        """Toggle manual (no auto-chain) mode for a pipeline group.

        Also refreshes gating so the flow's button-enable pattern flips
        immediately: turning manual mode ON unlocks every button of the
        (active) flow so the operator can click steps in any order;
        turning it OFF restores the progressive gating that follows the
        underlying pipeline state.
        """
        self._manual_mode[group] = bool(on)
        try:
            self.refresh_pipeline_gating()
        except Exception:
            # refresh_pipeline_gating may fire before the tab has
            # finished wiring itself (e.g. during __init__); silently
            # ignore — the next refresh call will bring us back in sync.
            pass

    def _set_running(self, on: bool) -> None:
        """Flip the whole-tab lockout flag and refresh gating."""
        self._is_running = bool(on)
        self.refresh_pipeline_gating()

    # ── Helpers ────────────────────────────────────────────────────────
    def _step_unblocks_next(self, group: str, sid: str, status: str) -> bool:
        """True if ``status`` on ``(group, sid)`` should enable downstream steps.

        Non-optional steps must SUCCEED; optional steps unblock on either
        SUCCESS or FAILED (they only stall the chain while they are
        RUNNING / PENDING).
        """
        if status == StepStatus.SUCCESS:
            return True
        if (group, sid) in self._optional_steps and status == StepStatus.FAILED:
            return True
        return False

    # ── PipelineState / progress mirror ────────────────────────────────
    def _pipeline_state(self):
        """Return the shared :class:`PipelineState` from AppWindow, if any."""
        return getattr(self.window(), "pipeline", None)

    def _apply_pipe_style(self, btn: QPushButton, status: str) -> None:
        btn.setStyleSheet(_style_for(status))

    def _mark_pipeline(self, group: str, sid: str, status: str) -> None:
        pl = self._pipeline_state()
        if pl is not None:
            pl.set_status(group, sid, status)
        btn = self._pipe_buttons.get(group, {}).get(sid)
        if btn is not None:
            self._apply_pipe_style(btn, status)

    # ── Enable/disable gating ──────────────────────────────────────────
    def refresh_pipeline_gating(self) -> None:
        """Recompute enable-state for every pipeline button.

        This is the single source of truth — call it after any pipeline
        step status change, and after ``self._config_applied`` flips.
        """
        pl = self._pipeline_state()
        applied = getattr(self, "_config_applied", False)
        prereqs_ok = self._prereqs_satisfied()

        first_flow = self._flow_order[0] if self._flow_order else None
        # Determine which flow is currently "active" — the first one that
        # is not yet fully complete.  Every flow before it is done; every
        # flow after it stays fully locked until the active flow finishes.
        active_flow = None
        for g in self._flow_order:
            group_steps = [sid for sid, _ in PIPELINE_STEPS[g]]
            if not all(
                self._step_unblocks_next(
                    g, sid,
                    pl.status(g, sid) if pl is not None else StepStatus.PENDING,
                )
                for sid in group_steps
            ):
                active_flow = g
                break

        for g in self._flow_order:
            steps = [sid for sid, _ in PIPELINE_STEPS[g]]
            for i, sid in enumerate(steps):
                btn = self._pipe_buttons.get(g, {}).get(sid)
                if btn is None:
                    continue
                status = (pl.status(g, sid) if pl is not None
                          else StepStatus.PENDING)
                self._apply_pipe_style(btn, status)

                # Worker-safety lockout is always absolute — never let
                # the operator queue a second command while one is in
                # flight, even in manual mode.
                if self._is_running:
                    btn.setEnabled(False)
                    continue

                # Manual-mode override is the NEXT-highest priority:
                # ticking a flow's checkbox unlocks every button in
                # that flow so the operator can click steps in any
                # order — even when Config has not been applied yet
                # and even when a previous-tab prerequisite pipeline
                # is not fully green.  Turning the checkbox off
                # restores the exact gating pattern that would have
                # applied without manual mode (state derives from the
                # pipeline status + config-applied + prereqs — nothing
                # to snapshot / restore).
                if self.is_manual(g):
                    btn.setEnabled(True)
                    continue

                if not applied or not prereqs_ok:
                    # Ordering lockouts: Config not applied yet, or a
                    # previous-tab prerequisite pipeline is not fully
                    # green.  These are overridden by manual mode above.
                    btn.setEnabled(False)
                    continue

                if g == active_flow:
                    # Enable steps up to and including the first
                    # not-yet-succeeded step.  Prior successes stay
                    # enabled for manual re-runs; downstream (never-
                    # reached) steps stay locked until their turn comes.
                    prior_all_ok = all(
                        self._step_unblocks_next(
                            g, s,
                            pl.status(g, s) if pl is not None else StepStatus.PENDING,
                        )
                        for s in steps[:i]
                    )
                    btn.setEnabled(prior_all_ok)
                elif active_flow is None or self._flow_order.index(g) < self._flow_order.index(active_flow):
                    # Fully-completed flow — leave every button enabled
                    # for optional manual re-runs.
                    btn.setEnabled(True)
                else:
                    # Later flow — the previous flow is fully green, so
                    # only the FIRST button of this flow is enabled and
                    # the operator must click it explicitly (no
                    # cross-flow chain).  Everything after stays locked
                    # until that first button succeeds.
                    prev_flow_done = self._is_flow_done(active_flow)  # type: ignore[arg-type]
                    btn.setEnabled(prev_flow_done and i == 0)

        # Utility buttons on this tab (if any) also participate in the
        # running-lockout so the operator can't kick off a manual
        # operation while a pipeline step is in flight.
        util_buttons = getattr(self, "_util_buttons", None) or []
        for ub in util_buttons:
            if self._is_running:
                ub.setEnabled(False)
            else:
                ub.setEnabled(True)

        # Manual-mode checkboxes should follow the same lockout so the
        # operator can't flip the mode mid-run.
        checkboxes = getattr(self, "_manual_checkboxes", None) or {}
        for cb in checkboxes.values():
            cb.setEnabled(not self._is_running)

    # ── Cross-tab prerequisite gate ────────────────────────────────────
    def _prereqs_satisfied(self) -> bool:
        """True when every group in ``self._prereq_groups`` is fully green.

        A group counts as done when every step in it either SUCCEEDED
        or is an optional step that FAILED (mirrors the in-tab flow
        logic).  When the group is unknown (missing from PIPELINE_STEPS
        or no ``PipelineState`` yet) we conservatively treat it as
        NOT done so the operator can't sneak past a prereq via a
        priming race.
        """
        prereqs = getattr(self, "_prereq_groups", None) or []
        if not prereqs:
            return True
        pl = self._pipeline_state()
        if pl is None:
            return False
        for g in prereqs:
            steps = PIPELINE_STEPS.get(g)
            if not steps:
                return False
            for sid, _ in steps:
                if not self._step_unblocks_next(g, sid, pl.status(g, sid)):
                    return False
        return True

    # ── Chain scope helpers ────────────────────────────────────────────
    def _is_flow_done(self, group: Optional[str]) -> bool:
        """True when every step in *group* is unblocking (success/optional-fail)."""
        if group is None:
            return True
        pl = self._pipeline_state()
        for sid, _ in PIPELINE_STEPS[group]:
            status = pl.status(group, sid) if pl is not None else StepStatus.PENDING
            if not self._step_unblocks_next(group, sid, status):
                return False
        return True

    # ── Step runner ────────────────────────────────────────────────────
    def _run_pipeline_step(
        self,
        group: str,
        sid: str,
        *,
        on_success: Optional[Callable[[], None]] = None,
        on_failure: Optional[Callable[[], None]] = None,
    ):
        """Dispatch one pipeline step in a background worker.

        The mixin does NOT attach extra slots to ``worker.task_done`` /
        ``worker.error`` — doing so previously caused the chain to die
        silently because ``BaseTab.run_worker``'s own cleanup slot ran
        first and removed the last Python reference to the worker
        QThread, invalidating the second queued call.  Instead we stash
        a single ``_pipe_active`` record and let :meth:`on_finished` /
        :meth:`on_error` (which are ``@Slot`` methods on ``self``, a
        QObject, so they always fire) dispatch it.
        """
        btn = self._pipe_buttons.get(group, {}).get(sid)
        if btn is None:
            return None
        fn = self._step_dispatch.get((group, sid))
        if fn is None:
            return None

        # Only one pipeline step is ever in flight at a time (chain
        # runner is strictly sequential), so a single-slot record is
        # enough.  Anything already pending would be a programmer bug.
        self._pipe_active = {
            "group":      group,
            "sid":        sid,
            "on_success": on_success,
            "on_failure": on_failure,
        }
        self._mark_pipeline(group, sid, StepStatus.RUNNING)
        # Whole-tab lockout while this worker is in flight.
        self._set_running(True)
        select_log = getattr(self, "select_pipeline_log", None)
        if callable(select_log):
            select_log(group)
        return self.run_worker(fn, self.cfg, _buttons=[btn])

    # BaseTab hooks — invoked by run_worker's own task_done / error slots
    # on the main thread, so they run whether or not the worker QThread
    # has been GC'd by the time the queued call is dispatched.
    def on_finished(self, result) -> None:  # type: ignore[override]
        pending = getattr(self, "_pipe_active", None)
        # Delegate to BaseTab so the banner still prints.
        super().on_finished(result)  # type: ignore[misc]
        if not pending:
            # Not a pipeline step (e.g. a utility button).  Still drop
            # the running lockout so utility buttons re-enable.
            self._set_running(False)
            return
        self._pipe_active = None
        g, sid = pending["group"], pending["sid"]
        ok = (result is not False)
        self._mark_pipeline(g, sid, StepStatus.SUCCESS if ok else StepStatus.FAILED)
        # Drop lockout FIRST so the follow-up callback (if it starts the
        # next worker) can immediately re-arm _set_running(True) itself.
        self._set_running(False)
        cb = pending["on_success"] if ok else pending["on_failure"]
        if cb is not None:
            cb()

    def on_error(self, tb: str) -> None:  # type: ignore[override]
        pending = getattr(self, "_pipe_active", None)
        super().on_error(tb)  # type: ignore[misc]
        if not pending:
            self._set_running(False)
            return
        self._pipe_active = None
        g, sid = pending["group"], pending["sid"]
        self._mark_pipeline(g, sid, StepStatus.FAILED)
        self._set_running(False)
        if pending["on_failure"] is not None:
            pending["on_failure"]()

    # ── Chain runner ───────────────────────────────────────────────────
    def _run_pipeline_chain_from(self, group: str, start_sid: str) -> None:
        """Run steps from (group, start_sid) onward, scoped to *group* only.

        - If ``self.is_manual(group)`` is True the chain runs ONLY the
          clicked step (no auto-advance) — the operator explicitly asked
          for step-by-step manual control on this flow.
        - Otherwise every step of THIS flow is chain-run sequentially,
          but the chain stops at the flow boundary.  The first button of
          the next flow becomes enabled (via ``refresh_pipeline_gating``)
          when the current flow completes, but the operator must click
          it explicitly to start the next flow.
        - Failure on a non-optional step aborts the chain; the failed
          button stays enabled and red for retry.
        """
        steps_in_group = [sid for sid, _ in PIPELINE_STEPS[group]]
        try:
            start_idx = steps_in_group.index(start_sid)
        except ValueError:
            return

        # Manual mode → single-step run, no chaining.
        if self.is_manual(group):
            self._run_pipeline_step(group, start_sid)
            return

        plan: list[tuple[str, str]] = [
            (group, sid) for sid in steps_in_group[start_idx:]
        ]
        if not plan:
            return

        def _kick(i: int = 0) -> None:
            if i >= len(plan):
                self.log.append_success(
                    f"'{group}' pipeline completed — click the first button "
                    "of the next flow to continue."
                )
                return
            g, sid = plan[i]

            # Skip steps that don't apply to the current family / ccert /
            # PUF-type combo.  Two signals mark a step as "not for this
            # run":
            #   * status == SUCCESS on entry — tab_bkp.showEvent auto-marks
            #     ``puf_activate`` (and the post-PUF helper/RKH repeats)
            #     SUCCESS when the ccert hint is INTERNAL, so gating no
            #     longer expects the operator to click them.
            #   * The step's button is invisible — visibility refreshers
            #     (see ``refresh_programming_pipeline_visibility``) hide
            #     the button for every "not applicable" combo.
            # Running the dispatcher anyway would fire the backend
            # (e.g. bkp_puf_activate on an INTERNAL device) with the
            # wrong / empty combo state and either crash or clobber the
            # device — silently advance past it instead.
            btn = self._pipe_buttons.get(g, {}).get(sid)
            # Use ``isHidden`` (queries THIS widget's explicit hidden flag)
            # rather than ``isVisible`` (walks the whole parent chain and
            # returns False as soon as any ancestor — including the
            # QTabWidget page — is not currently visible).  When the
            # operator switches tabs mid-chain the pipeline buttons on
            # the running tab are technically ``!isVisible()`` even
            # though nobody called ``setVisible(False)`` on them; the
            # old check treated that as "not applicable for current
            # combo" and silently skipped every remaining step.  The
            # visibility refreshers (``refresh_programming_pipeline_visibility``
            # &c) always call ``setVisible`` directly on the button, so
            # ``isHidden`` still correctly detects the real inapplicable
            # case (hidden by ccert / PUF-type combo).
            btn_hidden = (btn is not None and btn.isHidden())
            # ``auto_success_steps`` (owned by e.g. ``BkpTab``) records
            # every step that ``showEvent`` auto-marked SUCCESS *purely*
            # because the current family / ccert / PUF-type combo makes
            # the step inapplicable — the operator never actually ran
            # them.  Real successes (produced by a real button click)
            # are NOT tracked in this set, so we can tell the two cases
            # apart and log a message that accurately reflects why we
            # are advancing past the step.
            auto_marked = sid in getattr(self, "_auto_success_steps", set())
            if btn_hidden or auto_marked:
                self.log.append_info(
                    f"Skipping {g}.{sid} — not applicable for the current "
                    "family / ccert / PUF-type combo."
                )
                _kick(i + 1)
                return
            # NOTE: in auto (non-manual) mode we deliberately DO re-run
            # every step in the plan, including ones whose status is
            # already SUCCESS.  The operator's intent when clicking a
            # step in auto mode is "run this and every subsequent step
            # of the flow", and that includes re-executing steps that
            # previously succeeded — a green button just means "worked
            # last time", not "safe to skip".  User-action pauses are
            # handled entirely by ``_halt_after_steps`` (e.g. after
            # ``puf_activate`` the chain stops and prompts the operator
            # to power-cycle the device before the next click), which
            # is a separate mechanism from status-based skipping.
            #
            # The "not applicable for the current combo" skip above
            # remains because those steps have hidden buttons and can
            # never legally run in the current configuration.

            optional = (g, sid) in self._optional_steps

            def _on_fail(g=g, sid=sid, idx=i, optional=optional):
                if optional:
                    self.log.append_error(
                        f"Optional step {g}.{sid} failed — continuing the "
                        "chain anyway.  The failed button stays red so you "
                        "can retry it manually if you want."
                    )
                    _kick(idx + 1)
                else:
                    self.log.append_error(
                        f"Pipeline chain aborted at {g}.{sid} — the button "
                        "is left enabled so you can retry from that step."
                    )

            def _on_ok(g=g, sid=sid, idx=i):
                halt_msg = self._halt_after_steps.get((g, sid))
                if halt_msg:
                    # Green-light the next button (refresh_pipeline_gating
                    # already ran via on_finished → _set_running(False)),
                    # then STOP auto-advancing so the operator can act
                    # (typically: power-cycle the device) before clicking
                    # the next step themselves.
                    self.log.append_success(
                        f"'{g}.{sid}' succeeded — pipeline paused.\n{halt_msg}"
                    )
                    try:
                        from PySide6.QtWidgets import QMessageBox
                        QMessageBox.information(
                            self, "Action required", halt_msg
                        )
                    except Exception:
                        pass
                    return
                _kick(idx + 1)

            self._run_pipeline_step(
                g, sid,
                on_success=_on_ok,
                on_failure=_on_fail,
            )

        _kick(0)

    # ── Config-applied gate ────────────────────────────────────────────
    def on_config_applied(self) -> None:
        """AppWindow-facing hook: mark applied + refresh gating."""
        self._config_applied = True
        self.refresh_pipeline_gating()

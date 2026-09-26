#!/usr/bin/env python3
"""
pipeline.py - Shared state for the guided setup pipeline.

Tracks per-step status for the Installation and Server tabs so ``AppWindow``
can drive both a global progress bar at the bottom of the window and the
gating of subsequent tabs (a tab only becomes reachable once every step in
the previous pipeline group has reached the ``SUCCESS`` state).

This module is purely presentational — it does not itself invoke any
backend logic.  Each tab calls ``PipelineState.set_status`` after its
worker completes; ``AppWindow`` observes the ``changed`` /
``group_completed`` signals and refreshes the UI accordingly.

Exports:
    StepStatus       -- string constants for status values
    PIPELINE_STEPS   -- ordered step definitions per group
    PipelineState    -- QObject holding the live status per (group, step)
"""

from PySide6.QtCore import QObject, Signal

from utils.pipeline_spec import PIPELINE_CHAIN, PIPELINE_STEPS, StepStatus

__all__ = [
    "PIPELINE_CHAIN",
    "PIPELINE_STEPS",
    "PipelineState",
    "StepStatus",
]


class PipelineState(QObject):
    """Live status tracker for every step in ``PIPELINE_STEPS``.

    Emits ``changed(group, step_id, status)`` whenever a step's status
    transitions, and ``group_completed(group)`` when every step in a group
    reaches ``StepStatus.SUCCESS``.  ``AppWindow`` listens on both to refresh
    the global progress bar and unlock the next tab.
    """

    changed = Signal(str, str, str)   # (group, step_id, status)
    group_completed = Signal(str)     # group

    def __init__(self, parent=None):
        super().__init__(parent)
        self._status = {
            group: {sid: StepStatus.PENDING for sid, _label in steps}
            for group, steps in PIPELINE_STEPS.items()
        }

    def set_status(self, group: str, step_id: str, status: str) -> None:
        """Transition ``group.step_id`` to ``status`` and emit signals."""
        if group not in self._status or step_id not in self._status[group]:
            return
        if self._status[group][step_id] == status:
            return
        self._status[group][step_id] = status
        self.changed.emit(group, step_id, status)
        if self.is_group_complete(group):
            self.group_completed.emit(group)

    def mark_group_success(self, group: str) -> None:
        """Mark every step in *group* as SUCCESS (used for backfill on startup
        and after the legacy Full-Installation / Auto-Setup buttons complete).
        """
        for sid in list(self._status.get(group, {}).keys()):
            self.set_status(group, sid, StepStatus.SUCCESS)

    def reset(self) -> None:
        """Reset every step to PENDING when the active project changes."""
        for group, steps in self._status.items():
            for step_id in list(steps.keys()):
                self.set_status(group, step_id, StepStatus.PENDING)

    def status(self, group: str, step_id: str) -> str:
        return self._status.get(group, {}).get(step_id, StepStatus.PENDING)

    def is_group_complete(self, group: str) -> bool:
        vals = self._status.get(group, {}).values()
        return bool(vals) and all(s == StepStatus.SUCCESS for s in vals)

    def total(self) -> int:
        return sum(len(s) for s in self._status.values())

    def completed(self) -> int:
        return sum(
            1 for g in self._status.values()
            for s in g.values() if s == StepStatus.SUCCESS
        )

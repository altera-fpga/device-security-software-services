#!/usr/bin/env python3
"""Append-only JSON audit log for privileged BKPS operations (never raises)."""

import os
import json
import getpass
from datetime import datetime, timezone


# ── Public API ──────────────────────────────────────────────────────────────────

def audit_log(cfg, action: str, details: str = "", outcome: str = "started") -> None:
    """Append one JSON line to ``<bkps_dir>/logs/audit.log``.

    Args:
        action: Short operation name, e.g. ``create_super_admin``.
        outcome: ``started``, ``success``, or ``failure``.
        details: Optional extra context (IDs, paths).
    """
    try:
        log_dir = os.path.join(cfg.bkps_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)  # create logs/ directory if absent
        log_path = os.path.join(log_dir, "audit.log")

        entry = {
            "ts":      datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            # Prefer an explicit username on cfg; fall back to the OS user.
            "user":    getattr(cfg, "username", None) or getpass.getuser(),
            "action":  action,
            "outcome": outcome,
        }
        if details:
            entry["details"] = details

        # Append one JSON line; file is created if it does not exist.
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # Audit logging must NEVER raise — it must not crash the calling operation.

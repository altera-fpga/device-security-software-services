#!/usr/bin/env python3
"""Qt-free pipeline step definitions shared by the GUI and unit tests."""

from __future__ import annotations

import re


class StepStatus:
    """Enumerated status values for a single pipeline step (as strings)."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


PIPELINE_STEPS = {
    "installation": [
        ("dependency_setup",  "1. Check/Setup Dependencies"),
        ("repo_setup",        "2. Setup BKPS Repository"),
        ("security_provider", "3. Install Security Provider"),
        ("ssl_certs",         "4. Create SSL Certificates"),
        ("bkps_keystore",     "5. Create BKPS Keystore"),
        ("bkps_config",       "6. Create BKPS Configuration"),
    ],
    "server": [
        ("db_reset",          "1. Initialize / Reset Database"),
        ("super_admin",       "2. Create + Activate Super Admin"),
        ("auth_keys",         "3. Create Authentication Keys"),
        ("bkps_keys",         "4. Configure BKPS Keys"),
    ],
    "aes": [
        ("init_token",        "1. Init Token"),
        ("create_key",        "2. Create Key"),
        ("create_qek_ccert",  "3. Create QEK + ccert + Sign"),
    ],
    "configuration": [
        ("create_config",        "1. Create Configuration"),
        ("create_programmer",    "2. Create Programmer User"),
        ("generate_bkp_options", "3. Generate bkp_options.txt"),
    ],
    "programming": [
        ("generate_jic",             "1. Generate JIC"),
        ("program_helper_image_pre", "2. Program Helper Image"),
        ("provision_rkh_pre",        "3. Program Root Key Hash"),
        ("program_jic",              "4. Program JIC"),
        ("prefetch",                 "5. BKP Prefetch"),
        ("puf_activate",             "6. BKP PUF Activate"),
        ("program_helper_image",     "7. Program Helper Image (post-PUF)"),
        ("provision_rkh",            "8. Program Root Key Hash (post-PUF)"),
        ("set_authority",            "9. BKP Set Authority"),
        ("provision",                "10. BKP Provision"),
    ],
}

PIPELINE_CHAIN = (
    "installation",
    "server",
    "aes",
    "configuration",
    "programming",
)


def visible_pipeline_labels(
    group: str,
    visible_step_ids: set[str] | None = None,
) -> list[tuple[str, str]]:
    """Return consecutive numbered labels for the visible steps in *group*."""
    steps = PIPELINE_STEPS[group]
    visible_step_ids = visible_step_ids or {sid for sid, _ in steps}
    labels: list[tuple[str, str]] = []
    visible_index = 0
    for sid, configured_label in steps:
        if sid not in visible_step_ids:
            continue
        visible_index += 1
        title = re.sub(r"^\d+\.\s*", "", configured_label)
        labels.append((sid, f"{visible_index}. {title}"))
    return labels

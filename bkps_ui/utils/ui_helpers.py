#!/usr/bin/env python3
"""Qt-free helpers shared by the GUI and unit tests."""

from __future__ import annotations

import glob
import os
import re
import shutil
import sys

from bkps_config import (
    detect_system_softhsm_library,
    detect_softhsm_config_path,
    detect_softhsm_tokens_dir,
)
from bkps_windows_runtime import windows_softhsm_root, windows_softhsm_config_path

_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")

DEFAULT_SECRET_FIELDS = {
    "ssl_password": ("ssl_password", "SSL password"),
    "pkcs11_password": ("pkcs11_password", "PKCS#11 password"),
    "keystore_password": ("keystore_password", "keystore password"),
    "db_password": ("bkps_password", "database password"),
    "pg_superuser_password": ("postgres", "PostgreSQL superuser password"),
    "aes_passphrase": ("aes_passphrase", "AES passphrase"),
    "programmer_cert_password": (
        "programmer_cert_password",
        "programmer certificate password",
    ),
    "softhsm_user_pin": ("12345678", "SoftHSM user PIN"),
    "softhsm_so_pin": ("12345678", "SoftHSM security officer PIN"),
}


def default_secret_warnings(values: dict[str, str], provider: str) -> list[str]:
    """Return safe warnings for unchanged defaults without exposing values."""
    defaults = dict(DEFAULT_SECRET_FIELDS)
    if provider == "bouncycastle":
        defaults["bc_keystore_password"] = (
            "bc_keystore_password",
            "Bouncy Castle keystore password",
        )
    return [
        f"{label} is set to its default value — change before production use"
        for attr, (default, label) in defaults.items()
        if values.get(attr, "") == default
    ]


def redacted_env_export_message(key: str) -> str:
    """Describe an environment update without exposing its value."""
    return f"[env] exported {key} (value hidden)"


def redacted_env_skip_message(line_number: int) -> str:
    """Describe a malformed environment entry without echoing its contents."""
    return f"[env] ignored malformed entry on line {line_number} (content hidden)"


def apply_server_env_vars(env_text: str) -> None:
    """Export pipeline Extra Env Vars into ``os.environ`` for the JVM child."""
    applied: list[str] = []
    skipped: list[int] = []
    for line_number, raw in enumerate((env_text or "").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            skipped.append(line_number)
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not _ENV_NAME_RE.fullmatch(key):
            skipped.append(line_number)
            continue
        os.environ[key] = value
        applied.append(key)
    for key in applied:
        print(redacted_env_export_message(key))
    for line_number in skipped:
        print(redacted_env_skip_message(line_number))


def resolve_jic_output_dir(cfg, requested: str | None = None) -> str:
    """Return an explicit JIC output directory or the project-scoped default."""
    requested = (requested or "").strip()
    if requested:
        return os.path.abspath(os.path.expandvars(os.path.expanduser(requested)))
    cm_dir = (getattr(cfg, "cm_provisioning_dir", "") or "").strip()
    if not cm_dir:
        return ""
    cm_dir = os.path.abspath(os.path.expandvars(os.path.expanduser(cm_dir)))
    return os.path.join(cm_dir, "device_onboarding")


def find_softhsm_library(bkps_dir: str) -> str:
    """Return the first platform-appropriate SoftHSM PKCS#11 provider found."""
    home = os.path.expanduser("~")

    if not sys.platform.startswith("win"):
        system_provider = detect_system_softhsm_library()
        if system_provider:
            return system_provider

    patterns = ["libsofthsm2.so", "libsofthsm2.so.*"]
    if sys.platform.startswith("win"):
        patterns = ["softhsm2-x64.dll", "softhsm2.dll", "libsofthsm2.dll"]
    elif sys.platform == "darwin":
        patterns = ["libsofthsm2.dylib", "libsofthsm2.so", "libsofthsm2.so.*"]

    search_roots = []
    if sys.platform.startswith("win"):
        managed_root = windows_softhsm_root()
        if managed_root:
            search_roots.extend([
                os.path.join(managed_root, "lib"),
                os.path.join(managed_root, "bin"),
            ])
        for env_name in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
            program_root = os.environ.get(env_name, "").strip()
            if program_root:
                search_roots.extend([
                    os.path.join(program_root, "SoftHSM2", "lib"),
                    os.path.join(program_root, "SoftHSM2", "bin"),
                ])
    else:
        search_roots.extend([
            "/usr/lib/softhsm",
            "/usr/lib64/softhsm",
            "/usr/local/lib/softhsm",
            "/usr/lib",
            "/usr/lib64",
            "/usr/local/lib",
        ])
    search_roots.extend([
        os.path.join(bkps_dir, "lib"),
        bkps_dir,
        home,
    ])

    candidates = []
    seen_roots = set()
    for root in search_roots:
        normalized = os.path.normcase(os.path.abspath(root)) if root else ""
        if not normalized or normalized in seen_roots or not os.path.isdir(root):
            continue
        seen_roots.add(normalized)
        for pattern in patterns:
            candidates.extend(glob.glob(os.path.join(root, pattern)))
            candidates.extend(glob.glob(os.path.join(root, "*", pattern)))

    return os.path.abspath(candidates[0]) if candidates else ""


def find_executable(command: str, candidates: list[str]) -> str:
    """Return an absolute executable path from PATH or known install paths."""
    on_path = shutil.which(command)
    if on_path and os.path.isfile(on_path):
        return os.path.abspath(on_path)
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return os.path.abspath(candidate)
    return ""


def find_softhsm_tools(bkps_dir: str) -> dict[str, str]:
    """Find the SoftHSM provider, SoftHSM utility, and OpenSC PKCS#11 tool."""
    home = os.path.expanduser("~")
    project_candidates = [
        os.path.join(bkps_dir, "bin"),
        bkps_dir,
        os.path.join(home, ".local", "bin"),
    ]
    util_candidates: list[str] = []
    pkcs11_candidates: list[str] = []

    if sys.platform.startswith("win"):
        managed_root = windows_softhsm_root()
        if managed_root:
            util_candidates.append(
                os.path.join(managed_root, "bin", "softhsm2-util.exe")
            )
        for env_name in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
            program_root = os.environ.get(env_name, "").strip()
            if program_root:
                util_candidates.append(
                    os.path.join(program_root, "SoftHSM2", "bin", "softhsm2-util.exe")
                )
                pkcs11_candidates.extend([
                    os.path.join(
                        program_root,
                        "OpenSC Project",
                        "OpenSC",
                        "tools",
                        "pkcs11-tool.exe",
                    ),
                    os.path.join(program_root, "OpenSC", "tools", "pkcs11-tool.exe"),
                ])
        for root in project_candidates:
            util_candidates.append(os.path.join(root, "softhsm2-util.exe"))
            pkcs11_candidates.append(os.path.join(root, "pkcs11-tool.exe"))
    else:
        standard_bins = ["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"]
        for root in standard_bins + project_candidates:
            util_candidates.append(os.path.join(root, "softhsm2-util"))
            pkcs11_candidates.append(os.path.join(root, "pkcs11-tool"))

    if sys.platform.startswith("win"):
        managed_config = windows_softhsm_config_path()
        config_path = (
            os.path.abspath(managed_config)
            if managed_config and os.path.isfile(managed_config)
            else detect_softhsm_config_path()
        )
    else:
        config_path = detect_softhsm_config_path()

    return {
        "library": find_softhsm_library(bkps_dir),
        "softhsm_conf": config_path,
        "softhsm_tokens": detect_softhsm_tokens_dir(config_path),
        "softhsm_util": find_executable("softhsm2-util", util_candidates),
        "pkcs11_tool": find_executable("pkcs11-tool", pkcs11_candidates),
    }

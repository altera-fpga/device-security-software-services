"""Windows-only runtime helpers shared by BKPS setup and dependency checks."""

import os
import shutil
import subprocess
from pathlib import Path


WINDOWS_SOFTHSM_VERSION = "2.5.0"


def windows_softhsm_root() -> str:
    """Return the per-user directory used by the validated Windows lab runtime."""
    explicit_root = os.environ.get("BKPS_SOFTHSM_INSTALL_ROOT", "")
    if explicit_root:
        return os.path.abspath(os.path.expandvars(os.path.expanduser(explicit_root)))
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if not local_app_data:
        return ""
    return os.path.abspath(
        os.path.join(
            local_app_data,
            "BKPS",
            "SoftHSM2",
            f"runtime-{WINDOWS_SOFTHSM_VERSION}",
        )
    )


def windows_softhsm_config_path() -> str:
    """Return the configuration file used by the managed Windows lab runtime."""
    explicit_root = os.environ.get("BKPS_SOFTHSM_CONFIG_ROOT", "")
    if explicit_root:
        config_root = os.path.abspath(
            os.path.expandvars(os.path.expanduser(explicit_root))
        )
    else:
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        if not local_app_data:
            return ""
        config_root = os.path.abspath(
            os.path.join(local_app_data, "BKPS", "SoftHSM2")
        )
    return os.path.join(config_root, "softhsm2.conf")


def configure_windows_softhsm_defaults(cfg) -> None:
    """Populate missing config paths from setup-managed SoftHSM and OpenSC."""
    if os.name != "nt":
        return

    root = windows_softhsm_root()
    managed = {
        "softhsm_lib_path": os.path.join(root, "lib", "softhsm2-x64.dll"),
        "softhsm_util_path": os.path.join(root, "bin", "softhsm2-util.exe"),
        "softhsm_conf_path": windows_softhsm_config_path(),
    }
    for attr, candidate in managed.items():
        configured = (getattr(cfg, attr, "") or "").strip()
        if (not configured or not os.path.exists(configured)) and os.path.exists(candidate):
            setattr(cfg, attr, candidate)

    configured_p11 = (getattr(cfg, "pkcs11_tool_path", "") or "").strip()
    if configured_p11 and os.path.isfile(configured_p11):
        return
    on_path = shutil.which("pkcs11-tool")
    if on_path:
        cfg.pkcs11_tool_path = on_path
        return

    roots = []
    for name in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
        value = os.environ.get(name, "").strip()
        if value and value not in roots:
            roots.append(value)
    for base in roots:
        candidate = os.path.join(base, "OpenSC Project", "OpenSC", "tools", "pkcs11-tool.exe")
        if os.path.isfile(candidate):
            cfg.pkcs11_tool_path = candidate
            break


def install_windows_softhsm() -> str:
    """Install and validate the pinned, signed Windows demo/test runtime."""
    installer = Path(__file__).resolve().with_name("install_softhsm_windows.ps1")
    if not installer.is_file():
        raise RuntimeError(f"Windows SoftHSM installer is missing: {installer}")
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        raise RuntimeError("PowerShell is required to install Windows SoftHSM")
    result = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(installer),
        ],
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "The signed Windows SoftHSM lab runtime failed installation or validation"
        )
    root = windows_softhsm_root()
    utility = os.path.join(root, "bin", "softhsm2-util.exe")
    provider = os.path.join(root, "lib", "softhsm2-x64.dll")
    if not os.path.isfile(utility) or not os.path.isfile(provider):
        raise RuntimeError("Windows SoftHSM validation passed but runtime files are missing")
    os.environ["BKPS_SOFTHSM_ROOT"] = root
    return root

#!/usr/bin/env python3
"""Check and install system tools, Python packages, and native BKPS dependencies."""

import getpass
import hashlib
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from bkps_config import Config, detect_system_softhsm_library
from bkps_printer import print_header, print_step, print_success, print_warning, print_error, print_info
from bkps_runner import command_exists, run, stream
from bkps_windows_runtime import configure_windows_softhsm_defaults


# Platform flag used by the check/install loops.
is_windows = (os.name == "nt")

# Minimum Java version required
MINIMUM_JAVA_VERSION = (17, 0, 0)

# Truststore for integration testing (platform-agnostic temp dir)
TRUSTSTORE_PATH = os.path.join(tempfile.gettempdir(), "bkps-nonprod.p12")
TRUSTSTORE_PASSWORD = "donotchange"

# Native library versions (for bkpprogrammer, FCS server, spdm_wrapper builds)
NATIVE_LIB_VERSIONS = {
    "OPENSSL_VERSION": "3.5.5",
    "BOOST_VERSION": "1.84.0",
    "LIBCURL_VERSION": "8.12.1",
    "GTEST_VERSION": "1.14.0",
    "LIBSPDM_VERSION": "3.8.2",
}

# ── Required tool / package manifests ─────────────────────────────────────────────

# Python packages: {import_name: pip_package_name}
REQUIRED_PYTHON_PACKAGES = {
    "ecdsa":        "ecdsa>=0.13,<=0.18",
    "cryptography": "cryptography",
    "docopt":       "docopt>=0.6.2",
    "requests":     "requests>=2.28.0",
    "packaging":    "packaging>=23.0",
    "OpenSSL":      "pyOpenSSL>=21.0.0",
    "Crypto":       "pycryptodome",
    "PySide6":      "PySide6>=6.4.0",
    "psycopg2":     "psycopg2-binary>=2.9.0",
    "pkg_resources": "setuptools>=65.0,<72",
}

# System tools to check
REQUIRED_TOOLS = [
    ("python3",     "Python 3", ["python3", "python3-pip"], ["python3", "python3-pip"]),
    ("java",        "Java 17+", ["java-17-openjdk", "java-17-openjdk-devel"], ["openjdk-17-jre", "openjdk-17-jdk"]),
    ("psql",        "PostgreSQL", ["postgresql-server", "postgresql"], ["postgresql", "postgresql-contrib"]),
    ("openssl",     "OpenSSL", ["openssl"], ["openssl"]),
    ("wget",        "wget", ["wget"], ["wget"]),
    ("aria2c",      "aria2", ["aria2"], ["aria2"]),
    ("jq",          "jq", ["jq"], ["jq"]),
    ("curl",        "curl", ["curl"], ["curl"]),
    ("git",         "git", ["git"], ["git"]),
    ("unzip",       "unzip", ["unzip"], ["unzip"]),
    ("keytool",     "keytool (Java)", [], []),
    ("cmake",       "CMake", ["cmake"], ["cmake"]),
    ("make",        "Make", ["make", "gcc"], ["make", "build-essential"]),
    ("nc",          "netcat", ["nmap-ncat"], ["netcat-openbsd"])
]

# ── Tool classification sets ─────────────────────────────────────────────────────────

# Tools that are Linux-only utilities — not expected on Windows.
# Missing these on Windows is silently skipped (not an error).
# The upstream Windows build uses Visual Studio's compiler and bundled CMake;
# these Linux-oriented command names are therefore not required in PATH.
_WINDOWS_SKIP_TOOLS = {"wget", "aria2c", "jq", "unzip", "nc", "cmake", "make"}

# Quartus/FPGA tools are hardware-specific and optional.
# Missing them produces a warning but does NOT count as an error.
# Key-generation steps will simply fail at runtime if they're needed.
_SOFT_TOOLS = {"quartus_pgm", "quartus_sign", "quartus_pfg", "quartus_encrypt"}

# ── Public API ───────────────────────────────────────────────────────────────────

def check_dependencies(cfg: Config, last_check: bool = False) -> tuple:
    """Check required system tools and Python packages; SoftHSM extras for Agilex 5."""
    # setup.bat can install tools after the parent GUI process was started.
    # Refresh its in-process PATH before probing so an already-installed tool
    # is not incorrectly sent through winget again.
    if is_windows:
        _refresh_windows_path()
    configure_windows_softhsm_defaults(cfg)
    print_header("Checking Dependencies")
    missing = 0
    missing_required_tools = []
    missing_quartus_tools = []
    missing_python_packages = []
    missing_softhsm_tools = []

    # System tools
    step_n = 0
    for tool, label, _dnf_pkgs, _apt_pkgs in REQUIRED_TOOLS:
        # On Windows, skip Linux-only utilities entirely
        if is_windows:
            if tool in _WINDOWS_SKIP_TOOLS:
                continue

        step_n += 1
        print_step(step_n, f"Checking {label}...")

        if command_exists(tool):
            version = _tool_version(tool)
            if tool == "java":
                java_ok, java_ver = _check_java_version()
                if java_ok:
                    print_success(f"{label} found: {java_ver}")
                else:
                    print_error(f"Java version {java_ver} is below minimum {'.'.join(map(str, MINIMUM_JAVA_VERSION))}")
                    missing_required_tools.append(tool)
                    missing += 1
            else:
                print_success(f"{label} found{': ' + version if version else ''}")
        else:
            if last_check:
                print_error(f"{label} not found")
            else:
                print_warning(f"{label} not found")
            missing_required_tools.append(tool)
            missing += 1

    # Soft Tools (Quartus / FPGA — warning only, do not count as missing)
    for tool in _SOFT_TOOLS:
        if command_exists(tool):
            print_success(f"{tool} found.")
        else:
            if last_check:
                print_error(f"{tool} not found.")
            else:
                print_warning(f"{tool} not found.")
            missing_quartus_tools.append(tool)
            missing += 1

    # Python packages
    step_n += 1
    print_step(step_n, "Checking Python packages...")
    for import_name, pkg_name in REQUIRED_PYTHON_PACKAGES.items():
        ok = _python_import_ok(import_name)
        if ok:
            print_success(f"Python package {pkg_name} installed")
        else:
            if last_check:
                print_error(f"Python package {pkg_name} NOT installed")
            else:
                print_warning(f"Python package {pkg_name} NOT installed")
            missing_python_packages.append(pkg_name)
            missing += 1

    # Container engine — only when the build selection compiles inside one.
    container_components = [] if is_windows else _selected_container_components(cfg)
    if container_components:
        step_n += 1
        print_step(
            step_n,
            f"Checking container engine ({' and '.join(container_components)})...",
        )
        state, detail = _docker_build_status()
        if state == "ready":
            print_success("Container engine is ready")
        elif state == "group-shim":
            print_success(
                "Container engine is installed; the build applies the docker "
                "group to its own session"
            )
        else:
            report = print_error if last_check else print_warning
            report(
                f"Container engine is not usable: {detail}\n"
                f"    {' and '.join(container_components)} cannot be built "
                "without it."
            )
            missing += 1

    # SoftHSM tools — Linux only, soft check for Agilex 5
    if getattr(cfg, "profile_name", "") == "agilex5":
        step_n += 1
        print_step(step_n, "Checking SoftHSM / PKCS#11 tools (Agilex 5)...")

        # SoftHSM library path (Config tab → SoftHSM section).
        lib_path = (getattr(cfg, "softhsm_lib_path", "") or "").strip()
        if not lib_path:
            lib_path = detect_system_softhsm_library()
            if lib_path:
                cfg.softhsm_lib_path = lib_path
        if lib_path and os.path.isfile(lib_path):
            print_success(f"SoftHSM library found: {lib_path}")
        elif lib_path:
            print_error(
                "Configured SoftHSM library does not exist:\n"
                f"  {lib_path}\n"
                "Correct SoftHSM Library on the Config tab -> "
                "SoftHSM PKCS#11 section"
            )
            missing += 1
        else:
            print_error(
                "SoftHSM library was not found in standard system or "
                "multiarch locations.\n"
                "Set SoftHSM Library on the Config tab -> "
                "SoftHSM PKCS#11 section"
            )
            missing += 1

        # SoftHSM configuration path.  The command-line utility can silently
        # use a system default, but Quartus must receive the exact same file in
        # SOFTHSM2_CONF or it may load a different token store.
        conf_path = (getattr(cfg, "softhsm_conf_path", "") or "").strip()
        if conf_path and os.path.isfile(conf_path):
            print_success(f"SoftHSM configuration found: {conf_path}")
        else:
            report = print_error if last_check else print_warning
            report(
                "SoftHSM configuration file was not found.\n"
                f"  Configured path: {conf_path or '[empty]'}\n"
                "Set SOFTHSM_CONF_PATH to the softhsm2.conf used by the "
                "AlteraAESToken token store."
            )
            missing_softhsm_tools.append("softhsm2.conf")
            missing += 1

        # SoftHSM util path — needed by the AES compact certificate tab.
        util_path = (getattr(cfg, "softhsm_util_path", "") or "").strip()
        if util_path and os.path.isfile(util_path):
            print_success(f"softhsm2-util tool is available: {util_path}")
        elif shutil.which("softhsm2-util"):
            print_success("softhsm2-util tool found on PATH")
        else:
            if last_check:
                print_error(
                    "  softhsm2-util tool is not configured and not on PATH\n"
                    "    Set softhsm_util_path on the Config tab → SoftHSM PKCS#11 section,\n"
                    "    or install softhsm2 so softhsm2-util is on PATH."
                )
            else:
                print_warning(
                    "  softhsm2-util tool is not configured and not on PATH\n"
                    "    Set softhsm_util_path on the Config tab → SoftHSM PKCS#11 section,\n"
                    "    or install softhsm2 so softhsm2-util is on PATH."
                )
            missing_softhsm_tools.append("softhsm2-util")
            missing += 1

        # pkcs11-tool path — needed by the AES compact certificate tab.
        p11_path = (getattr(cfg, "pkcs11_tool_path", "") or "").strip()
        if p11_path and os.path.isfile(p11_path):
            print_success(f"pkcs11-tool tool is available: {p11_path}")
        elif shutil.which("pkcs11-tool"):
            print_success("pkcs11-tool tool found on PATH")
        else:
            if last_check:
                print_error(
                    "pkcs11-tool binary not configured and not on PATH\n"
                    "Set pkcs11_tool_path on the Config tab → SoftHSM PKCS#11 section,\n"
                    "or install opensc so pkcs11-tool is on PATH."
                )
            else:
                print_warning(
                    "pkcs11-tool binary not configured and not on PATH\n"
                    "Set pkcs11_tool_path on the Config tab → SoftHSM PKCS#11 section,\n"
                    "or install opensc so pkcs11-tool is on PATH."
                )
            missing_softhsm_tools.append("pkcs11-tool")
            missing += 1

        # SoftHSM token/user PIN sanity checks — required for Agilex 5 flows.
        for attr, label in [
            ("softhsm_token_label", "Token Label"),
            ("softhsm_user_pin",    "User PIN"),
            ("softhsm_key_label",   "Key Label"),
        ]:
            val = (getattr(cfg, attr, "") or "").strip()
            if val:
                # Never echo the PIN back to the log.
                shown = "***" if attr == "softhsm_user_pin" else val
                print_success(f"  SoftHSM {label}: {shown}")
            else:
                if last_check:
                    print_error(
                        f"  SoftHSM {label} is empty ({attr})\n"
                        f"    Set it on the Config tab → SoftHSM PKCS#11 section."
                    )
                else:
                    print_warning(
                        f"  SoftHSM {label} is empty ({attr})\n"
                        f"    Set it on the Config tab → SoftHSM PKCS#11 section."
                    )
                missing += 1

    if missing == 0:
        print_success("\nAll dependencies satisfied!")
    else:
        if last_check:
            print_error(f"\n{missing} missing dependencies found")
        else:
            print_warning(f"\n{missing} missing dependencies found")
    return (missing, missing_required_tools, missing_python_packages, missing_softhsm_tools, missing_quartus_tools)


def install_dependencies(cfg: Config) -> None:
    """Install missing Python packages, then system packages for the current OS."""
    print_header("Installing Dependencies")

    # First, check if all dependencies are already met
    (missing, missing_required_tools, missing_python_packages, missing_softhsm_tools, missing_quartus_tools) = check_dependencies(cfg)
    if missing == 0:
        print_success("All dependencies already satisfied - skipping installation")
        return

    distro_family = _detect_distro()
    print_info(f"Detected distribution family: {distro_family}")

    if os.name != "nt":
        # The package, cluster, and service commands below run under sudo.
        # Priming the credential cache keeps them non-interactive, because the
        # GUI has no terminal on which to answer a password prompt.
        # Imported locally to keep module import order independent.
        from bkps_database import authenticate_sudo
        authenticate_sudo(cfg)

    # ---- Step 1: Install missing Python packages (single batched pip call) ----
    print_step(1, "Installing Python packages...")
    if missing_python_packages:
        print_info(f"Installing {len(missing_python_packages)} Python packages: "
                   f"{', '.join(missing_python_packages)}")
        stream([sys.executable, "-m", "pip", "install", *missing_python_packages])
    else:
        print_success("  All Python packages already installed")

    # ---- Windows: winget auto-install ----
    if distro_family == 'windows':
        _install_dependencies_windows(cfg)
        return

    # ---- Step 2: Check and install only missing system packages ----
    print_step(2, "Checking system packages...")



    missing_pkgs = []
    if missing_required_tools:
        print_info(f"Installing {len(missing_required_tools)} system packages...")
        for tool, label, dnf_pkgs, apt_pkgs in REQUIRED_TOOLS:
            if tool in missing_required_tools:
                print_info(f"{label} missing - will be installed")
                if distro_family == "rhel":
                    missing_pkgs.extend(dnf_pkgs)
                else:
                    missing_pkgs.extend(apt_pkgs)
        missing_pkgs = list(dict.fromkeys(missing_pkgs))
        _install_system_packages(missing_pkgs, distro_family)
    else:
        print_success("  All system packages already installed")

    # On RHEL, PostgreSQL requires a one-time cluster initialisation before it can start.
    # Run this whenever psql was just installed (i.e. it was in the missing list).
    if distro_family == "rhel" and any("postgresql" in p for p in missing_pkgs):
        _ensure_postgresql_rhel()



    # ---- Step 3: Container engine for the selected build ----
    container_components = _selected_container_components(cfg)
    if container_components:
        print_step(
            3,
            f"Setting up container engine ({' and '.join(container_components)})...",
        )
        _ensure_container_engine(cfg, distro_family)

    # ---- Step 4: Check and create truststore ----
    print_step(4, "Checking test truststore...")
    _create_dummy_truststore()  # This function already checks internally

    # ---- Step 5: SoftHSM setup (Agilex 5 on Linux only) ----
    if getattr(cfg, "profile_name", "") == "agilex5" and missing_softhsm_tools:
        print_step(5, "Setting up SoftHSM (Agilex 5)...")
        _install_softhsm(cfg, distro_family)

    print_success("\nDependency installation complete!")


def ensure_dependencies(cfg: Config) -> bool:
    """Check dependencies, auto-install anything missing, then re-check."""
    print_header("Ensuring All Dependencies Are Satisfied")

    (missing, _, _, _, _) = check_dependencies(cfg)
    if missing > 0:
        print_warning("Missing dependencies detected. Installing now...")
        install_dependencies(cfg)

        print_info("Re-checking dependencies after installation...")
        (missing, _, _, _, _) = check_dependencies(cfg, last_check=True)
        if missing > 0:
            print_error("Some dependencies are still missing after installation!")
            print_error("Please install missing dependencies manually and try again")
            return False

    print_success("All dependencies are satisfied")
    return True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# ── Internal helpers ────────────────────────────────────────────────────────────────

def _detect_distro() -> str:
    """Return OS family: 'windows', 'debian', 'rhel', or 'unknown'."""
    if os.name == 'nt':
        return 'windows'
    try:
        with open("/etc/os-release") as f:
            content = f.read().lower()
        if any(x in content for x in ("ubuntu", "debian", "linuxmint", "pop!_os")):
            return "debian"
        if any(x in content for x in ("rhel", "centos", "fedora", "rocky", "almalinux",
                                       "oracle linux", "scientific linux")):
            return "rhel"
    except OSError:
        pass
    # Fallback: probe the package manager directly
    if shutil.which("apt"):
        return "debian"
    if shutil.which("dnf") or shutil.which("yum"):
        return "rhel"
    return "unknown"


def _refresh_windows_path() -> None:
    """Append well-known Windows install directories to the in-process PATH."""
    if os.name != "nt":
        return

    program_files = (
        os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles", "")
    )
    program_files86 = os.environ.get("ProgramFiles(x86)", "")
    local_app_data  = os.environ.get("LOCALAPPDATA",
                                     os.path.expanduser(r"~\AppData\Local"))

    candidates: list[str] = []

    # Java (Microsoft OpenJDK 17 / 21) — pattern: <ProgramFiles>\Microsoft\jdk-*\bin
    for base in (os.path.join(program_files, "Microsoft"),
                 os.path.join(program_files, "Eclipse Adoptium")):
        if os.path.isabs(base) and os.path.isdir(base):
            for name in os.listdir(base):
                bin_dir = os.path.join(base, name, "bin")
                if os.path.isdir(bin_dir):
                    candidates.append(bin_dir)

    # Python (Python.Python.3.12) — installs per-user under LOCALAPPDATA\Programs\Python
    py_root = os.path.join(local_app_data, "Programs", "Python")
    if os.path.isdir(py_root):
        for name in os.listdir(py_root):
            root = os.path.join(py_root, name)
            if os.path.isdir(root):
                candidates.append(root)
                scripts = os.path.join(root, "Scripts")
                if os.path.isdir(scripts):
                    candidates.append(scripts)

    # PostgreSQL — <ProgramFiles>\PostgreSQL\<ver>\bin
    pg_root = os.path.join(program_files, "PostgreSQL")
    if os.path.isdir(pg_root):
        for ver in os.listdir(pg_root):
            bin_dir = os.path.join(pg_root, ver, "bin")
            if os.path.isdir(bin_dir):
                candidates.append(bin_dir)

    # OpenSSL Light — default install path
    for base in (os.path.join(program_files, "OpenSSL-Win64", "bin"),
                 os.path.join(program_files86, "OpenSSL-Win32", "bin")):
        if os.path.isabs(base) and os.path.isdir(base):
            candidates.append(base)

    # Git for Windows — provides git.exe + bash.exe + openssl.exe + curl.exe
    for base in (os.path.join(program_files,   "Git", "cmd"),
                 os.path.join(program_files,   "Git", "bin"),
                 os.path.join(program_files,   "Git", "usr", "bin"),
                 os.path.join(program_files86, "Git", "cmd"),
                 os.path.join(program_files86, "Git", "bin"),
                 os.path.join(program_files86, "Git", "usr", "bin")):
        if os.path.isabs(base) and os.path.isdir(base):
            candidates.append(base)

    # curl standalone winget package — <ProgramFiles>\curl\bin (rare)
    curl_bin = os.path.join(program_files, "curl", "bin")
    if os.path.isabs(curl_bin) and os.path.isdir(curl_bin):
        candidates.append(curl_bin)

    if not candidates:
        return

    current = os.environ.get("PATH", "")
    parts = current.split(os.pathsep) if current else []
    existing_lower = {p.lower().rstrip("\\") for p in parts}
    added = [c for c in candidates if c.lower().rstrip("\\") not in existing_lower]
    if added:
        os.environ["PATH"] = os.pathsep.join(parts + added)


def _install_dependencies_windows(cfg) -> None:
    """Install missing Windows tools via winget (Python, Java, PostgreSQL, OpenSSL, curl, Git)."""
    print_header("Installing Windows Dependencies")
    _refresh_windows_path()

    has_winget = bool(shutil.which("winget"))
    if has_winget:
        # ── Python 3 ──────────────────────────────────────────────────────────
        # On Windows, Python may be installed as `python.exe` only (no `python3.exe`),
        # so probe both before deciding to install.
        if not (shutil.which("python") or shutil.which("python3")):
            print_step(1, "Installing Python 3...")
            r = subprocess.run(
                ["winget", "install", "--id", "Python.Python.3.12",
                "--accept-package-agreements", "--accept-source-agreements", "--silent"],
                capture_output=False,
            )
            if r.returncode == 0:
                print_success("Python 3 installed")
                _refresh_windows_path()
            else:
                print_warning("Python 3 install failed or was already present — check manually")
        else:
            print_success("Python 3 already in PATH")

        # ── Java 17+ ──────────────────────────────────────────────────────────
        java_ok, java_ver = _check_java_version()
        if not java_ok:
            print_step(2, "Installing Java 17 (Microsoft OpenJDK)...")
            r = subprocess.run(
                ["winget", "install", "--id", "Microsoft.OpenJDK.17",
                "--accept-package-agreements", "--accept-source-agreements", "--silent"],
                capture_output=False,
            )
            if r.returncode == 0:
                print_success("Java 17 installed")
                _refresh_windows_path()
            else:
                print_warning("Java 17 install failed or was already present — check manually")
        else:
            print_success(f"Java already OK: {java_ver}")

        # ── PostgreSQL ────────────────────────────────────────────────────────
        if not shutil.which("psql"):
            print_step(3, "Installing PostgreSQL...")
            print_info("The PostgreSQL installer will run — follow the prompts.")
            print_info("Set the postgres superuser password to match the")
            print_info("PG_SUPERUSER_PASSWORD value in your BKPS configuration.")
            r = subprocess.run(
                ["winget", "install", "--id", "PostgreSQL.PostgreSQL",
                "--accept-package-agreements", "--accept-source-agreements"],
                capture_output=False,
            )
            if r.returncode == 0:
                print_success("PostgreSQL installed")
                _refresh_windows_path()
                # Start the service — installer creates a versioned service name
                for svc in ("postgresql-x64-18", "postgresql-x64-17",
                            "postgresql-x64-16", "postgresql-x64-15",
                            "postgresql"):
                    started = subprocess.run(
                        ["net", "start", svc], capture_output=True,
                    )
                    if started.returncode == 0:
                        print_success(f"PostgreSQL service started: {svc}")
                        break
            else:
                print_warning("PostgreSQL install failed or was already present — check manually")
        else:
            print_success("PostgreSQL already in PATH")

        # ── OpenSSL ───────────────────────────────────────────────────────────
        # Git for Windows (already installed) ships openssl.exe — reuse it if available
        if not shutil.which("openssl"):
            print_step(4, "Installing OpenSSL (Light)...")
            r = subprocess.run(
                ["winget", "install", "--id", "ShiningLight.OpenSSL.Light",
                "--accept-package-agreements", "--accept-source-agreements", "--silent"],
                capture_output=False,
            )
            if r.returncode == 0:
                print_success("OpenSSL installed")
                _refresh_windows_path()
            else:
                print_warning("OpenSSL install failed — check manually")
        else:
            print_success("OpenSSL already in PATH")

        # ── curl ──────────────────────────────────────────────────────────────
        # Windows 10 1803+ ships curl.exe in System32; only auto-install if absent.
        if not shutil.which("curl"):
            print_step(5, "Installing curl...")
            r = subprocess.run(
                ["winget", "install", "--id", "cURL.cURL",
                "--accept-package-agreements", "--accept-source-agreements", "--silent"],
                capture_output=False,
            )
            if r.returncode == 0:
                print_success("curl installed")
                _refresh_windows_path()
            else:
                print_warning("curl install failed — check manually")
        else:
            print_success("curl already in PATH")

        # Gradle is not installed system-wide by the GUI on Windows; the BKPS
        # repository's gradlew.bat wrapper handles Gradle provisioning itself.

        # ── git (Git for Windows also provides bash) ──────────────────────────
        # Probe git directly rather than bash — a machine with WSL bash on PATH
        # could otherwise silently skip a missing git install.
        if not shutil.which("git"):
            print_step(6, "Installing Git for Windows (provides git + bash)...")
            r = subprocess.run(
                ["winget", "install", "--id", "Git.Git",
                "--accept-package-agreements", "--accept-source-agreements", "--silent"],
                capture_output=False,
            )
            if r.returncode == 0:
                print_success("Git for Windows installed (git + bash available)")
                _refresh_windows_path()
            else:
                print_warning("Git install failed — install manually from https://git-scm.com/")
        else:
            print_success("git already in PATH")

        # Native build prerequisites are owned by the cloned repository. The
        # current Windows repository script uses Visual Studio C++ tools; v2
        # discovers them when the source-build phase begins but does not install
        # or patch them here.

        # keytool ships with the Java 17 install (bin/keytool.exe); no separate
        # winget package required.  Python packages are installed at the top of
        # install_dependencies() before this helper runs.

        # ── Test truststore ───────────────────────────────────────────────────
        # Mirror the Linux flow: keytool is available via the freshly-installed
        # Java 17, so create the dummy truststore used by BKPS integration tests.
        print_info("\nChecking test truststore...")
        _create_dummy_truststore()

        print_success("\nDependency setup complete")
    else:
        print_error("Winget not found - dependency setup failed")
        print_info("Please install the following dependencies manually:")
        print_info("  Python 3:   winget install Python.Python.3.12")
        print_info("              or: https://www.python.org/downloads/windows/")
        print_info("  Java 17+:   winget install Microsoft.OpenJDK.17")
        print_info("              or: https://adoptium.net/")
        print_info("  PostgreSQL: winget install PostgreSQL.PostgreSQL")
        print_info("              or: https://www.postgresql.org/download/windows/")
        print_info("  OpenSSL:    winget install ShiningLight.OpenSSL.Light")
        print_info("              or: https://slproweb.com/products/Win32OpenSSL.html")
        print_info("  curl:       winget install cURL.cURL")
        print_info("  Git:        winget install Git.Git")
        print_info("  Quartus Prime tools: https://www.intel.com/content/www/us/en/software/programmable/quartus-prime/download.html")


def _install_system_packages(packages: list, distro_family: str) -> None:
    """Install system packages via apt, dnf/yum, or print manual instructions.

    Args:
        packages: Package names to install.
        distro_family: ``'debian'``, ``'rhel'``, or ``'unknown'``.
    """
    if distro_family == "rhel":
        mgr = shutil.which("dnf") and "dnf" or "yum"
        print_info(f"\nInstalling {len(packages)} packages via {mgr}...")
        run(["sudo", mgr, "makecache", "--refresh"], check=False)
        stream(["sudo", mgr, "install", "-y"] + packages)
    elif distro_family == "debian":
        print_info(f"\nInstalling {len(packages)} packages via apt...")
        run(["sudo", "apt", "update"], check=False)
        stream(["sudo", "apt", "install", "-y"] + packages)
    else:
        print_warning(f"Unknown distribution — cannot install packages automatically.")
        print_info("Please install the following packages manually:")
        for pkg in packages:
            print_info(f"  {pkg}")


def _ensure_postgresql_rhel() -> None:
    """Initialise the PostgreSQL data cluster on RHEL/CentOS/Fedora if needed."""
    # Common RHEL PostgreSQL data directories (versioned and unversioned)
    pg_data_candidates = [
        "/var/lib/pgsql/data",
        "/var/lib/pgsql/18/data",
        "/var/lib/pgsql/17/data",
        "/var/lib/pgsql/16/data",
        "/var/lib/pgsql/15/data",
        "/var/lib/pgsql/14/data",
        "/var/lib/pgsql/13/data",
    ]
    for pg_data in pg_data_candidates:
        if os.path.isdir(pg_data) and os.listdir(pg_data):
            print_success("PostgreSQL data cluster already initialised")
            return

    print_info("Initialising PostgreSQL data cluster (required on RHEL before first start)...")
    result = subprocess.run(
        ["sudo", "postgresql-setup", "--initdb"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        print_success("PostgreSQL data cluster initialised")
    else:
        # Newer RHEL variants use initdb directly
        print_warning(f"postgresql-setup --initdb failed: {result.stderr.strip()}")
        print_info("Trying fallback: sudo -u postgres initdb -D /var/lib/pgsql/data")
        result2 = subprocess.run(
            ["sudo", "-u", "postgres", "initdb", "-D", "/var/lib/pgsql/data"],
            capture_output=True, text=True,
        )
        if result2.returncode == 0:
            print_success("PostgreSQL data cluster initialised via initdb")
        else:
            print_warning("Could not initialise PostgreSQL automatically.")
            print_info("Run manually: sudo postgresql-setup --initdb")
            print_info("Then:         sudo systemctl enable --now postgresql")
            return

    # Enable and start the service
    print_info("Enabling and starting PostgreSQL service...")
    subprocess.run(["sudo", "systemctl", "enable", "postgresql"], capture_output=True)
    result3 = subprocess.run(
        ["sudo", "systemctl", "start", "postgresql"],
        capture_output=True, text=True,
    )
    if result3.returncode == 0:
        print_success("PostgreSQL service started")
    else:
        print_warning("Could not start PostgreSQL automatically.")
        print_info("Run manually: sudo systemctl start postgresql")


def _tool_version(tool: str) -> str:
    """Return the first line of a tool's version output, or '' on failure.

    Args:
        tool: Command name as it appears in PATH.
    """
    flag_map = {
        "python3":     ["--version"],
        "java":        ["-version"],
        "psql":        ["--version"],
        "openssl":     ["version"],
        "jq":          ["--version"],
        "aria2c":      ["--version"],
        "curl":        ["--version"],
        "git":         ["--version"],
        "quartus_pgm": ["--version"],
    }
    flags = flag_map.get(tool, ["--version"])
    try:
        result = subprocess.run(
            [tool] + flags,
            capture_output=True, text=True, timeout=5
        )
        out = (result.stdout + result.stderr).strip().splitlines()
        return out[0] if out else ""
    except Exception:
        return ""


def _python_import_ok(import_name: str) -> bool:
    """Return True if *import_name* can be imported in a subprocess.

    Args:
        import_name: Module name to test, e.g. ``'cryptography'``.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-c", f"import {import_name}"],
            capture_output=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def _check_java_version() -> tuple:
    """Return (ok, version_string) for the installed Java vs MINIMUM_JAVA_VERSION."""
    try:
        result = subprocess.run(
            ["java", "-version"],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout + result.stderr
        # Java version can be in format: "17.0.1" or "1.8.0_xxx"
        match = re.search(r'version "([^"]+)"', output)
        if not match:
            return (False, "unknown")

        version_str = match.group(1)
        # Parse version - handle both "17.0.1" and "1.8.0_xxx" formats
        parts = version_str.split(".")
        try:
            major = int(parts[0])
            # Handle old 1.x format (1.8 = Java 8)
            if major == 1 and len(parts) > 1:
                major = int(parts[1])
            minor = int(parts[1].split("_")[0].split("-")[0]) if len(parts) > 1 else 0
            patch = int(parts[2].split("_")[0].split("-")[0]) if len(parts) > 2 else 0

            current = (major, minor, patch)
            ok = current >= MINIMUM_JAVA_VERSION
            return (ok, version_str)
        except (ValueError, IndexError):
            return (False, version_str)
    except Exception:
        return (False, "not found")


def _create_dummy_truststore() -> bool:
    """Create a dummy PKCS12 truststore in the system temp directory for integration tests."""
    if not command_exists("keytool"):
        print_warning("keytool not found, skipping truststore creation")
        return False

    # Check if truststore already exists with the dummy alias
    if os.path.isfile(TRUSTSTORE_PATH):
        result = subprocess.run(
            ["keytool", "-list", "-keystore", TRUSTSTORE_PATH,
             "-storepass", TRUSTSTORE_PASSWORD, "-alias", "dummy"],
            capture_output=True
        )
        if result.returncode == 0:
            print_success(f"Truststore already exists: {TRUSTSTORE_PATH}")
            return True

    # Create dummy truststore
    print_info(f"Creating dummy truststore at {TRUSTSTORE_PATH}...")
    result = subprocess.run([
        "keytool", "-genkey", "-keyalg", "RSA",
        "-keystore", TRUSTSTORE_PATH,
        "-keysize", "2048",
        "-keypass", TRUSTSTORE_PASSWORD,
        "-storepass", TRUSTSTORE_PASSWORD,
        "-dname", "CN=Developer, OU=Department, O=Company, L=City, ST=State, C=CA",
        "-alias", "dummy"
    ], capture_output=True)

    if result.returncode == 0:
        print_success(f"Created test truststore: {TRUSTSTORE_PATH}")
        return True
    else:
        print_warning(f"Failed to create truststore: {result.stderr.decode()}")
        return False



def _install_softhsm(cfg: Config, distro_family: str) -> None:
    """Install SoftHSM2 + PKCS#11 tools and create softhsm2.conf if missing."""

    # ── 1. Install system packages ────────────────────────────────────────
    APT_PKGS = ["softhsm2", "opensc", "pcscd", "libpcsclite-dev"]
    DNF_PKGS = ["softhsm", "opensc", "pcsc-lite", "pcsc-lite-devel"]

    missing = []
    if distro_family == "rhel":
        for pkg in DNF_PKGS:
            tool = "softhsm2-util" if "softhsm" in pkg else "pkcs11-tool"
            if not shutil.which(tool):
                missing.append(pkg)
        if missing:
            _install_system_packages(missing, distro_family)
    else:
        for pkg in APT_PKGS:
            tool = "softhsm2-util" if "softhsm" in pkg else ("pkcs11-tool" if pkg == "opensc" else None)
            if tool is None or not shutil.which(tool):
                missing.append(pkg)
        if missing:
            _install_system_packages(list(dict.fromkeys(missing)), distro_family)

    if not missing:
        print_success("  SoftHSM packages already installed")

    # ── 2. Resolve config path and tokens dir ─────────────────────────────
    conf_path = (cfg.softhsm_conf_path.strip()
                 if getattr(cfg, "softhsm_conf_path", "") else "")
    if not conf_path:
        conf_path = os.path.expanduser("~/.config/softhsm2/softhsm2.conf")

    tokens_dir = (cfg.softhsm_tokens_dir.strip()
                  if getattr(cfg, "softhsm_tokens_dir", "") else "")
    if not tokens_dir:
        tokens_dir = os.path.expanduser("~/softhsm/tokens")

    # ── 3. Create tokens directory ────────────────────────────────────────
    os.makedirs(tokens_dir, exist_ok=True)
    print_success(f"  Token storage dir: {tokens_dir}")

    # ── 4. Create softhsm2.conf if missing ───────────────────────────────
    if os.path.isfile(conf_path):
        print_success(f"  softhsm2.conf already exists: {conf_path}")
    else:
        os.makedirs(os.path.dirname(conf_path), exist_ok=True)
        with open(conf_path, "w") as f:
            f.write(
                "# SoftHSM v2 configuration file\n\n"
                f"directories.tokendir = {tokens_dir}\n"
                "objectstore.backend = file\n\n"
                "# ERROR, WARNING, INFO, DEBUG\n"
                "log.level = ERROR\n\n"
                "# If CKF_REMOVABLE_DEVICE flag should be set\n"
                "slots.removable = false\n\n"
                "# Enable and disable PKCS#11 mechanisms using slots.mechanisms.\n"
                "slots.mechanisms = ALL\n\n"
                "# If the library should reset the state on fork\n"
                "library.reset_on_fork = false\n"
            )
        print_success(f"  softhsm2.conf created: {conf_path}")

    # ── 5. Update cfg so subsequent calls use the correct conf path ───────
    if not getattr(cfg, "softhsm_conf_path", ""):
        cfg.softhsm_conf_path = conf_path
    if not getattr(cfg, "softhsm_tokens_dir", ""):
        cfg.softhsm_tokens_dir = tokens_dir

    print_info(f"  Set SOFTHSM2_CONF={conf_path} for SoftHSM operations")
    print_info("  Persist softhsm_conf_path in the config file (SOFTHSM_CONF_PATH) to keep this after restart")


def _windows_executable(name: str, fallbacks: list[str]) -> str:
    """Resolve a Windows executable from PATH and standard install roots."""
    found = shutil.which(name)
    if found and os.path.isfile(found):
        return os.path.abspath(found)
    for candidate in fallbacks:
        if candidate and os.path.isfile(candidate):
            return os.path.abspath(candidate)
    return ""


def _windows_visual_studio_build_dir() -> str:
    """Locate VC/Auxiliary/Build without embedding an edition or user path."""
    candidates = []
    configured = os.environ.get("BKPS_VS_BUILD_DIR", "").strip().strip('"')
    if configured:
        candidates.append(configured)

    vs_install_dir = os.environ.get("VSINSTALLDIR", "").strip().strip('"')
    if vs_install_dir:
        candidates.append(
            os.path.join(vs_install_dir, "VC", "Auxiliary", "Build")
        )

    program_files_x86 = os.environ.get("ProgramFiles(x86)", "")
    vswhere = os.path.join(
        program_files_x86,
        "Microsoft Visual Studio",
        "Installer",
        "vswhere.exe",
    )
    if os.path.isfile(vswhere):
        try:
            result = subprocess.run(
                [
                    vswhere,
                    "-latest",
                    "-products", "*",
                    "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                    "-property", "installationPath",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            install_root = (result.stdout or "").strip().splitlines()
            if result.returncode == 0 and install_root:
                candidates.append(
                    os.path.join(
                        install_root[-1], "VC", "Auxiliary", "Build"
                    )
                )
        except OSError:
            pass

    for candidate in dict.fromkeys(filter(None, candidates)):
        build_dir = os.path.abspath(candidate)
        if all(
            os.path.isfile(os.path.join(build_dir, script))
            for script in ("vcvarsall.bat", "vcvarsamd64_x86.bat")
        ):
            return build_dir
    return ""


def _windows_reg_query_works() -> bool:
    """Return whether native ``reg query`` can read the Windows SDK root.

    Some managed Windows installations allow PowerShell registry reads but
    block reg.exe through policy. Visual Studio's vcvars scripts use reg.exe,
    so that policy otherwise leaves the SDK include and library paths unset.
    """
    reg_exe = _windows_executable(
        "reg.exe",
        [
            os.path.join(
                os.environ.get("SystemRoot", r"C:\Windows"),
                "System32",
                "reg.exe",
            )
        ],
    )
    if not reg_exe:
        return False
    try:
        result = subprocess.run(
            [
                reg_exe,
                "query",
                r"HKLM\SOFTWARE\Microsoft\Windows Kits\Installed Roots",
                "/v",
                "KitsRoot10",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return False
    return result.returncode == 0 and "KitsRoot10" in (result.stdout or "")


def _windows_registry_query_shim_dir() -> str:
    """Return the bundled read-only ``reg query`` shim directory."""
    shim_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "windows_cmd_shims")
    required = ("reg.cmd", "reg_query.ps1")
    if all(os.path.isfile(os.path.join(shim_dir, name)) for name in required):
        return shim_dir
    return ""


def _selected_build_options(cfg: Config) -> tuple[str, bool]:
    """Return the validated repository build mode and programmer selection."""
    mode = str(getattr(cfg, "bkps_build_mode", "full") or "full").strip().lower()
    if mode not in {"full", "bkp_only"}:
        raise RuntimeError(
            f"Unsupported BKPS build mode {mode!r}; expected 'full' or 'bkp_only'."
        )
    return mode, bool(getattr(cfg, "include_bkp_programmer", True))


# Native packages consumed only by the BKP Programmer build, so a build that
# excludes the programmer must not report them as missing prerequisites. The
# repository scripts skip them on their own via --bkp-only.
_PROGRAMMER_ONLY_DEPENDENCIES = ("BOOST", "LIBCURL", "GTEST")


def _container_build_components(mode: str, include_programmer: bool) -> list[str]:
    """Return the selected artifacts that the repository builds in containers.

    ``build_ubuntu.sh`` calls ``build_fcsserver`` for every full build and
    ``build_bkpprogrammer`` whenever the programmer is included, so the two
    selections require Docker independently of each other.
    """
    components = []
    if mode == "full":
        components.append("FCSServer")
    if include_programmer:
        components.append("BKP Programmer")
    return components


def _selected_container_components(cfg: Config) -> list[str]:
    """Return the container-built components for the current build selection."""
    try:
        mode, include_programmer = _selected_build_options(cfg)
    except RuntimeError:
        # An invalid selection is reported by the build step itself.
        return []
    return _container_build_components(mode, include_programmer)


def _docker_ps(argv: list[str]) -> tuple[bool, str]:
    """Run a ``docker ps`` probe with stdin closed so nothing can prompt."""
    result = run(argv, capture=True, check=False, input_text="")
    if result.returncode == 0:
        return True, ""
    detail = (result.stderr or result.stdout or "").strip().splitlines()
    return False, detail[-1].strip() if detail else "'docker ps' failed"


def _docker_build_status() -> tuple[str, str]:
    """Classify container-build readiness as ready, group-shim, or unusable.

    ``group-shim`` means the daemon works but only for a process that carries
    the ``docker`` group, which is the state right after the user is added to
    that group and before the next login.
    """
    if not command_exists("docker"):
        return "unusable", "the docker client is not installed"
    usable, detail = _docker_ps(["docker", "ps"])
    if usable:
        return "ready", ""
    if command_exists("sg"):
        shimmed, _ = _docker_ps(["sg", "docker", "-c", "docker ps"])
        if shimmed:
            return "group-shim", detail
    return "unusable", detail


def _in_docker_group(user: str) -> bool:
    """Report whether the group database already lists the user in ``docker``."""
    try:
        import grp

        return user in grp.getgrnam("docker").gr_mem
    except (ImportError, KeyError):
        return False


def _ensure_container_engine(cfg: Config, distro_family: str) -> bool:
    """Install, start, and grant access to the engine the build needs.

    The repository script installs Docker itself through ``curl | sudo sh``.
    This provisions it from the distribution's own packages instead, using the
    same sudo credentials as the rest of the dependency phase.
    """
    state, detail = _docker_build_status()
    if state == "ready":
        print_success("Container engine is ready")
        return True
    if state == "group-shim":
        print_success(
            "Container engine is installed; the build will run with the "
            "docker group applied to this session"
        )
        return True

    if distro_family not in {"debian", "rhel"}:
        print_error(f"Container engine is not usable: {detail}")
        print_info(
            "This distribution is not recognised, so install a Docker engine "
            "manually, or select the BKP-only build without BKP Programmer."
        )
        return False

    from bkps_database import authenticate_sudo

    authenticate_sudo(cfg)

    if not command_exists("docker"):
        package = "docker.io" if distro_family == "debian" else "docker"
        print_info(f"Installing the container engine package: {package}")
        _install_system_packages([package], distro_family)
        if not command_exists("docker"):
            print_error(f"Package {package} did not provide a docker client")
            print_info(
                "Install a Docker engine for this distribution manually, or "
                "select the BKP-only build without BKP Programmer."
            )
            return False

    print_info("Enabling and starting the container engine service...")
    started = run(
        ["sudo", "systemctl", "enable", "--now", "docker"],
        capture=True, check=False,
    )
    if started.returncode != 0:
        run(["sudo", "service", "docker", "start"], capture=True, check=False)

    user = getpass.getuser()
    if not _in_docker_group(user):
        print_info(f"Granting {user} access to the container engine socket...")
        run(["sudo", "usermod", "-aG", "docker", user], capture=True, check=False)

    state, detail = _docker_build_status()
    if state == "ready":
        print_success("Container engine installed and ready")
        return True
    if state == "group-shim":
        print_success("Container engine installed")
        print_info(
            f"{user} was just added to the docker group. A new login session "
            "would normally be required, so the build runs its script with "
            "that group applied instead."
        )
        return True

    print_error(f"Container engine is still not usable: {detail}")
    print_info(
        "Check 'systemctl status docker', or select the BKP-only build "
        "without BKP Programmer to build nothing in a container."
    )
    return False


def _linux_docker_prerequisite(cfg: Config, mode: str, include_programmer: bool) -> str:
    """Return the container-build state for a selection, provisioning if needed.

    Returns ``ready``, ``group-shim``, or ``unusable``; ``ready`` is also
    returned when the selection builds nothing in a container.
    """
    components = _container_build_components(mode, include_programmer)
    if not components:
        return "ready"

    state, detail = _docker_build_status()
    if state != "unusable":
        return state

    print_info(
        f"{' and '.join(components)} build inside Docker containers; "
        f"the container engine is not usable yet: {detail}"
    )
    if not _ensure_container_engine(cfg, _detect_distro()):
        return "unusable"
    return _docker_build_status()[0]


def _repository_build_selection_args(mode: str, include_programmer: bool) -> list[str]:
    """Map config ``BKPS_BUILD_MODE`` / ``INCLUDE_BKP_PROGRAMMER`` to a script flag.

    The repository scripts take one selection flag; a full build always
    includes BKP Programmer.
    """
    if mode == "full":
        return ["--full"]
    if include_programmer:
        return ["--bkp-with-bkpprogrammer"]
    return ["--bkp-only"]


def _linux_build_selection_args(mode: str, include_programmer: bool) -> list[str]:
    """Alias kept for existing Linux callers and tests."""
    return _repository_build_selection_args(mode, include_programmer)


def _linux_build_invocation(
    script_path: str,
    docker_state: str,
    extra_args: list[str] | None = None,
) -> list[str]:
    """Return the argv that runs a build script with container access."""
    extra = list(extra_args or [])
    if docker_state == "group-shim":
        quoted = " ".join(
            [shlex.quote(script_path), *(shlex.quote(arg) for arg in extra)]
        )
        return ["sg", "docker", "-c", f"bash {quoted}"]
    return ["bash", script_path, *extra]


def _docker_prompt_answer(components: list[str]) -> str:
    """Answer the script's ``[y/N]`` prompt for Docker-dependent builds.

    ``prompt_docker_required`` gates ``build_fcsserver`` and
    ``build_bkpprogrammer`` behind this answer, so declining it silently drops
    both from the output. The engine is already provisioned by the time the
    script runs, so answering yes never reaches its ``curl | sudo sh`` path.
    """
    return "y\n" if components else "n\n"


def _linux_build_script_unchanged(build_script: str, original: str) -> bool:
    """Report whether the repository build script survived the build unchanged.

    The Windows flow makes the same check. Selected builds run from a temporary
    copy, so any difference here means the repository-owned script was edited
    during the build and its output can no longer be trusted.
    """
    try:
        current = Path(build_script).read_text(encoding="utf-8")
    except OSError as exc:
        print_error(f"Could not re-read {build_script} after the build: {exc}")
        return False
    if current != original:
        print_error(
            f"Repository build script changed during the build: {build_script}; "
            "refusing to continue."
        )
        return False
    return True


def build_windows_repository(cfg: Config, repo_dir: str = None) -> bool:
    """Run the cloned repository Windows build script unchanged."""
    repo_dir = os.path.abspath(repo_dir or cfg.bkps_repo_dir)
    batch_path = os.path.join(repo_dir, "build-dependencies.bat")
    if not os.path.isfile(batch_path):
        print_error(
            "Repository Windows build script is missing: " + batch_path
        )
        return False

    vs_build_dir = _windows_visual_studio_build_dir()
    if not vs_build_dir:
        print_error(
            "The cloned repository's build-dependencies.bat requires Visual "
            "Studio C++ build tools. Run setup.bat --ensure-msvc to install "
            "the standalone Build Tools components, or set BKPS_VS_BUILD_DIR "
            "to the VC\\Auxiliary\\Build directory containing vcvarsall.bat "
            "and vcvarsamd64_x86.bat. The full Visual Studio IDE is not "
            "required."
        )
        return False

    cmd_exe = _windows_executable(
        "cmd.exe",
        [
            os.environ.get("COMSPEC", ""),
            os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                         "System32", "cmd.exe"),
        ],
    )
    if not cmd_exe:
        print_error("Windows command processor cmd.exe was not found")
        return False

    version = (getattr(cfg, "bkps_version", "") or "").strip() or "1.0.0"
    original_script = Path(batch_path).read_bytes()
    original_hash = hashlib.sha256(original_script).hexdigest()
    mode, include_programmer = _selected_build_options(cfg)
    selection_args = _repository_build_selection_args(mode, include_programmer)

    print_info("Repository Windows script SHA-256: " + original_hash)
    print_info(f"Using repository-owned Windows build script: {batch_path}")
    print_info(
        f"Build selection: {mode}; BKP Programmer: "
        f"{'included' if include_programmer else 'skipped'}"
    )
    print_info("Script arguments: " + " ".join(selection_args))
    build_env = None
    if not _windows_reg_query_works():
        shim_dir = _windows_registry_query_shim_dir()
        if not shim_dir:
            print_error(
                "Windows registry queries are blocked and the bundled read-only "
                "REG QUERY compatibility shim is missing. Visual Studio cannot "
                "discover the installed Windows SDK."
            )
            return False
        print_warning(
            "Native reg.exe queries are blocked by Windows policy. Using the "
            "BKPS read-only registry-query shim for Visual Studio SDK discovery."
        )
        build_env = {
            "PATH": shim_dir + os.pathsep + os.environ.get("PATH", ""),
        }

    command = [
        cmd_exe, "/d", "/s", "/c", "call", batch_path,
        vs_build_dir, version, *selection_args,
    ]
    result = stream(command, cwd=repo_dir, env=build_env)

    if Path(batch_path).read_bytes() != original_script:
        print_error(
            "Repository build-dependencies.bat changed during the build; "
            "refusing to continue."
        )
        return False
    if result != 0:
        print_error(f"Repository Windows build failed with exit code {result}")
        return False
    print_success("Repository Windows build completed")
    return True


def build_native_dependencies(cfg: Config, repo_dir: str = None, force: bool = False) -> bool:
    """Run the platform-native repository dependency build flow.

    Args:
        repo_dir: Repo clone to build in; defaults to ``cfg.bkps_repo_dir``.
    """
    print_header("Building Native Dependencies")

    # Find repo directory
    if repo_dir is None:
        repo_dir = cfg.bkps_repo_dir

    # On Windows, the cloned repository script owns dependency, wrapper, JAR,
    # and SQL generation. Run that script unchanged; selection is passed as
    # ``--full`` / ``--bkp-with-bkpprogrammer`` / ``--bkp-only``.
    if _detect_distro() == "windows":
        return build_windows_repository(cfg, repo_dir=repo_dir)

    # Check which dependencies the Config tab selection actually requires.
    mode, include_programmer = _selected_build_options(cfg)
    status = check_native_dependencies(repo_dir, include_programmer=include_programmer)
    all_built = all(status.values())

    if all_built:
        print_success("All native dependencies already built:")
        for lib, built in status.items():
            print_success(f"  {lib}: OK")
        return True

    # Show which are missing
    missing = [lib for lib, built in status.items() if not built]
    present = [lib for lib, built in status.items() if built]

    if present:
        print_info("Already built:")
        for lib in present:
            print_success(f"  {lib}: OK")

    if missing:
        print_info("Need to build:")
        for lib in missing:
            print_warning(f"  {lib}: MISSING")

    build_script = os.path.join(repo_dir, "build_ubuntu.sh")
    if not os.path.isfile(build_script):
        print_error(f"Repository Linux build script not found: {build_script}")
        return False

    docker_state = _linux_docker_prerequisite(cfg, mode, include_programmer)
    if docker_state == "unusable":
        return False
    container_components = _container_build_components(mode, include_programmer)
    docker_answer = _docker_prompt_answer(container_components)

    # Report the missing native inputs before invoking the repository flow.
    print_info("")
    print_info("Building BKPS JAR, SQL schema, and native libraries from source...")
    # Versions come from the checked-out release, not from this tool, so only
    # the package names are reported here.
    for lib in missing:
        print_info(f"  {lib}")
    print_info("")
    print_warning("This may take 10-30 minutes depending on your system...")

    original_cwd = os.getcwd()
    try:
        os.chdir(repo_dir)

        # Use the cloned repository's script unchanged. Selection comes from
        # the config file (BKPS_BUILD_MODE) and is passed as a
        # ``build_ubuntu.sh`` flag (--full / --bkp-with-bkpprogrammer /
        # --bkp-only). Do not rewrite a copy.
        version = (getattr(cfg, "bkps_version", "") or "").strip() or "0.0.1"
        gradle_opts = os.environ.get("GRADLE_OPTS", "").strip()
        # The script's own gradlew calls carry no flags of ours, and they run on
        # a PTY, which makes Gradle pick its rich console and emit cursor codes.
        for option in ("-Dorg.gradle.daemon=false", "-Dorg.gradle.console=plain"):
            if option not in gradle_opts.split():
                gradle_opts = " ".join(filter(None, [gradle_opts, option]))
        build_env = {
            "BUILD_VERSION": version,
            "GRADLE_OPTS": gradle_opts,
        }
        mode, include_programmer = _selected_build_options(cfg)
        original_script = Path(build_script).read_text(encoding="utf-8")
        selection_args = _linux_build_selection_args(mode, include_programmer)
        print_info(f"Using repository-owned Linux build script: {build_script}")
        print_info(
            f"Build selection: {mode}; BKP Programmer: "
            f"{'included' if include_programmer else 'skipped'}"
        )
        print_info("Script arguments: " + " ".join(selection_args))
        if mode == "full" and include_programmer:
            print_info(
                "The full build also runs every module's unit, integration, "
                "and sealing tests, so expect a longer run than BKP-only."
            )
        print_info(
            "Container-built artifacts requested: "
            + (", ".join(container_components) or "none")
        )
        result = stream(
            _linux_build_invocation(build_script, docker_state, selection_args),
            env=build_env,
            input_text=docker_answer,
        )
        if not _linux_build_script_unchanged(build_script, original_script):
            return False
        if result == 0:
            print_success("Native dependencies built successfully!")
            return True
        print_error("Native dependency build failed")
        return False
    except Exception as e:
        print_error(f"Build error: {e}")
        return False
    finally:
        os.chdir(original_cwd)


def check_native_dependencies(
    repo_dir: str, include_programmer: bool = True
) -> dict:
    """Return {library_name: already_built} for the required native packages.

    Args:
        repo_dir: BKPS repo clone whose ``dependencies/`` directory is inspected.
        include_programmer: When False, Boost, libcurl, and GoogleTest are
            omitted because only the BKP Programmer build consumes them.
    """
    deps_dir = os.path.join(repo_dir, "dependencies")
    distro_family = _detect_distro()
    is_windows = (distro_family == 'windows')
    libraries = ["openssl", "boost", "libcurl", "gtest", "libspdm"]
    if not include_programmer:
        libraries = [
            lib for lib in libraries
            if lib.upper() not in _PROGRAMMER_ONLY_DEPENDENCIES
        ]
    status = {}
    for lib in libraries:
        folder_name = lib
        if is_windows:
            ver_key = f"{lib.upper()}_VERSION"
            folder_name = f"{lib}-{NATIVE_LIB_VERSIONS[ver_key]}-windows-x64.zip"
            lib_path = os.path.join(deps_dir, folder_name)
            status[lib] = os.path.isfile(lib_path)
        else:
            lib_path = os.path.join(deps_dir, folder_name)
            status[lib] = bool(os.path.isdir(lib_path) and os.listdir(lib_path))

    return status

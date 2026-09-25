#!/usr/bin/env python3
"""
setup.py - First-time setup for BKPS Demo Automation Tool.

Run this script on a new system to install Python dependencies
and verify system tools are available.

Usage:
    python setup.py [--install] [--check-only]

Options:
    --install      Install Python packages (default if no options given)
    --check-only   Only check dependencies, don't install anything
"""

import subprocess
import sys
import os
import shutil

# Minimum Python version
MIN_PYTHON = (3, 8)

# Required system tools
SYSTEM_TOOLS = {
    "java":        ("Java JDK/JRE", "https://adoptium.net/"),
    "psql":        ("PostgreSQL", "https://www.postgresql.org/download/"),
    "quartus_pgm": ("Quartus Prime", "https://www.intel.com/content/www/us/en/products/details/fpga/development-tools/quartus-prime.html"),
    "openssl":     ("OpenSSL", "https://www.openssl.org/"),
    "wget":        ("wget", "apt install wget / brew install wget / choco install wget"),
    "curl":        ("curl", "Usually pre-installed; apt install curl / choco install curl"),
    "git":         ("Git", "https://git-scm.com/downloads"),
    "jq":          ("jq", "apt install jq / brew install jq / choco install jq"),
}

OPTIONAL_TOOLS = {
    "nc": ("netcat", "Optional - for port checks"),
}


def print_ok(msg):
    print(f"  ✓ {msg}")


def print_fail(msg):
    print(f"  ✗ {msg}")


def print_warn(msg):
    print(f"  ? {msg}")


def check_python_version():
    """Check Python version meets minimum requirement."""
    print("\n[1/4] Checking Python version...")
    current = sys.version_info[:2]
    if current >= MIN_PYTHON:
        print_ok(f"Python {current[0]}.{current[1]} (>= {MIN_PYTHON[0]}.{MIN_PYTHON[1]} required)")
        return True
    else:
        print_fail(f"Python {current[0]}.{current[1]} - need {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+")
        return False


def check_system_tools():
    """Check required system tools are installed."""
    print("\n[2/4] Checking system tools...")
    missing = []
    
    for tool, (name, install_hint) in SYSTEM_TOOLS.items():
        if shutil.which(tool):
            print_ok(f"{name} ({tool})")
        else:
            print_fail(f"{name} ({tool}) - NOT FOUND")
            missing.append((tool, name, install_hint))
    
    for tool, (name, note) in OPTIONAL_TOOLS.items():
        if shutil.which(tool):
            print_ok(f"{name} ({tool}) - optional")
        else:
            print_warn(f"{name} ({tool}) - {note}")
    
    return missing


def install_python_packages():
    """Install Python packages from requirements.txt."""
    print("\n[3/4] Installing Python packages...")
    
    req_file = os.path.join(os.path.dirname(__file__), "requirements.txt")
    if not os.path.exists(req_file):
        print_fail("requirements.txt not found!")
        return False
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", req_file,
            "--quiet", "--disable-pip-version-check"
        ])
        print_ok("All Python packages installed")
        return True
    except subprocess.CalledProcessError as e:
        print_fail(f"pip install failed: {e}")
        return False


def check_python_packages():
    """Verify Python packages can be imported."""
    print("\n[4/4] Verifying Python packages...")
    
    packages = [
        ("PySide6", "PySide6 (GUI framework)"),
        ("cryptography", "cryptography"),
        ("OpenSSL", "pyOpenSSL"),
        ("Crypto", "pycryptodome"),
        ("docopt", "docopt (CLI)"),
        ("requests", "requests (admin-tools runner.py)"),
        ("packaging", "packaging (admin-tools runner.py)"),
        ("psycopg2", "psycopg2-binary"),
    ]
    
    all_ok = True
    for import_name, display_name in packages:
        try:
            __import__(import_name)
            print_ok(display_name)
        except ImportError:
            print_fail(f"{display_name} - NOT INSTALLED")
            all_ok = False
    
    return all_ok


def print_missing_tools_help(missing):
    """Print installation instructions for missing system tools."""
    if not missing:
        return
    
    print("\n" + "=" * 60)
    print("MISSING SYSTEM TOOLS - Install these before using the tool:")
    print("=" * 60)
    
    for tool, name, hint in missing:
        print(f"\n  {name} ({tool}):")
        print(f"    {hint}")


def main():
    print("=" * 60)
    print("  BKPS Demo Automation Tool - Setup")
    print("=" * 60)
    
    check_only = "--check-only" in sys.argv
    
    # Step 1: Python version
    if not check_python_version():
        print("\nPlease upgrade Python and try again.")
        sys.exit(1)
    
    # Step 2: System tools
    missing_tools = check_system_tools()
    
    # Step 3: Install or check Python packages
    if check_only:
        print("\n[3/4] Skipping installation (--check-only)...")
        packages_ok = check_python_packages()
    else:
        packages_ok = install_python_packages()
        if packages_ok:
            packages_ok = check_python_packages()
    
    # Summary
    print("\n" + "=" * 60)
    if missing_tools:
        print("  STATUS: System tools missing (see below)")
        print_missing_tools_help(missing_tools)
    elif not packages_ok:
        print("  STATUS: Python packages missing")
        print("\nRun: pip install -r requirements.txt")
    else:
        print("  STATUS: Ready to use!")
        print("\nTo launch the GUI:")
        print(f"    python {os.path.join('gui', 'main.py')}")
        print("\nTo use the CLI:")
        print(f"    python bkps_main.py --config <config_file> <command>")
    print("=" * 60)
    
    sys.exit(0 if (not missing_tools and packages_ok) else 1)


if __name__ == "__main__":
    main()

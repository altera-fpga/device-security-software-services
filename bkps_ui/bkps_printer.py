#!/usr/bin/env python3
"""Colored stdout helpers ([INFO], [PASS], [WARNING], [ERROR]) and confirmation prompts."""

import sys

# ── ANSI color escape codes ──────────────────────────────────────────────────
# NC (No Color) resets attributes; must be appended after every colorized segment.
RED    = '\033[0;31m'
GREEN  = '\033[0;32m'
YELLOW = '\033[1;33m'  # Bold yellow — used for warnings and confirmation prompts
BLUE   = '\033[0;34m'
CYAN   = '\033[0;36m'
NC     = '\033[0m'      # Reset / No Color


# ── Section-level output ─────────────────────────────────────────────────────

def print_header(msg: str) -> None:
    """Print a cyan section header between blue rule lines."""
    print(f"\n{BLUE}================================================================{NC}")
    print(f"{CYAN}{msg}{NC}")
    print(f"{BLUE}================================================================{NC}\n")
    sys.stdout.flush()


def print_step(n, msg: str, parent=None):
    """Print a numbered ``[STEP n]`` progress label.

    Args:
        parent: When set, print ``[STEP parent.n]`` instead of ``[STEP n]``.
    """
    label = f"{parent}.{n}" if parent is not None and parent != "" else n
    print(f"{GREEN}[STEP {label}]{NC} {msg}")
    sys.stdout.flush()
    return label


# ── Severity-tagged message helpers ──────────────────────────────────────────

def print_info(msg: str) -> None:
    """Print a cyan ``[INFO]`` message."""
    print(f"{CYAN}[INFO]{NC} {msg}")
    sys.stdout.flush()


def print_success(msg: str) -> None:
    """Print a green ``[PASS]`` message."""
    print(f"{GREEN}[PASS]{NC} {msg}")
    sys.stdout.flush()


def print_warning(msg: str) -> None:
    """Print a yellow ``[WARNING]`` message."""
    print(f"{YELLOW}[WARNING]{NC} {msg}")
    sys.stdout.flush()


def print_error(msg: str) -> None:
    """Print a red ``[ERROR]`` message to stdout."""
    # Print to stdout instead of stderr so it appears in GUI
    print(f"{RED}[ERROR]{NC} {msg}")
    sys.stdout.flush()


# ── Interactive confirmation ───────────────────────────────────────────────────

def ask_confirmation(prompt: str, yes: bool = False) -> bool:
    """Return True if the user confirms, or immediately if ``yes`` is True.

    Args:
        yes: Auto-accept without prompting (``--yes`` / non-interactive).
    """
    if yes:
        print(f"{YELLOW}{prompt} (y/n):{NC} y  [auto-confirmed via --yes]")
        return True
    if not sys.stdin.isatty():
        raise RuntimeError(
            f"Destructive operation requires confirmation but stdin is not a TTY.\n"
            f"Pass --yes to auto-confirm: {prompt}"
        )
    response = input(f"{YELLOW}{prompt} (y/n):{NC} ").strip()
    if response.lower() != 'y':
        print("Operation cancelled.")
        return False
    return True

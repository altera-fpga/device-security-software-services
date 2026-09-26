#!/usr/bin/env python3
"""BKPS sealing-key, import-key, and context-key operations via runner.py."""

import os
from datetime import datetime
from bkps_config import Config
from bkps_printer import print_header, print_step, print_success, print_warning, print_error, print_info
from bkps_runner import run_runner_tool as _runner
from bkps_audit import audit_log
from bkps_printer import ask_confirmation



# ── Signing key queries ──────────────────────────────────────────────────

def list_signing_keys(cfg: Config) -> None:
    """Print all BKPS signing keys."""
    print_header("List Signing Keys")
    print_info("Fetching signing key list from BKPS...")
    _runner(cfg, "signing-key", "list")
    print_success("Signing key list retrieved")


def list_root_signing_keys(cfg: Config) -> None:
    """Print all BKPS root signing keys."""
    print_header("List Root Signing Keys")
    print_info("Fetching root signing key list from BKPS...")
    _runner(cfg, "root-signing-key", "list")
    print_success("Root signing key list retrieved")


# ── Sealing key operations ───────────────────────────────────────────────

def create_sealing_key(cfg: Config) -> None:
    """Create a new sealing key in BKPS."""
    print_header("Create Sealing Key")
    print_info("Creating sealing key on BKPS...")
    _runner(cfg, "sealing-key", "create")
    print_success("Sealing key created")


def list_sealing_keys(cfg: Config) -> None:
    """Print all sealing keys registered in BKPS."""
    print_header("List Sealing Keys")
    print_info("Fetching sealing key list from BKPS...")
    _runner(cfg, "sealing-key", "list")
    print_success("Sealing key list retrieved")


def rotate_sealing_key(cfg: Config) -> None:
    """Rotate the active sealing key after confirmation."""
    audit_log(cfg, "rotate_sealing_key", outcome="started")
    print_header("Rotate Sealing Key")
    print_warning("This will rotate the sealing key on the security enclave")
    if not ask_confirmation("Rotate the sealing key?", yes=cfg.yes):
        return
    print_info("Rotating sealing key...")
    result = _runner(cfg, "sealing-key", "rotate", capture=True, check=False)
    if result.returncode == 0:
        print_success("Sealing key rotated successfully")
    else:
        print_error("Failed to rotate sealing key")
        raise RuntimeError("Sealing key rotation failed")


# ── Import key operations ──────────────────────────────────────────────────

def create_import_key(cfg: Config) -> None:
    """Create the BKPS service import key pair."""
    print_header("Create Service Import Key")
    print_info("Creating service import key on BKPS...")
    _runner(cfg, "service-import-key", "create")
    print_success("Service import key created")


def delete_import_key(cfg: Config) -> None:
    """Delete the BKPS service import key pair."""
    audit_log(cfg, "delete_import_key", outcome="started")
    print_header("Delete Service Import Key")
    result = _runner(cfg, "service-import-key", "delete", capture=True, check=False)
    if result.returncode == 0:
        print_success("Import key deleted successfully")
    else:
        print_error("Failed to delete import key")
        raise RuntimeError("Import key delete failed")


def get_import_pubkey(cfg: Config) -> None:
    """Export the BKPS service import public key to bkps_import_pubkey.pem."""
    print_header("Get Import Public Key")
    output_file = os.path.join(cfg.quartus_keys_dir, "bkps_import_pubkey.pem")
    print_info(f"Exporting import public key to: {output_file}")

    result = _runner(cfg, "service-import-pub-key", "get", capture=True, check=False)
    if result.returncode == 0 and result.stdout:
        with open(output_file, "w") as f:
            f.write(result.stdout)
        print_success(f"Import public key exported to: {output_file}")
        print(result.stdout)
    else:
        print_error("Failed to export import public key")
        raise RuntimeError("Import pubkey export failed")


# ── Sealing key backup / restore ──────────────────────────────────────────

def backup_sealing_keys(cfg: Config) -> None:
    """Backup sealing keys to a timestamped JSON file in bkps_dir."""
    print_header("Backup Sealing Keys")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(cfg.bkps_dir, f"sealing_key_backup_{timestamp}.json")
    pubkey_file = os.path.join(cfg.quartus_keys_dir, "bkps_import_pubkey.pem")

    if not os.path.isfile(pubkey_file):
        print_info("Import public key not found, fetching...")
        result = _runner(cfg, "service-import-pub-key", "get", capture=True)
        if result.stdout:
            with open(pubkey_file, "w") as f:
                f.write(result.stdout)

    print_info(f"Backing up sealing keys to: {backup_file}")
    result = _runner(cfg, "sealing-key", "backup",
                     "--input", pubkey_file, "--output", backup_file, capture=True, check=False)
    if result.returncode == 0 and os.path.isfile(backup_file):
        print_success(f"Sealing keys backed up to: {backup_file}")
    else:
        print_error("Failed to backup sealing keys")
        raise RuntimeError("Sealing key backup failed")


def restore_sealing_keys(cfg: Config, backup_file: str) -> None:
    """Restore sealing keys from a backup JSON file after confirmation.

    Args:
        backup_file: Path produced by ``backup_sealing_keys``.
    """
    audit_log(cfg, "restore_sealing_keys", details=backup_file, outcome="started")
    print_header("Restore Sealing Keys")

    if not backup_file:
        print_error("Backup file required")
        print_info("Usage: --restore-sealing-keys <BACKUP_FILE>")
        raise ValueError("Backup file required")

    if not os.path.isfile(backup_file):
        print_error(f"Backup file not found: {backup_file}")
        raise FileNotFoundError(backup_file)

    print_warning("This will restore sealing keys from backup")
    if not ask_confirmation("Restore sealing keys from backup?", yes=cfg.yes):
        return

    result = _runner(cfg, "sealing-key", "restore", "--input", backup_file, capture=True, check=False)
    if result.returncode == 0:
        print_success("Sealing keys restored successfully")
    else:
        print_error("Failed to restore sealing keys")
        raise RuntimeError("Sealing key restore failed")


# ── Context key operations ────────────────────────────────────────────────

def rotate_context_key(cfg: Config) -> None:
    """Rotate the BKPS context encryption key."""
    audit_log(cfg, "rotate_context_key", outcome="started")
    print_header("Rotate Context Key")
    print_warning("This will rotate the context encryption key")
    print_info("Rotating context key...")
    result = _runner(cfg, "context-key", "rotate", capture=True, check=False)
    if result.returncode == 0:
        print_success("Context key rotated successfully")
    else:
        print_error("Failed to rotate context key")
        raise RuntimeError("Context key rotation failed")

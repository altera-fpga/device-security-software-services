#!/usr/bin/env python3
"""List, import root, and delete certificates in the BKPS truststore via runner.py."""

import os
import sys
from bkps_config import Config
from bkps_printer import print_header, print_step, print_success, print_warning, print_error, print_info
from bkps_runner import run_runner_tool as _runner
from bkps_audit import audit_log


# ── Public API ───────────────────────────────────────────────────────────────

def list_trusted_certs(cfg: Config) -> None:
    """Print all certificates in the BKPS truststore."""
    print_header("List Trusted Certificates")
    print_info("Fetching trusted certificate list from BKPS...")
    _runner(cfg, "communication", "list")
    print_success("Trusted certificate list retrieved")


def delete_trusted_cert(cfg: Config, cert_alias: str) -> None:
    """Remove a certificate from the BKPS truststore by alias.

    Args:
        cert_alias: Alias from ``list_trusted_certs``; prompted on a TTY if empty.
    """
    audit_log(cfg, "delete_trusted_cert", details=f"alias={cert_alias}", outcome="started")
    print_header("Delete Trusted Certificate")

    if not cert_alias:
        _runner(cfg, "communication", "list")
        if not sys.stdin.isatty():
            raise ValueError(
                "Certificate alias required. Pass it as an argument: "
                "--delete-trusted-cert <ALIAS>"
            )
        cert_alias = input("Enter certificate alias to delete: ").strip()

    if not cert_alias:
        print_error("Invalid certificate alias")
        raise ValueError("Certificate alias required")

    print_warning(f"Deleting trusted certificate: {cert_alias}...")
    print_warning("Note: BKPS will restart automatically after this operation. Wait 30 seconds before next operation.")

    result = _runner(cfg, "communication", "delete", "--id", cert_alias, capture=True, check=False)
    if result.returncode == 0:
        print_success(f"Trusted certificate {cert_alias} deleted successfully")
    else:
        print_error("Failed to delete trusted certificate")
        raise RuntimeError("Certificate delete failed")


def import_root_cert(cfg: Config, cert_file: str) -> None:
    """Import a PEM root CA certificate into the BKPS truststore.

    Args:
        cert_file: Path to the PEM-encoded root CA certificate.
    """
    print_header("Import Root Certificate")

    if not cert_file:
        print_error("Certificate file required")
        print_info("Usage: --import-root-cert <CERT_FILE>")
        raise ValueError("Certificate file required")

    if not os.path.isfile(cert_file):
        print_error(f"Certificate file not found: {cert_file}")
        raise FileNotFoundError(cert_file)

    print_info(f"Importing root certificate from: {cert_file}")
    print_warning("Note: BKPS will restart automatically after this operation. Wait 30 seconds before next operation.")

    result = _runner(cfg, "communication", "import", "--input", cert_file, capture=True, check=False)
    if result.returncode == 0:
        print_success("Root certificate imported successfully")
    else:
        print_error(f"Failed to import root certificate (exit code: {result.returncode})")
        for line in (result.stderr or "").splitlines():
            print(f"    {line}")
        print_info("Troubleshooting:")
        print_info(f"  1. Verify certificate format:")
        print_info(f"     openssl x509 -in {cert_file} -text -noout | head -20")
        print_info("  2. Check BKPS connectivity: --check-health")
        raise RuntimeError("Root cert import failed")

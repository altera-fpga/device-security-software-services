#!/usr/bin/env python3
"""Export logs, check certificate expiry, validate the keystore, and stream bkps.log."""

import os
import time
import subprocess
from datetime import datetime, timezone
from bkps_config import Config
from bkps_printer import print_header, print_step, print_success, print_warning, print_error, print_info
from bkps_runner import run


# ── Log Export ──────────────────────────────────────────────────────────────

def export_logs(cfg: Config, days: int = 7) -> None:
    """Copy recent ``bkps.log`` lines to a timestamped file under ``cfg.home``.

    Args:
        cfg: Config; uses ``bkps_dir`` and ``home``.
        days: Approximate history window; about 1000 lines per day are exported.
    """
    print_header("Export BKPS Logs")

    log_file = os.path.join(cfg.bkps_dir, "logs", "bkps.log")
    if not os.path.isfile(log_file):
        print_error(f"BKPS log file not found: {log_file}")
        raise FileNotFoundError(log_file)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    export_file = os.path.join(cfg.home, f"bkps_logs_export_{timestamp}.log")

    print_info(f"Exporting logs from last {days} days to: {export_file}")

    cutoff = time.time() - (days * 86400)
    mtime = os.path.getmtime(log_file)

    if mtime >= cutoff:
        # File was modified within the window — export relevant lines.
        # Heuristic: ~1000 lines per day of BKPS activity.
        lines_to_tail = days * 1000
        if os.name == 'nt':
            with open(log_file, errors='replace') as f:
                all_lines = f.readlines()
            content = "".join(all_lines[-lines_to_tail:])
        else:
            result = subprocess.run(
                ["tail", "-n", str(lines_to_tail), log_file],
                capture_output=True, text=True
            )
            content = result.stdout
    else:
        print_warning("Log file is older than the requested window; exporting entire file")
        with open(log_file, errors='replace') as f:
            content = f.read()

    with open(export_file, "w") as f:
        f.write(content)

    if os.path.getsize(export_file) > 0:
        size = _human_size(os.path.getsize(export_file))
        print_success(f"Logs exported to: {export_file} (Size: {size})")
    else:
        print_error("Failed to export logs (output file is empty)")
        os.remove(export_file)
        raise RuntimeError("Log export produced empty file")


# ── Certificate Expiry ─────────────────────────────────────────────────────────

def check_cert_expiry(cfg: Config, warn_days: int = 30) -> None:
    """Print expiry status for the SSL, super-admin, and programmer certificates.

    Args:
        cfg: Config; uses ``bkps_dir`` and ``quartus_keys_dir``.
        warn_days: Days-before-expiry threshold for a warning.
    """
    print_header("Certificate Expiry Check")

    print_info("Checking all certificates for expiration...")
    print()

    certs = [
        (os.path.join(cfg.bkps_dir, "keys", "bkps_ssl_cert", "bkps_ssl_cert.crt"),
         "BKPS SSL CA", "BKPS SSL Certificates"),
        (os.path.join(cfg.bkps_dir, "keys", "bkps_ssl_cert", "bkps_ssl_signed_certificate.crt"),
         "BKPS SSL Server", None),
        (os.path.join(cfg.bkps_dir, "keys", "super_admin_cert.crt"),
         "Super Admin", "Admin Certificates"),
        (os.path.join(cfg.bkps_dir, "keys", "super_admin_bkps_signed.crt"),
         "Super Admin (BKPS Signed)", None),
        (os.path.join(cfg.quartus_keys_dir, "programmer_cert.crt"),
         "Programmer", "Programmer Certificates"),
        (os.path.join(cfg.quartus_keys_dir, "programmer_bkps_signed.crt"),
         "Programmer (BKPS Signed)", None),
    ]

    last_group = None
    for cert_path, label, group in certs:
        if group and group != last_group:
            print(f"{group}:")
            last_group = group
        _check_single_cert(cert_path, label, warn_days)

    print()
    print_success("Certificate expiry check completed")


# ── Keystore Validation ─────────────────────────────────────────────────────────

def validate_keystore(cfg: Config) -> None:
    """List ``bkps_keystore.p12`` aliases with keytool and verify it opens.

    Args:
        cfg: Config; uses ``bkps_dir`` and ``keystore_password``.
    """
    print_header("Validate Keystore")

    ks_file = os.path.join(cfg.bkps_dir, "keys", "bkps_keystore.p12")
    if not os.path.isfile(ks_file):
        print_error(f"Keystore file not found: {ks_file}")
        raise FileNotFoundError(ks_file)

    print_info(f"Validating keystore: {ks_file}")
    print()
    print("Keystore Contents:")
    result = run([
        "keytool", "-list", "-v",
        "-keystore", ks_file,
        "-storepass", cfg.keystore_password,
        "-storetype", "PKCS12",
    ], capture=True, check=False)

    for line in (result.stdout or "").splitlines():
        # Only print the most informative fields; skip verbose certificate detail lines.
        if any(k in line for k in ["Alias name:", "Entry type:", "Valid from:", "until:"]):
            print(f"  {line.strip()}")

    # Verify integrity
    print()
    print_info("Verifying keystore integrity...")
    result2 = run([
        "keytool", "-list",
        "-keystore", ks_file,
        "-storepass", cfg.keystore_password,
        "-storetype", "PKCS12",
    ], capture=True, check=False)

    if result2.returncode == 0:
        print_success("Keystore is valid and accessible")
    else:
        print_error("Keystore validation failed")
        raise RuntimeError("Keystore invalid")


# ── Live Log Streaming ───────────────────────────────────────────────────────────

def show_logs(cfg: Config, _cancel_event=None,
              stop_patterns: list[str] | None = None,
              fail_patterns: list[str] | None = None,
              wait_for_file: float = 0.0,
              stop_control_label: str = "Stop Live Logs") -> bool:
    """Tail ``bkps.log`` until cancel, a stop/fail pattern, or the file is missing.

    Args:
        cfg: Config; uses ``cfg.bkps_dir``.
        _cancel_event: Optional ``threading.Event`` to stop streaming.
        stop_patterns: Substrings that end the tail when seen in a new line.
        fail_patterns: Substrings that end the tail and signal startup failure.
        wait_for_file: Seconds to wait for ``bkps.log`` to appear.
        stop_control_label: Visible control name shown in the streaming hint.

    Returns:
        True when a ``stop_patterns`` entry matched, False otherwise.
    """
    print_header("BKPS Server Logs")

    log_file = os.path.join(cfg.bkps_dir, "logs", "bkps.log")
    if wait_for_file > 0:
        deadline = time.time() + wait_for_file
        while not os.path.isfile(log_file) and time.time() < deadline:
            if _cancel_event is not None and _cancel_event.is_set():
                print_info("Log monitoring stopped")
                return False
            time.sleep(0.2)
    if not os.path.isfile(log_file):
        print_error(f"Log file not found: {log_file}")
        raise FileNotFoundError(log_file)

    if stop_patterns:
        print_info(f"Streaming logs… (auto-stop on: {', '.join(stop_patterns)})")
    else:
        print_info(f"Streaming logs… (click '{stop_control_label}' to stop)")
    ready = False
    with open(log_file, "r", errors="replace") as f:
        f.seek(0, 2)  # seek to end of file so we tail only new lines
        while True:
            if _cancel_event is not None and _cancel_event.is_set():
                break
            line = f.readline()
            if line:
                print(line, end="")
                if fail_patterns and any(pattern in line for pattern in fail_patterns):
                    break
                if stop_patterns and any(pattern in line for pattern in stop_patterns):
                    ready = True
                    break
            else:
                time.sleep(0.2)
    print_info("Log monitoring stopped")
    return ready


# ── Internal Helpers ───────────────────────────────────────────────────────────

def _check_single_cert(cert_path: str, label: str, warn_days: int) -> None:
    """Print one certificate's expiry status.

    Args:
        cert_path: Path to the PEM/DER certificate.
        label: Display name.
        warn_days: Days-before-expiry warning threshold.
    """
    if not os.path.isfile(cert_path):
        print(f"  \u26a0 {label}: FILE NOT FOUND")
        return

    result = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-noout", "-enddate"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"  \u26a0 {label}: INVALID CERTIFICATE")
        return

    enddate_line = result.stdout.strip()
    expiry_str = enddate_line.split("=", 1)[-1].strip()

    try:
        # Parse the openssl enddate string and convert to a UNIX timestamp for
        # arithmetic comparison against the current time.
        exp_ts = _parse_openssl_date(expiry_str)
        now_ts = time.time()
        days_left = int((exp_ts - now_ts) / 86400)

        if exp_ts < now_ts:
            print(f"  \u2717 {label}: EXPIRED ({expiry_str})")
        elif days_left < warn_days:
            print(f"  \u26a0 {label}: Expires in {days_left} days ({expiry_str})")
        else:
            print(f"  \u2713 {label}: Valid until {expiry_str} ({days_left} days)")
    except Exception:
        print(f"  ? {label}: Expires {expiry_str} (could not parse date)")


def _parse_openssl_date(date_str: str) -> float:
    """Parse ``openssl x509 -enddate`` text to a UTC UNIX timestamp.

    Args:
        date_str: OpenSSL date, e.g. ``Mar 25 12:00:00 2026 GMT``.
    """
    # Two format attempts: '%b %d' has a leading space for single-digit days
    # on some platforms, while '%b  %d' has a double space.
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            dt = datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    raise ValueError(f"Cannot parse date: {date_str}")


def _human_size(size_bytes: int) -> str:
    """Format a byte count as B/KB/MB/GB/TB.

    Args:
        size_bytes: Size in bytes.
    """
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f}TB"

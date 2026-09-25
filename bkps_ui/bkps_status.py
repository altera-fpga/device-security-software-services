#!/usr/bin/env python3
"""Status reporting, validation, backup/restore, cleanup, and debug tests."""

import os
import sys
import glob
import shutil
import subprocess
import tempfile
import time
from datetime import datetime

# Platform-agnostic temp directory for test output files.
# Individual test functions write their raw curl/openssl output here so the
# results can be reviewed after the test run.
_TMP = tempfile.gettempdir()
import json
from bkps_config import Config
from bkps_deps import check_dependencies
from bkps_database import check_sql_connection, _admin_psql, _maint_psql
from bkps_monitoring import check_cert_expiry
from bkps_server import stop_bkps_server
from bkps_printer import (
    print_header, print_step, print_success, print_warning,
    print_error, print_info, ask_confirmation,
    GREEN, YELLOW, RED, CYAN, NC,
)
from bkps_runner import run, get_output, command_exists


# ── Status & Key/Cert Inspection ───────────────────────────────────────────────

def show_status(cfg: Config) -> None:
    """Print a high-level status summary of directories, key files, server, and database."""
    print_header("BKPS Demo Status")

    print(f"{CYAN}Directory Status:{NC}")
    _dir_ok(cfg.bkps_dir, "BKPS directory")
    _dir_ok(cfg.quartus_keys_dir, "Quartus keys directory")
    _dir_ok(cfg.cm_provisioning_dir, "CM provisioning directory")

    print(f"\n{CYAN}Key Files:{NC}")
    _file_ok(os.path.join(cfg.quartus_keys_dir, "root0.qky"), "Root key")
    _file_ok(os.path.join(cfg.quartus_keys_dir, "signed_aes_efuse.ccert"), "AES certificate")

    print(f"\n{CYAN}BKPS Server:{NC}")
    pid_path = os.path.join(cfg.bkps_dir, "bkps.pid")
    if os.path.isfile(pid_path):
        with open(pid_path) as f:
            pid_str = f.read().strip()
        try:
            pid = int(pid_str)
            if os.name == 'nt':
                # Windows: use tasklist to check if the PID is alive.
                r = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                    capture_output=True, text=True
                )
                alive = str(pid) in r.stdout
            else:
                try:
                    os.kill(pid, 0)  # signal 0 = check existence without killing
                    alive = True
                except ProcessLookupError:
                    alive = False
            if alive:
                print_success(f"  BKPS server running (PID: {pid})")
            else:
                print_warning("  BKPS server not running (stale PID file)")
        except ValueError:
            print_warning("  BKPS server not running (stale PID file)")
    else:
        print_warning("  BKPS server not running")

    print(f"\n{CYAN}Database:{NC}")
    env = {"PGPASSWORD": cfg.db_password}
    result = subprocess.run(
        ["psql", "-h", "localhost", "-U", cfg.db_user, "-d", cfg.db_name, "-c", "SELECT 1;"],
        env={**os.environ, **env}, capture_output=True
    )
    if result.returncode == 0:
        print_success("  Database connection OK")
    else:
        print_error("  Database connection failed")


def check_keys(cfg: Config) -> bool:
    """Return True if all required key files are present in cfg.quartus_keys_dir."""
    print_header("Checking Keys")
    keys_dir = cfg.quartus_keys_dir
    required = [
        "root0_private.pem", "root0.qky",
        "design0_sign_chain.qky", "aesccert1_sign_chain.qky",
        "signed_aes_efuse.ccert",
    ]
    # At least one mode-specific QEK must exist (HSM vs. passphrase flow).
    qek_candidates = ["aes_hsm_root.qek", "aes_root.qek"]
    missing = 0
    for key in required:
        path = os.path.join(keys_dir, key)
        if os.path.isfile(path):
            print_success(f"  {key} exists")
        else:
            print_error(f"  {key} MISSING")
            missing += 1

    if any(os.path.isfile(os.path.join(keys_dir, q)) for q in qek_candidates):
        present = [q for q in qek_candidates if os.path.isfile(os.path.join(keys_dir, q))]
        print_success(f"  QEK exists ({', '.join(present)})")
    else:
        print_error(f"  QEK missing (expected one of: {', '.join(qek_candidates)})")
        missing += 1

    if missing == 0:
        print_success("\nAll keys present")
        return True
    else:
        print_error(f"\n{missing} keys missing")
        return False


def check_certs(cfg: Config) -> bool:
    """Return True if required certificates exist under cfg.bkps_dir/keys, printing expiry dates."""
    print_header("Checking Certificates")
    keys_dir = os.path.join(cfg.bkps_dir, "keys")
    required = [
        "bkps_ssl_cert/bkps_ssl_cert.crt",
        "super_admin_cert.crt",
        "tsci_cert/tsci_altera_com.pem",
    ]
    missing = 0
    for rel_path in required:
        full_path = os.path.join(keys_dir, rel_path)
        if os.path.isfile(full_path):
            print_success(f"  {rel_path} exists")
            if full_path.endswith(".crt"):
                expiry = get_output(
                    ["openssl", "x509", "-in", full_path, "-noout", "-enddate"]
                )
                if expiry:
                    print_info(f"    Expires: {expiry.split('=')[-1].strip()}")
        else:
            print_error(f"  {rel_path} MISSING")
            missing += 1

    if missing == 0:
        print_success("\nAll certificates present")
        return True
    else:
        print_error(f"\n{missing} certificates missing")
        return False


# ── Comprehensive Validation ─────────────────────────────────────────────────

import re as _re


def _cert_is_expired(cert_path: str) -> bool:
    """Return True if the certificate at ``cert_path`` has already expired."""
    result = run(
        ["openssl", "x509", "-in", cert_path, "-noout", "-checkend", "0"],
        capture=True, check=False,
    )
    # openssl -checkend 0 exits 0 if the cert is still valid, non-zero if expired.
    return result.returncode != 0


def _cert_serial(cert_path: str) -> str:
    """Return the certificate serial as normalised uppercase hex, or '' on failure."""
    out = get_output(
        ["openssl", "x509", "-in", cert_path, "-noout", "-serial"]
    ) or ""
    if "=" in out:
        return _norm_serial(out.split("=", 1)[1])
    return ""


def _norm_serial(hex_str: str) -> str:
    """Normalise a serial-number string for equality comparison."""
    hex_str = _re.sub(r"[:\s]", "", (hex_str or "")).upper()
    if hex_str.startswith("0X"):
        hex_str = hex_str[2:]
    hex_str = hex_str.lstrip("0")
    return hex_str or "0"


def _parse_keystore_trusted_entries(keystore_path: str, storepass: str) -> list:
    """Parse ``keytool -list -v`` and return trustedCertEntry dicts (alias/serial/owner).

    Args:
        keystore_path: Path to the PKCS12 / JKS keystore file.
        storepass: Keystore password.
    """
    if not os.path.isfile(keystore_path):
        return []

    result = run(
        ["keytool", "-list", "-v",
         "-keystore",  keystore_path,
         "-storepass", storepass,
         "-storetype", "PKCS12"],
        capture=True, check=False,
    )
    if result.returncode != 0:
        return []

    entries: list = []
    current: dict = {}
    for raw in (result.stdout or "").splitlines():
        line = raw.strip()

        if line.startswith("Alias name:"):
            if current:
                entries.append(current)
            current = {"alias": line.split(":", 1)[1].strip()}
        elif line.startswith("Entry type:"):
            current["type"] = line.split(":", 1)[1].strip()
        elif line.startswith("Owner:"):
            current["owner"] = line.split(":", 1)[1].strip()
        elif line.startswith("Issuer:"):
            current["issuer"] = line.split(":", 1)[1].strip()
        elif line.startswith("Serial number:"):
            current["serial"] = _norm_serial(line.split(":", 1)[1])

    if current:
        entries.append(current)

    # Only keep trustedCertEntry rows — the truststore entries proper.
    return [e for e in entries
            if e.get("type", "").lower().replace(" ", "") == "trustedcertentry"]


def _cert_subject(cert_path: str) -> str:
    """Return the certificate subject DN as a normalised string (empty on failure)."""
    out = get_output(
        ["openssl", "x509", "-in", cert_path, "-noout", "-subject"]
    ) or ""
    # openssl output form: "subject=CN = foo, O = bar" (spacing varies by version).
    if "=" in out:
        return _re.sub(r"\s+", " ", out.split("=", 1)[1]).strip()
    return ""


def _cert_issuer(cert_path: str) -> str:
    """Return the certificate issuer DN as a normalised string (empty on failure)."""
    out = get_output(
        ["openssl", "x509", "-in", cert_path, "-noout", "-issuer"]
    ) or ""
    if "=" in out:
        return _re.sub(r"\s+", " ", out.split("=", 1)[1]).strip()
    return ""


def _is_self_signed(cert_path: str) -> bool:
    """Return True when the certificate's subject and issuer DN match."""
    subj = _cert_subject(cert_path)
    iss  = _cert_issuer(cert_path)
    return bool(subj) and subj == iss


def _verify_chain(cert_path: str, ca_path: str,
                  untrusted_paths=None) -> tuple:
    """Verify *cert_path* with openssl, using *ca_path* or the system CA bundle.

    Args:
        cert_path: Leaf certificate to verify.
        ca_path: Trust-anchor PEM, or empty to use the system CA bundle.
        untrusted_paths: Optional intermediate certificate paths.
    """
    cmd = ["openssl", "verify"]
    if ca_path:
        cmd += ["-CAfile", ca_path]
    for p in (untrusted_paths or []):
        if p and os.path.isfile(p):
            cmd += ["-untrusted", p]
    cmd.append(cert_path)
    result = run(cmd, capture=True, check=False)
    out = ((result.stdout or "") + (result.stderr or "")).strip()
    last = out.splitlines()[-1] if out else ""
    return result.returncode == 0, last


def _check_local_cert(cert_path: str, label: str,
                      ca_path: str = None,
                      untrusted_paths=None,
                      verify_chain: bool = True) -> int:
    """Check that a local certificate exists, is unexpired, and its chain verifies.

    Args:
        cert_path: Certificate file to inspect.
        label: Display name used in status lines.
        ca_path: Optional trust-anchor PEM for chain verification.
        untrusted_paths: Optional intermediate certificate paths.
        verify_chain: When False, skip openssl chain verification.
    """
    if not os.path.isfile(cert_path):
        print_error(f"  {label}: MISSING ({cert_path})")
        return 1

    errors = 0

    try:
        if _cert_is_expired(cert_path):
            print_error(f"  {label}: EXPIRED ({cert_path})")
            errors += 1
        else:
            expiry = get_output(
                ["openssl", "x509", "-in", cert_path, "-noout", "-enddate"]
            ) or ""
            expiry_str = expiry.split("=", 1)[-1].strip() if "=" in expiry else "unknown"
            print_success(f"  {label}: valid (expires {expiry_str})")
    except Exception as exc:
        print_error(f"  {label}: expiry check failed ({exc})")
        errors += 1

    if verify_chain:
        # Only run chain verification when subject != issuer.  Self-signed
        # certificates (root anchors) have no chain to verify above them.
        try:
            self_signed = _is_self_signed(cert_path)
        except Exception as exc:
            print_warning(f"  {label}: could not determine subject/issuer ({exc})")
            self_signed = False

        # When ca_path is None the system default trust store is used.
        ca_missing = bool(ca_path) and not os.path.isfile(ca_path)

        if self_signed:
            print_info(f"  {label}: self-signed (subject == issuer) — chain check skipped")
        elif ca_missing:
            print_warning(f"  {label}: CA file unavailable — skipping chain verification")
            errors += 1
        else:
            try:
                ok, msg = _verify_chain(cert_path, ca_path, untrusted_paths)
                if ok:
                    print_success(f"  {label}: chain trusted ({msg or 'OK'})")
                else:
                    print_error(f"  {label}: chain NOT trusted ({msg or 'verify failed'})")
                    errors += 1
            except Exception as exc:
                print_error(f"  {label}: chain verification failed ({exc})")
                errors += 1

    return errors


def _check_trusted_certs(cfg: Config) -> bool:
    """Validate local BKPS/TSCI/client certs and reconcile serials with the truststore."""
    print_header("Checking BKPS Trusted Certificates")

    keys_dir = os.path.join(cfg.bkps_dir, "keys")

    bkps_ssl_ca       = os.path.join(keys_dir, "bkps_ssl_cert", "bkps_ssl_cert.crt")
    bkps_server_ssl   = os.path.join(keys_dir, "bkps_ssl_cert", "bkps_ssl_signed_certificate.crt")
    tsci_cert         = os.path.join(keys_dir, "tsci_cert", "tsci_altera_com.pem")
    admin_cert        = os.path.join(keys_dir, "super_admin_cert.crt")
    admin_signed      = os.path.join(keys_dir, "super_admin_bkps_signed.crt")
    programmer_cert   = os.path.join(cfg.quartus_keys_dir, "programmer_cert.crt")
    programmer_signed = os.path.join(cfg.quartus_keys_dir, "programmer_bkps_signed.crt")
    bkps_truststore   = os.path.join(keys_dir, "bkps_keystore.p12")

    errors = 0

    # ── Local certificate expiry + chain trust ────────────────────────────
    print_info("Verifying local certificates and chain trust...")

    # BKPS SSL CA — self-signed anchor; chain check auto-skips (subject==issuer).
    errors += _check_local_cert(
        bkps_ssl_ca, "bkps_ssl_cert.crt (BKPS SSL CA)",
        ca_path=bkps_ssl_ca,
    )

    # BKPS server SSL leaf.  In self-signed CA deployments the BKPS SSL CA
    # itself is also the server certificate, so a separate signed leaf may
    # not exist — treat that case as informational, not an error.
    if os.path.isfile(bkps_server_ssl):
        errors += _check_local_cert(
            bkps_server_ssl, "bkps_ssl_signed_certificate.crt (BKPS server SSL)",
            ca_path=bkps_ssl_ca,
        )
    elif os.path.isfile(bkps_ssl_ca) and _is_self_signed(bkps_ssl_ca):
        print_info(
            "  bkps_ssl_signed_certificate.crt: not present — BKPS SSL CA "
            "is self-signed and serves as the server certificate"
        )
    else:
        print_error(f"  bkps_ssl_signed_certificate.crt: MISSING ({bkps_server_ssl})")
        errors += 1

    # TSCI certificate — issued by an Altera/public CA, not by BKPS.  Verify
    # against the system default trust store (openssl verify without -CAfile).
    errors += _check_local_cert(
        tsci_cert, "tsci_altera_com.pem (TSCI)",
        ca_path=None,  # use system default CA bundle
    )

    # Admin & programmer client certs — chain up to the BKPS SSL CA
    # (BKPS signs them so the leaf's issuer is the BKPS SSL CA).
    errors += _check_local_cert(
        admin_cert, "super_admin_cert.crt (admin client)",
        ca_path=bkps_ssl_ca, untrusted_paths=[admin_signed],
    )
    errors += _check_local_cert(
        programmer_cert, "programmer_cert.crt (programmer client)",
        ca_path=bkps_ssl_ca, untrusted_paths=[programmer_signed],
    )

    # ── Enumerate the local truststore's trustedCertEntry serials ─────────
    print_info("\nEnumerating trustedCertEntries in local truststore "
               f"({bkps_truststore})...")
    truststore_entries: list = []
    try:
        truststore_entries = _parse_keystore_trusted_entries(
            bkps_truststore, cfg.keystore_password or "",
        )
    except Exception as exc:
        print_error(f"Failed to read local truststore: {exc}")

    if not truststore_entries:
        print_error(
            "  No trustedCertEntry rows parsed from bkps_keystore.p12 — "
            "cannot reconcile client certificates against the truststore."
        )
        errors += 1
    else:
        print_success(
            f"  Parsed {len(truststore_entries)} trustedCertEntry row(s)"
        )
        for e in truststore_entries:
            print_info(
                f"    - alias={e.get('alias', '?')} "
                f"serial={e.get('serial', '?')} "
                f"owner={e.get('owner', '?')}"
            )

    trust_serials = {e.get("serial", "") for e in truststore_entries if e.get("serial")}

    # ── Local client cert serials must appear in the truststore ───────────
    for path, label in [
        (admin_cert,      "super_admin_cert.crt"),
        (programmer_cert, "programmer_cert.crt"),
    ]:
        if not os.path.isfile(path):
            # already reported as MISSING above
            continue
        try:
            serial = _cert_serial(path)
            if not serial:
                print_warning(f"  {label}: could not read serial number")
                errors += 1
            elif not trust_serials:
                # truststore unavailable — already counted as an error above
                pass
            elif serial in trust_serials:
                print_success(f"  {label}: serial {serial} present in truststore")
            else:
                print_error(
                    f"  {label}: serial {serial} NOT found in truststore"
                )
                errors += 1
        except Exception as exc:
            print_error(f"  {label}: serial check failed ({exc})")
            errors += 1

    if errors == 0:
        print_success("\nAll BKPS trusted certificates verified")
        return True

    print_error(f"\n{errors} trusted-certificate issue(s) detected")
    return False


def _check_server_connection(cfg: Config) -> bool:
    """Return True if a TCP connection to the BKPS HTTPS port succeeds."""
    import socket

    host = cfg.bkps_server_ip or "localhost"
    try:
        port = int(cfg.bkps_server_port) if cfg.bkps_server_port else 9443
    except (TypeError, ValueError):
        port = 9443

    print_info(f"Probing BKPS server at {host}:{port} ...")
    try:
        with socket.create_connection((host, port), timeout=2.0):
            print_success(f"  BKPS server reachable at {host}:{port}")
            return True
    except Exception as exc:
        print_error(f"  BKPS server unreachable at {host}:{port} ({exc})")
        return False


def validate_setup(cfg: Config) -> bool:
    """Run dependency, database/server, trusted-cert, and Quartus-key checks."""
    import traceback

    print_header("Comprehensive Setup Validation")
    errors = 0

    def _safe(step_num: int, label: str, fn, *args, **kwargs) -> bool:
        """Run a validation step and report any exception without aborting later steps."""
        print_step(step_num, label)
        try:
            result = fn(*args, **kwargs)
            # Treat None / non-boolean truthy returns (e.g. from show_status
            # style helpers that don't return anything) as success.
            return True if result is None else bool(result)
        except Exception as exc:
            print_error(f"  Step failed with unexpected error: {exc}")
            for line in traceback.format_exc().splitlines():
                print(f"    {line}")
            return False

    if not _safe(1, "Checking dependencies...",
                 check_dependencies, cfg):
        errors += 1

    print_step(2, "Checking BKPS database and server connection...")
    db_ok = False
    srv_ok = False
    try:
        db_ok = bool(check_sql_connection(cfg))
    except Exception as exc:
        print_error(f"  Database check failed with unexpected error: {exc}")
        for line in traceback.format_exc().splitlines():
            print(f"    {line}")
    try:
        srv_ok = bool(_check_server_connection(cfg))
    except Exception as exc:
        print_error(f"  Server check failed with unexpected error: {exc}")
        for line in traceback.format_exc().splitlines():
            print(f"    {line}")
    if not (db_ok and srv_ok):
        errors += 1

    if not _safe(3, "Checking BKPS trusted certificate validity...",
                 _check_trusted_certs, cfg):
        errors += 1

    if not _safe(4, "Checking Quartus keys...",
                 check_keys, cfg):
        errors += 1

    if errors == 0:
        print_success("\n=== All validation checks passed ===")
        return True
    else:
        print_error(f"\n=== {errors} validation checks failed ===")
        return False


# ── Backup / Restore / Cleanup ───────────────────────────────────────────────

def backup_setup(cfg: Config) -> None:
    """Create a timestamped backup of the BKPS directory, Quartus keys, and database."""
    print_header("Backing Up BKPS Setup")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join(cfg.home, f"bkps_backup_{timestamp}")
    os.makedirs(backup_dir, exist_ok=True)

    print_step(1, "Backing up BKPS directory...")
    shutil.copytree(cfg.bkps_dir, os.path.join(backup_dir, "bkps"), dirs_exist_ok=True)
    print_success("BKPS backed up")

    print_step(2, "Backing up Quartus keys...")
    shutil.copytree(cfg.quartus_keys_dir, os.path.join(backup_dir, "quartus_keys"), dirs_exist_ok=True)
    print_success("Keys backed up")

    print_step(3, "Backing up database...")
    db_backup = os.path.join(backup_dir, "database_backup.sql")
    with open(db_backup, "w") as f:
        subprocess.run(
            ["pg_dump", "-U", cfg.db_user, cfg.db_name],
            env={**os.environ, "PGPASSWORD": cfg.db_password},
            stdout=f
        )
    print_success("Database backed up")

    print_step(4, "Creating backup metadata...")
    meta = (
        f"Backup Date: {datetime.now()}\n"
        f"BKPS Directory: {cfg.bkps_dir}\n"
        f"Quartus Keys: {cfg.quartus_keys_dir}\n"
        f"Database: {cfg.db_name}\n"
        f"User: {cfg.db_user}\n"
    )
    with open(os.path.join(backup_dir, "backup_info.txt"), "w") as f:
        f.write(meta)

    print_success(f"\nBackup complete: {backup_dir}")


def restore_setup(cfg: Config, backup_dir: str) -> None:
    """Restore BKPS directory, keys, and database from a previous backup.

    Args:
        backup_dir: Path to a directory created by backup_setup.
    """
    print_header("Restoring BKPS Setup")

    if not backup_dir:
        print_error("Backup directory required")
        print_info("Usage: --restore <backup_directory>")
        raise ValueError("Backup directory required")

    if not os.path.isdir(backup_dir):
        print_error(f"Backup directory not found: {backup_dir}")
        raise FileNotFoundError(backup_dir)

    if not ask_confirmation("This will overwrite current setup. Continue?", yes=cfg.yes):
        return

    print_step(1, "Restoring BKPS directory...")
    shutil.rmtree(cfg.bkps_dir, ignore_errors=True)
    shutil.copytree(os.path.join(backup_dir, "bkps"), cfg.bkps_dir)
    print_success("BKPS restored")

    print_step(2, "Restoring Quartus keys...")
    shutil.rmtree(cfg.quartus_keys_dir, ignore_errors=True)
    shutil.copytree(os.path.join(backup_dir, "quartus_keys"), cfg.quartus_keys_dir)
    print_success("Keys restored")

    print_step(3, "Restoring database...")
    _cmd, env = _maint_psql(cfg, ["-c", f"DROP DATABASE IF EXISTS {cfg.db_name};"])
    run(_cmd, env=env)
    _cmd, env = _maint_psql(cfg, ["-c", f"CREATE DATABASE {cfg.db_name};"])
    run(_cmd, env=env)
    db_backup = os.path.join(backup_dir, "database_backup.sql")
    with open(db_backup) as f:
        subprocess.run(
            ["psql", "-h", cfg.db_host or "localhost", "-U", cfg.db_user, "-d", cfg.db_name],
            env={**os.environ, "PGPASSWORD": cfg.db_password},
            stdin=f
        )
    print_success("Database restored")
    print_success("\nRestore complete")


def cleanup(cfg: Config) -> None:
    """Stop the server, drop the database and role, and remove managed directories."""
    print_header("Cleanup")

    if not ask_confirmation(
        "This will delete all BKPS files and reset the database. Continue?", yes=cfg.yes
    ):
        return

    print_step(1, "Stopping BKPS server...")
    stop_bkps_server(cfg)

    print_step(2, "Dropping database...")
    _cmd, env = _maint_psql(cfg, ["-c", f"DROP DATABASE IF EXISTS {cfg.db_name};"])
    run(_cmd, env=env, check=False)
    _cmd, env = _maint_psql(cfg, ["-c", f"DROP ROLE IF EXISTS {cfg.db_user};"])
    run(_cmd, env=env, check=False)
    print_success("Database dropped")

    print_step(3, "Removing directories...")
    for d in [cfg.bkps_dir, cfg.quartus_keys_dir, cfg.cm_provisioning_dir]:
        shutil.rmtree(d, ignore_errors=True)
    print_success("Directories removed")

    print_success("Cleanup complete")


# ---------------------------------------------------------------------------
# Debug tests (prechecks / connectivity / cert validity)
# ---------------------------------------------------------------------------

# ── Debug Tests ──────────────────────────────────────────────────────────────
# Each function below targets a specific category of test and writes raw
# output to files under _TMP so engineers can inspect them after the run.

def run_prechecks(cfg: Config) -> None:
    """Run BKPS pre-checks for port, required files, cert expiry, server banner, and clock skew."""
    ca_cert     = cfg.ca_cert
    client_cert = cfg.client_cert
    client_key  = cfg.client_key
    bkps_url    = cfg.bkps_url

    print_header("[PRECHECK] BKPS Port Availability")
    if command_exists("nc"):
        result = subprocess.run(
            ["nc", "-zvw3", cfg.bkps_server_ip, cfg.bkps_server_port],
            capture_output=not cfg.verbose, text=True
        )
        if result.returncode != 0:
            print_warning(f"BKPS port {cfg.bkps_server_port} on {cfg.bkps_server_ip} is not open.")
        else:
            print_success("BKPS port is open.")
    else:
        print_warning("nc (netcat) not found, skipping port check.")
    print()

    print_header("[PRECHECK] Required File Presence")
    for f in [ca_cert, client_cert, client_key]:
        if not os.path.isfile(f):
            print(f"ERROR: Required file missing: {f}")
        else:
            print(f"Found: {f}")
    print()

    print_header("[PRECHECK] Certificate Expiry")
    _check_cert_expiry_brief(ca_cert)
    _check_cert_expiry_brief(client_cert)
    print()

    print_header("[PRECHECK] Server Version/Banner")
    curl_flags = ["-v"] if cfg.verbose else ["-s"]
    result = subprocess.run(
        ["curl"] + curl_flags + ["--cacert", ca_cert, "--cert", client_cert,
                                  "--key", client_key, "-I", f"{bkps_url}/"],
        capture_output=True, text=True
    )
    out = result.stdout + result.stderr
    server_line = next((l for l in out.splitlines() if l.lower().startswith("server:")), "")
    print(server_line if server_line else "No server version/banner found in HTTP headers.")
    print()

    print_header("[PRECHECK] Clock Skew Check")
    # Detect clock skew between server and client; large skew can
    # cause TLS certificate validation to fail ("not yet valid").
    result = subprocess.run(
        ["curl", "-s", "--cacert", ca_cert, "--cert", client_cert,
         "--key", client_key, "-I", f"{bkps_url}/"],
        capture_output=True, text=True
    )
    date_line = next(
        (l.split(" ", 1)[1] for l in (result.stdout + result.stderr).splitlines()
         if l.lower().startswith("date:")), ""
    )
    if os.name == 'nt':
        local_date = subprocess.run(
            ["powershell", "-Command",
             "Get-Date -Format 'ddd, dd MMM yyyy HH:mm:ss UTC' -AsUTC"],
            capture_output=True, text=True
        ).stdout.strip()
    else:
        local_date = subprocess.run(["date", "-u"], capture_output=True, text=True).stdout.strip()
    if date_line:
        print(f"Server UTC date: {date_line.strip()}")
        print(f"Local  UTC date: {local_date}")
    else:
        print("Could not retrieve server date from HTTP headers.")
    print()

    print("=" * 64)
    print_success("Prechecks completed.")


def run_connectivity_tests(cfg: Config) -> None:
    """Run TLS handshake, mTLS health, SLA, and provisioning endpoint tests."""
    ca_cert     = cfg.ca_cert
    client_cert = cfg.client_cert
    client_key  = cfg.client_key
    bkps_url    = cfg.bkps_url
    curl_flags  = ["-v"] if cfg.verbose else ["-s"]

    # Test 1 - TLS Handshake
    print_header("[TEST 1] TLS Handshake (no client cert)")
    tls_out_path = os.path.join(_TMP, "bkps_test1_tls.txt")
    result = subprocess.run(
        ["openssl", "s_client", "-connect",
         f"{cfg.bkps_server_ip}:{cfg.bkps_server_port}",
         "-CAfile", ca_cert, "-showcerts"],
        input=b"", capture_output=True
    )
    tls_output = result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace")
    with open(tls_out_path, "w") as f:
        f.write(tls_output)
    if cfg.verbose:
        print(tls_output)
    if "Verify return code: 0" in tls_output:
        print_success(f"TLS handshake succeeded. See {tls_out_path}")
    else:
        print_warning(f"TLS handshake had issues. See {tls_out_path}")
    print()

    # Test 2 - mTLS Health
    print_header("[TEST 2] mTLS Health Check (/health)")
    health_path = os.path.join(_TMP, "bkps_test2_health.txt")
    result = subprocess.run(
        ["curl"] + curl_flags + [
            "--cacert", ca_cert, "--cert", client_cert, "--key", client_key,
            f"{bkps_url}/health"
        ],
        capture_output=True, text=True
    )
    with open(health_path, "w") as f:
        f.write(result.stdout + result.stderr)
    if cfg.verbose:
        print(result.stdout)
    if result.returncode == 0:
        print_success(f"mTLS connection succeeded. See {health_path}")
    else:
        print_warning(f"mTLS connection had issues (exit: {result.returncode}). See {health_path}")
    print()

    # Test 3 - SLA Health
    print_header("[TEST 3] SLA Health (/health/sla)")
    sla_path = os.path.join(_TMP, "bkps_test3_sla.txt")
    result = subprocess.run(
        ["curl"] + curl_flags + [
            "--cacert", ca_cert, "--cert", client_cert, "--key", client_key,
            f"{bkps_url}/health/sla"
        ],
        capture_output=True, text=True
    )
    with open(sla_path, "w") as f:
        f.write(result.stdout + result.stderr)
    if result.stdout.strip():
        print_success(f"SLA endpoint responded. See {sla_path}")
    else:
        print_warning(f"SLA endpoint returned empty response. See {sla_path}")
    print()

    # Test 4 - Health version check
    print_header("[TEST 4] Health Endpoint version (/health)")
    health4_path = os.path.join(_TMP, "bkps_test4_health.txt")
    result = subprocess.run(
        ["curl", "-s", "--cacert", ca_cert, "--cert", client_cert, "--key", client_key,
         f"{bkps_url}/health"],
        capture_output=True, text=True
    )
    with open(health4_path, "w") as f:
        f.write(result.stdout + result.stderr)
    try:
        data = json.loads(result.stdout)
        version = data.get("version", "unspecified")
        if version == "unspecified" or not version:
            print_warning(f"Health endpoint version is 'unspecified' or missing. See {health4_path}")
        else:
            print_success(f"BKPS version: {version}. See {health4_path}")
    except Exception:
        if result.stdout:
            print_success(f"Health endpoint responded. See {health4_path}")
        else:
            print_warning(f"Health endpoint returned no output. See {health4_path}")
    print()

    # Test 5 - Provisioning endpoint
    print_header("[TEST 5] Provisioning Endpoint Auth (/prov/v1/get_next)")
    prov_path = os.path.join(_TMP, "bkps_test5_prov.txt")
    result = subprocess.run(
        ["curl"] + curl_flags + [
            "-X", "POST",
            "--cacert", ca_cert, "--cert", client_cert, "--key", client_key,
            "-H", "Content-Type: application/json",
            "-d", "{}",
            f"{bkps_url}/prov/v1/get_next"
        ],
        capture_output=True, text=True
    )
    with open(prov_path, "w") as f:
        f.write(result.stdout + result.stderr)
    # NOTE: HTTP 2051 is the BKPS-specific "Access Denied" response code;
    # it is expected when the programmer certificate lacks endpoint permissions.
    prov_out = result.stdout + result.stderr
    if any(x in prov_out for x in ["200", "2051"]):
        print_success(f"Provisioning endpoint responded. See {prov_path}")
    else:
        print_warning(f"Provisioning endpoint response: check {prov_path}")
    print()

    print_info("Note: HTTP 2051 (Access Denied) is expected if programmer lacks endpoint permissions")
    print("=" * 64)
    print_success(f"Connectivity tests completed. See {_TMP}/bkps_test*.txt")


def run_cert_validity_tests(cfg: Config) -> None:
    """Run local certificate/key verification tests."""
    ca_cert     = cfg.ca_cert
    client_cert = cfg.client_cert
    client_key  = cfg.client_key
    out_path    = os.path.join(_TMP, "bkps_test6_local.txt")

    print_header("[TEST 6] Local Certificate/Key Verification")

    output_lines = []

    def _capture(cmd, stdin=None):
        r = subprocess.run(cmd, input=stdin, capture_output=True, text=True)
        return (r.stdout + r.stderr).strip()

    # Subject/Issuer/Expiry
    info = _capture(["openssl", "x509", "-in", client_cert, "-noout", "-text"])
    for line in info.splitlines():
        if any(k in line for k in ["Subject:", "Issuer:", "Not After"]):
            output_lines.append(line.strip())

    # Verify cert signed by CA
    issuer  = _capture(["openssl", "x509", "-in", client_cert, "-noout", "-issuer"])
    subject = _capture(["openssl", "x509", "-in", client_cert, "-noout", "-subject"])
    if issuer == subject:
        verify_out = _capture(["openssl", "verify", "-CAfile", ca_cert, client_cert])
        output_lines.append(verify_out)
        output_lines.append("NOTE: Self-signed certificate - openssl verify failure is expected in demo setups.")
    else:
        verify_out = _capture(["openssl", "verify", "-CAfile", ca_cert, client_cert])
        output_lines.append(verify_out)

    # Key/cert modulus match
    cert_mod = _capture(["openssl", "x509", "-noout", "-modulus", "-in", client_cert])
    cert_md5 = _capture(["openssl", "md5"], stdin=cert_mod)
    key_mod  = _capture(["openssl", "rsa", "-noout", "-modulus", "-in", client_key])
    key_md5  = _capture(["openssl", "md5"], stdin=key_mod)
    output_lines.append(f"Cert modulus MD5: {cert_md5}")
    output_lines.append(f"Key  modulus MD5: {key_md5}")

    for line in output_lines:
        print(f"  {line}")

    with open(out_path, "w") as f:
        f.write("\n".join(output_lines) + "\n")

    print("=" * 64)
    print_success(f"Certificate validity tests completed. See {out_path}")


def run_debug_tests(cfg: Config) -> None:
    """Run prechecks, connectivity tests, and certificate validity tests in sequence."""
    run_prechecks(cfg)
    run_connectivity_tests(cfg)
    run_cert_validity_tests(cfg)
    print_success("All debug tests completed.")


# ── Internal Helpers ───────────────────────────────────────────────────────────

def _dir_ok(path: str, label: str) -> None:
    """Print a success or error line for a directory existence check."""
    if os.path.isdir(path):
        print_success(f"  {label} exists")
    else:
        print_error(f"  {label} missing")


def _file_ok(path: str, label: str) -> None:
    """Print a success or error line for a file existence check."""
    if os.path.isfile(path):
        print_success(f"  {label} exists")
    else:
        print_error(f"  {label} missing")


def _check_cert_expiry_brief(cert_path: str) -> None:
    """Print the expiry date of a certificate without detailed analysis."""
    if not os.path.isfile(cert_path):
        print_warning(f"Certificate not found: {cert_path}")
        return
    result = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-noout", "-enddate"],
        capture_output=True, text=True
    )
    expiry = result.stdout.split("=")[-1].strip() if result.stdout else "unknown"
    print(f"  Certificate {os.path.basename(cert_path)} expires: {expiry}")

#!/usr/bin/env python3
"""Start the BKPS server, create the super admin, and configure keys."""

import os
import time
import re
from bkps_config import Config
from bkps_printer import print_header, print_step, print_success, print_warning, print_error, print_info
from bkps_server import start_bkps_server
from bkps_configure import create_super_admin, configure_bkps_keys
from bkps_keys import create_authentication_keys
from bkps_database import _admin_psql
from bkps_runner import run as _run, run_runner_tool as _runner
import socket
from bkps_server import _find_pid_on_port



# ── Setup-state check helpers ───────────────────────────────────────────────────────

def _check_server_running(cfg: Config) -> bool:
    """Return True if localhost:``cfg.bkps_server_port`` accepts a TCP connection.

    Args:
        cfg: Config; uses ``bkps_server_port``.
    """
    try:
        with socket.create_connection(("localhost", int(cfg.bkps_server_port)), timeout=2):
            return True
    except OSError:
        return False


def _super_admin_exists(cfg: Config) -> bool:
    """Return True if the BKPS DB has a ROLE_SUPER_ADMIN row; False on any probe error.

    Args:
        cfg: Config; uses ``db_name`` via ``_admin_psql``.
    """
    query = (
        "SELECT 1 FROM app_user_authority "
        "WHERE authority_name = 'ROLE_SUPER_ADMIN' LIMIT 1;"
    )
    try:
        cmd, env = _admin_psql(
            cfg,
            ["-d", cfg.db_name, "-tA", "-c", query],
        )
        result = _run(cmd, env=env, capture=True, check=False)
    except Exception as exc:  # pragma: no cover - defensive
        print_info(f"Super-admin DB probe skipped ({exc.__class__.__name__}: {exc})")
        return False

    if result.returncode != 0:
        # Table may not exist yet (fresh DB) or auth failed — treat as absent.
        return False
    return bool((result.stdout or "").strip())


def check_setup_complete(cfg: Config) -> bool:
    """Return True if the signed super-admin cert and import public key both exist.

    Args:
        cfg: Config; uses ``bkps_dir`` and ``quartus_keys_dir``.
    """
    signed_cert = os.path.join(cfg.bkps_dir, "keys", "super_admin_bkps_signed.crt")
    import_pubkey = os.path.join(cfg.quartus_keys_dir, "bkps_import_pubkey.pem")
    return os.path.isfile(signed_cert) and os.path.isfile(import_pubkey)


# ── Automated setup orchestrator ─────────────────────────────────────────────────────

def auto_setup_bkps(
    cfg: Config,
    timeout: int = 120,
    _cancel_event=None,
    skip_qky: bool = False,
) -> bool:
    """Start the server, create the super admin, then create and configure keys.

    Args:
        cfg: Config with BKPS paths and credentials.
        timeout: Seconds to wait for the initial token in ``bkps.log``.
        _cancel_event: Optional ``threading.Event``; when set, abort at the next checkpoint.
        skip_qky: Forwarded to key-generation helpers to reuse existing QKY files.
    """
    print_header("Automated BKPS Setup")

    def _is_cancelled() -> bool:
        return bool(_cancel_event is not None and _cancel_event.is_set())

    def _check_cancel(stage: str) -> bool:
        if _is_cancelled():
            print_warning(f"Auto setup cancelled by user during: {stage}")
            return True
        return False

    try:
        # Check prerequisites
        admin_cert = os.path.join(cfg.bkps_dir, "keys", "super_admin_cert.crt")
        if not os.path.isfile(admin_cert):
            print_error("Super admin certificate not found!")
            print_info("Run Installation Pipeline first (it creates super_admin_cert.crt).")
            return False

        # ── Pre-flight status check ────────────────────────────────────────────
        print_info("Checking current BKPS setup status...")

        server_running   = _check_server_running(cfg)

        if server_running:
            print_success(f"Server: already running on port {cfg.bkps_server_port}")
        else:
            print_info("Server: not running")

        if server_running:
            print_success("Server is already running — auto setup stops here.")
            print_info("Continue from Server Pipeline if those steps are not done.")
            return True

        print_info("")

        # ── Step 1: Start server ───────────────────────────────────────────────
        print_step(1, "Starting BKPS server...")
        if server_running:
            print_info("Server already running — skip")
        else:
            if _check_cancel("start server"):
                return False
            if not start_bkps_server(cfg):
                return False

        # ── Steps 2–3: Token + super admin ────────────────────────────────────
        admin_exists = _super_admin_exists(cfg)
        print_step(2, f"Monitoring logs for initial token (timeout: {timeout}s)...")
        if admin_exists:
            print_info("Super admin already exists — skip token wait")
        else:
            token = _wait_for_token(cfg, timeout, _cancel_event=_cancel_event,
                                    log_start_pos=0)

            if _check_cancel("wait for initial token"):
                return False

            if not token:
                print_error("Failed to extract initial token from logs")
                return False

            token_file = os.path.join(cfg.bkps_dir, ".initial_token")
            with open(token_file, "w") as f:
                f.write(token)
            print_success(f"Token saved to: {token_file}")
            print_info(f"Token: {token}")

        print_step(3, "Creating super admin automatically...")
        if admin_exists:
            print_info("Super admin already exists — skip")
        else:
            if _check_cancel("create super admin"):
                return False
            create_super_admin(cfg, token, parent_step=3)

        # ── Steps 4–5: Wait for readiness + configure keys ────────────────────
        print_step(4, "Waiting for BKPS authenticated APIs to be ready...")
        if _check_cancel("wait for BKPS authenticated readiness"):
            return False
        if not _wait_for_authenticated_ready(cfg, _cancel_event=_cancel_event):
            print_error("BKPS authenticated APIs did not become ready in time")
            print_info("Try waiting ~30 seconds and run 'Configure BKPS Keys' again.")
            return False

        print_step(5, "Creating authentication keys...")
        if _check_cancel("create authentication keys"):
            return False
        create_authentication_keys(cfg, skip_qky=skip_qky, parent_step=5)

        print_step(6, "Configuring BKPS keys automatically...")
        if _check_cancel("configure keys"):
            return False
        configure_bkps_keys(cfg, skip_qky=skip_qky, parent_step=6)
        print_success("BKPS keys configured (including Service Import Key Pair)")

        print_success("✓ Automated setup completed successfully!")
        print_info("")

        # Write marker so the GUI knows setup is done (Auto Setup button is disabled until DB reset)
        marker = os.path.join(cfg.bkps_dir, ".bkps_setup_complete")
        with open(marker, "w") as _f:
            _f.write("1")

        return True
    except Exception as e:
        print_error(f"Failed to complete automated setup: {e}")
        return False


# ── Readiness wait helpers ───────────────────────────────────────────────────────────

def _wait_for_runner_health(cfg: Config, timeout: int = 300, _cancel_event=None) -> bool:
    """Poll ``runner.py health --detailed`` until exit 0 or timeout.

    Args:
        cfg: Config forwarded to the admin-tools runner.
        timeout: Maximum seconds to wait.
        _cancel_event: Optional ``threading.Event`` to abort the wait.
    """
    start_time = time.time()
    last_progress = -1
    last_reason = ""

    while (time.time() - start_time) < timeout:
        if _cancel_event is not None and _cancel_event.is_set():
            print_warning("BKPS readiness wait cancelled by user")
            return False

        try:
            result = _runner(cfg, "health", "--detailed", check=False, capture=True)
            if result.returncode == 0:
                print_success("BKPS health check passed")
                return True
            err = (result.stderr or result.stdout or "").strip().splitlines()
            last_reason = err[-1] if err else f"exit {result.returncode}"
        except Exception as exc:
            last_reason = str(exc)

        elapsed = int(time.time() - start_time)
        if elapsed // 10 != last_progress and elapsed > 0:
            last_progress = elapsed // 10
            remaining = max(0, timeout - elapsed)
            extra = f" — last: {last_reason}" if last_reason else ""
            print_info(f"Waiting for BKPS readiness... ({remaining}s remaining){extra}")

        time.sleep(3)

    print_error("BKPS health check did not pass in time")
    if last_reason:
        print_info(f"Last health failure: {last_reason}")
    return False


def _wait_for_authenticated_ready(cfg: Config, timeout: int = 300, _cancel_event=None) -> bool:
    """Wait for health, then two consecutive successful ``runner.py user list`` calls.

    Args:
        cfg: Config forwarded to the admin-tools runner.
        timeout: Seconds budget for health plus the user-list poll.
        _cancel_event: Optional ``threading.Event`` to abort the wait.
    """
    if not _wait_for_runner_health(cfg, timeout=timeout, _cancel_event=_cancel_event):
        return False

    start_time = time.time()
    consecutive_successes = 0
    required_successes = 2
    last_progress = -1

    while (time.time() - start_time) < timeout:
        if _cancel_event is not None and _cancel_event.is_set():
            print_warning("BKPS authenticated readiness wait cancelled by user")
            return False

        try:
            result = _runner(cfg, "user", "list", check=False, capture=True)
            if result.returncode == 0:
                consecutive_successes += 1
                if consecutive_successes >= required_successes:
                    print_success("BKPS authenticated APIs are ready")
                    return True
            else:
                consecutive_successes = 0
        except Exception:
            consecutive_successes = 0

        elapsed = int(time.time() - start_time)
        if elapsed // 10 != last_progress and elapsed > 0:
            last_progress = elapsed // 10
            remaining = max(0, timeout - elapsed)
            print_info(f"Waiting for authenticated BKPS readiness... ({remaining}s remaining)")

        time.sleep(3)

    return False


# ── Log monitoring helpers ───────────────────────────────────────────────────────────

def _wait_for_token(cfg: Config, timeout: int, _cancel_event=None,
                    log_start_pos: int = 0) -> str:
    """Tail ``bkps.log`` until the 64-hex initial token appears, or timeout.

    Args:
        cfg: Config; uses ``cfg.bkps_dir``.
        timeout: Maximum seconds to wait.
        _cancel_event: Optional ``threading.Event`` to abort the wait.
        log_start_pos: Byte offset to start reading (skip older log content).
    """
    log_path = os.path.join(cfg.bkps_dir, "logs", "bkps.log")
    token_pattern = re.compile(r'Temporary user access token:\s*([a-f0-9]{64})')
    ansi_re = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
    fail_pattern = re.compile(
        r'APPLICATION FAILED TO START'
        r'|Application run failed'
        r'|Failed to start'
        r'|APPLICATION\s+FAILED'
        r'|Logback configuration error detected'
        r'|Logging system failed to initialize'
        r'|Could not find or load main class'
        r'|BindException'
        r'|Address already in use',
        re.IGNORECASE,
    )

    start_time = time.time()
    last_size = log_start_pos
    last_progress_tick = -1
    # Grace period before we start checking if the process is alive —
    # the Java process may not appear in the process list immediately.
    _grace_seconds = 20

    while (time.time() - start_time) < timeout:
        if _cancel_event is not None and _cancel_event.is_set():
            print_warning("Token monitoring cancelled by user")
            return ""

        if not os.path.isfile(log_path):
            print_info("Waiting for log file to be created...")
            time.sleep(2)
            continue

        # Only read new content (efficient for large logs)
        try:
            current_size = os.path.getsize(log_path)
            if current_size < last_size:
                # Log was truncated/rotated — restart from beginning
                last_size = 0

            with open(log_path, 'r', errors='replace') as f:
                f.seek(last_size)
                new_content = f.read()
                last_size = f.tell()

            # Strip ANSI escape codes before matching (Spring Boot / Logback
            # emits colour codes when running in a PTY, which tee writes into
            # the log file literally and breaks the regex).
            clean = ansi_re.sub('', new_content)

            # Detect Spring Boot startup failure immediately — no point waiting
            if fail_pattern.search(clean):
                print_error("BKPS server failed to start!")
                # Print the last relevant log lines to help diagnose
                all_lines = clean.splitlines()
                error_lines = [ln for ln in all_lines if any(
                    kw in ln for kw in ("ERROR", "WARN", "Exception", "Failed", "required", "Description", "Action", "Parameter")
                )]
                for ln in error_lines[-15:]:
                    print_error(f"  {ln.strip()}")
                return ""

            match = token_pattern.search(clean)
            if match:
                token = match.group(1)
                print_success("Found token in logs!")
                return token

            # After grace period, check if the Java process is still alive
            elapsed = int(time.time() - start_time)
            if elapsed > _grace_seconds and not _find_pid_on_port(cfg.bkps_server_port) != 0:
                print_error("BKPS Java process is no longer running — server crashed at startup")
                print_info(f"Check the log for errors: {log_path}")
                return ""

            # Show progress every 10 seconds (tick-based to avoid duplicates)
            tick = elapsed // 10
            if tick != last_progress_tick and elapsed > 0:
                last_progress_tick = tick
                remaining = max(0, timeout - elapsed)
                print_info(f"Still waiting... ({remaining}s remaining)")

        except Exception as e:
            print_warning(f"Error reading log: {e}")

        time.sleep(2)

    print_warning(f"Timeout after {timeout}s - token not found in logs")
    return ""


def extract_token_from_logs(cfg: Config) -> str:
    """Return the first initial token found in ``bkps.log``, or ''.

    Args:
        cfg: Config; uses ``cfg.bkps_dir``.
    """
    log_path = os.path.join(cfg.bkps_dir, "logs", "bkps.log")

    if not os.path.isfile(log_path):
        print_error(f"Log file not found: {log_path}")
        return ""

    token_pattern = re.compile(r'Temporary user access token:\s*([a-f0-9]{64})')
    ansi_re = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

    try:
        with open(log_path, 'r', errors='replace') as f:
            content = f.read()
        clean = ansi_re.sub('', content)
        match = token_pattern.search(clean)
        if match:
            return match.group(1)
    except Exception as e:
        print_error(f"Error reading log file: {e}")

    return ""

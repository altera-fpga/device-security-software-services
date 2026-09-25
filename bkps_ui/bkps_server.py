#!/usr/bin/env python3
"""Start, stop, and diagnose the BKPS Java server process."""

import os
import sys
import glob
import select
import shlex
import socket
import subprocess
import time

from bkps_config import Config
from bkps_printer import print_header, print_step, print_success, print_warning, print_error, print_info
from bkps_runner import run_runner_tool as _runner, command_exists
from bkps_monitoring import show_logs


def is_bkps_server_running(cfg: Config) -> bool:
    """Return whether the configured local BKPS TCP port is listening."""
    try:
        port = int(cfg.bkps_server_port)
    except (TypeError, ValueError):
        return False
    return _is_port_listening(port)


# ---------------------------------------------------------------------------
# start_bkps_server
# ---------------------------------------------------------------------------

# ── start_bkps_server ────────────────────────────────────────────────────────────────

def _validate_bkps_server_runtime(cfg: Config) -> str:
    """Validate setup artifacts needed before a BKPS process can start.

    Returns the executable JAR basename. Validation happens before any running
    process is stopped, so a failed restart cannot take down a usable server.
    """
    jars = glob.glob(os.path.join(cfg.bkps_dir, "bkps*.jar"))
    if not jars:
        print_error(f"BKPS JAR file not found in {cfg.bkps_dir}")
        print_info("Complete BKPS Setup -> Setup BKPS Repository")
        raise FileNotFoundError("BKPS JAR missing")

    required = (
        (
            os.path.join(cfg.bkps_dir, "keys", "bkps_keystore.p12"),
            "Create BKPS Keystore",
        ),
        (
            os.path.join(
                cfg.bkps_dir,
                "config",
                f"application-{cfg.profile_name}.yml",
            ),
            "Create BKPS Config",
        ),
    )
    missing = [(path, step) for path, step in required if not os.path.isfile(path)]
    if missing:
        print_error("BKPS server setup is incomplete; required runtime files are missing:")
        for path, step in missing:
            print_error(f"  {path}")
            print_info(f"  Run BKPS Setup -> {step}")
        raise FileNotFoundError(
            "BKPS server prerequisites missing: "
            + ", ".join(os.path.basename(path) for path, _step in missing)
        )

    return os.path.basename(jars[0])


def start_bkps_server(cfg: Config, extra_flags: str = "") -> bool:
    """Start the BKPS JAR in the background and stream logs until the token line.

    Args:
        cfg: Config with ``bkps_dir``, port, security provider, and profile.
        extra_flags: Extra JVM/Spring flags appended to the java command.

    Returns:
        True when the server is running (log readiness and/or listening port).
        False when startup failed.
    """
    print_header("Starting BKPS Server")

    # Validate the runtime before stopping a currently running instance.
    bkps_jar = _validate_bkps_server_runtime(cfg)

    # Pre-flight: ensure target port is available.
    try:
        target_port = int(cfg.bkps_server_port)
    except Exception:
        target_port = 8082

    if _is_port_listening(target_port):
        print_warning(f"Port {target_port} is already in use")

        bkps_pid = _find_pid_on_port(target_port)
        if bkps_pid != 0:
            print_info(f"Port {target_port} is held by PID {bkps_pid}; stopping it before restart...")
            stop_bkps_server(cfg)
            time.sleep(2)
            if _is_port_listening(target_port):
                owner = _describe_port_owner(target_port)
                print_error(f"Port {target_port} is still in use after stop attempt")
                if owner:
                    print_error(f"Port owner: {owner}")
                raise RuntimeError(f"Port {target_port} is busy")
            print_success(f"Port {target_port} is free after BKPS stop")

    logs_dir = os.path.join(cfg.bkps_dir, "logs")
    log_path = os.path.join(logs_dir, "bkps.log")
    pid_path = os.path.join(cfg.bkps_dir, "bkps.pid")
    # Java classpath separator is ':' on POSIX and ';' on Windows
    _sep = ";" if os.name == 'nt' else ":"
    _libs_sep = "\\" if os.name == 'nt' else "/"
    classpath = f"{bkps_jar}{_sep}libs-ext{_libs_sep}*"

    os.makedirs(logs_dir, exist_ok=True)
    # Clear log for fresh monitoring
    open(log_path, "w").close()

    print_info(f"JAR: {bkps_jar}")
    print_info(f"Log file: {log_path}")
    print_info(f"Security Provider: {cfg.security_provider}, Profile: {cfg.profile_name}")

    extra = extra_flags.strip()

    # nCipher requires module-protection JVM flags when using JCA/JCE CSP mode
    ncipher_flags = "-Dprotect=module -DignorePassphrase=true " if cfg.security_provider == "ncipher" else ""

    # Build the launch command string and write a platform-specific script
    java_cmd = (
        f'java -cp "{classpath}" '
        f"{ncipher_flags}"
        f"-Dloader:main=com.intel.bkp.bkps.BkpsApp "
        f"org.springframework.boot.loader.launch.PropertiesLauncher "
        f"--spring.profiles.active=prod,{cfg.security_provider},{cfg.profile_name},logs "
        f"{extra + ' ' if extra else ''}".strip()
    )

    # Discard the JVM's raw stdout/stderr: Logback writes everything we
    # need (including the token line) into bkps.log.  Piping the process
    # stream into the same file causes Logback to fail with
    # "The process cannot access the file because it is being used by
    # another process" on Windows.
    _dev_null = "NUL" if os.name == 'nt' else "/dev/null"

    if os.name == 'nt':
        script_path = os.path.join(cfg.bkps_dir, "start_bkps.bat")
        with open(script_path, "w") as f:
            f.write("@echo off\r\n")
            f.write(f'cd /d "{cfg.bkps_dir}"\r\n')
            f.write(f'{java_cmd} > {_dev_null} 2>&1\r\n')
        shell_cmd = f'cd /d "{cfg.bkps_dir}" && {java_cmd} > {_dev_null} 2>&1'
        print_info("You can run it manually: start_bkps.bat")
    else:
        # Windows finds a co-located libspdm_wrapper.dll through the working
        # directory; POSIX loaders do not search it, so the staged wrapper
        # directory has to be on the library search path.
        library_path = (
            f"export LD_LIBRARY_PATH={shlex.quote(cfg.bkps_dir)}"
            '${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}'
        )
        shell_cmd = (
            f"cd {shlex.quote(cfg.bkps_dir)} && {library_path} && "
            f"{java_cmd} > {_dev_null} 2>&1"
        )
        script_path = os.path.join(cfg.bkps_dir, "start_bkps.sh")
        with open(script_path, "w") as f:
            f.write("#!/bin/bash\n")
            f.write(shell_cmd + "\n")
        os.chmod(script_path, 0o755)
        print_info("You can run it manually: bash start_bkps.sh")

    print_info("")
    print_info("Executing command:")
    print_info(f"  {shell_cmd}")
    print_info("")
    print_info(f"Script written to: {script_path}")
    print_info("")

    log_ready = _launch_in_terminal(cfg, script_path, log_path)
    if log_ready is False:
        print_error("Failed to start BKPS server")
        return False

    java_pid = 0
    for _ in range(15):
        time.sleep(1)
        pid = _find_pid_on_port(target_port)
        if pid != 0:
            java_pid = pid
            break

    port_up = _is_port_listening(target_port)
    if not log_ready and not port_up:
        print_error("Failed to start BKPS server")
        return False

    if java_pid != 0:
        try:
            with open(pid_path, "w") as f:
                f.write(str(java_pid))
        except OSError as exc:
            print_warning(f"Could not write PID file {pid_path}: {exc}")
    elif port_up:
        print_warning(
            f"Server is listening on port {target_port} but process PID could not be resolved"
        )

    print_success("BKPS server started in background")
    return True


def _launch_in_terminal(cfg: Config, script_path: str, log_path: str) -> bool | None:
    """Launch the start script in a new session and stream logs until a stop pattern.

    Args:
        cfg: Config; uses ``cfg.bkps_dir`` as the working directory.
        script_path: Path to ``start_bkps.sh`` or ``start_bkps.bat``.
        log_path: Unused; ``show_logs`` reads ``cfg.bkps_dir/logs/bkps.log``.

    Returns:
        True when log streaming ended on a readiness pattern, False on a startup
        failure pattern, or None when the subprocess could not be launched.
    """
    proc = subprocess.Popen(
        [script_path],
        cwd=cfg.bkps_dir,
        start_new_session=True,
    )

    if not proc:
        print_error("Failed to start BKPS server")
        return None

    match_patterns = [
        "Temporary user access token",
        "refreshTempAccessToken() with result = null",
        "Application 'bkps' is running",
    ]
    fail_patterns = [
        "Application run failed",
        "ERROR [main] SpringApplication",
    ]
    return show_logs(
        cfg,
        stop_patterns=match_patterns,
        fail_patterns=fail_patterns,
        wait_for_file=15,
    )


# ---------------------------------------------------------------------------
# stop_bkps_server
# ---------------------------------------------------------------------------

# ── stop_bkps_server ────────────────────────────────────────────────────────────────

def stop_bkps_server(cfg: Config) -> None:
    """Kill the process listening on ``cfg.bkps_server_port``.

    Args:
        cfg: Config; uses ``bkps_server_port``.
    """
    print_header("Stopping BKPS Server")

    stopped = False

    # --- 1. Kill processes running on the configured server port ---
    try:
        port = int(cfg.bkps_server_port) if cfg.bkps_server_port else 0
    except (TypeError, ValueError):
        raise ValueError("Invalid server port")
    if port != 0:
        port_pid = _find_pid_on_port(port)
        if port_pid != 0:
            print_info(f"Killing process bound to port {port}: PID {port_pid}")
            _kill_pid(port_pid, label=f"process on port {port}")
            stopped = True
        elif not _is_port_listening(port):
            print_info(f"Port {port} is free")
        else:
            print_warning(f"Port {port} still listening but no owner PID resolved")
    else:
        print_info("No server port configured")

    if stopped:
        print_success("BKPS server stopped")
    else:
        print_warning("No running BKPS server process found")


def _kill_pid(pid: int, label: str = "process") -> None:
    """Send SIGTERM (Linux) or taskkill /F (Windows) to ``pid``.

    Args:
        pid: Process ID to terminate; 0 is ignored.
        label: Text used in status messages.
    """
    if pid == 0:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                capture_output=True,
            )
            print_success(f"Stopped {label} (PID: {pid})")
        except Exception as e:
            print_warning(f"Could not terminate {label} {pid}: {e}")
        return

    try:
        os.kill(pid, 15)  # SIGTERM
        print_info(f"Sent SIGTERM to {label} (PID: {pid})")
    except ProcessLookupError:
        print_info(f"{label} {pid} already exited")


def _find_pid_on_port(port: int) -> int:
    """Return the PID listening on TCP ``port``, or 0 if none is found.

    Args:
        port: TCP port number.
    """
    pid = 0
    port = int(port)

    if os.name == "nt":
        try:
            result = subprocess.run(
                ["netstat", "-ano", "-p", "TCP"],
                capture_output=True, text=True, timeout=8,
            )
            needle = f":{port}"
            for line in result.stdout.splitlines():
                parts = line.split()
                # Proto  Local Address       Foreign Address     State       PID
                if len(parts) >= 5 and "LISTENING" in parts and parts[1].endswith(needle):
                    try:
                        pid = int(parts[-1])
                    except ValueError:
                        pass
        except Exception:
            pass
        return pid

    # lsof: -tiTCP:<port> -sTCP:LISTEN prints only PID(s), one per line
    if command_exists("lsof"):
        try:
            result = subprocess.run(
                ["lsof", "-tiTCP:%d" % port, "-sTCP:LISTEN"],
                capture_output=True, text=True, timeout=5,
            )
            pid = _parse_pid_from_tool_output(result.stdout)
        except Exception:
            pass
        if pid != 0:
            return pid

    if command_exists("ss"):
        try:
            result = subprocess.run(
                ["ss", "-ltnpH", f"sport = :{port}"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                # users:(("java",pid=1234,fd=42))
                for chunk in line.split("users:")[1:]:
                    for token in chunk.replace("(", " ").replace(")", " ").split(","):
                        token = token.strip()
                        if token.startswith("pid="):
                            try:
                                pid = int(token.split("=", 1)[1])
                            except ValueError:
                                pass
        except Exception:
            pass

    if pid == 0 and command_exists("fuser"):
        try:
            result = subprocess.run(
                ["fuser", "-n", "tcp", str(port)],
                capture_output=True, text=True, timeout=5,
            )
            pid = _parse_pid_from_tool_output(result.stdout)
        except Exception:
            pass

    return pid


def _parse_pid_from_tool_output(stdout: str) -> int:
    """Return the first numeric token from lsof/fuser-style stdout, or 0."""
    for token in stdout.split():
        token = token.strip()
        if token.isdigit():
            return int(token)
    return 0


def _is_port_listening(port: int) -> bool:
    """Return True if 127.0.0.1:port accepts a TCP connection.

    Args:
        port: TCP port number.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        return sock.connect_ex(("127.0.0.1", int(port))) == 0
    except Exception:
        return False
    finally:
        sock.close()


def _describe_port_owner(port: int) -> str:
    """Return a process-listing line for the owner of TCP ``port``, or ''.

    Args:
        port: TCP port number.
    """
    port = str(port)

    # Windows: netstat -ano
    if os.name == 'nt':
        try:
            result = subprocess.run(
                ["netstat", "-ano", "-p", "TCP"],
                capture_output=True, text=True, timeout=3,
            )
            for line in result.stdout.splitlines():
                if f":{port}" in line and "LISTENING" in line:
                    return line.strip()
        except Exception:
            pass
        return ""

    # Preferred: ss (Linux modern tool)
    try:
        result = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if f":{port}" in line and "LISTEN" in line:
                    # Example users:(("java",pid=12345,fd=123))
                    return line.strip()
    except Exception:
        pass

    # Fallback: lsof
    try:
        result = subprocess.run(
            ["lsof", "-iTCP:" + port, "-sTCP:LISTEN", "-n", "-P"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if result.returncode == 0:
            lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
            if len(lines) >= 2:
                return lines[1].strip()
    except Exception:
        pass

    # Fallback: netstat
    try:
        result = subprocess.run(["netstat", "-tlnp"], capture_output=True, text=True, timeout=3)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if f":{port}" in line and "LISTEN" in line:
                    return line.strip()
    except Exception:
        pass

    return ""


# ---------------------------------------------------------------------------
# monitor_bkps_logs
# ---------------------------------------------------------------------------

# ── monitor_bkps_logs ───────────────────────────────────────────────────────────────

def monitor_bkps_logs(cfg: Config) -> None:
    """Show recent ``bkps.log`` lines, then save the initial token if present.

    Args:
        cfg: Config; uses ``cfg.bkps_dir``.
    """
    print_header("Monitoring BKPS Server Logs")

    log_path = os.path.join(cfg.bkps_dir, "logs", "bkps.log")
    if not os.path.isfile(log_path):
        print_error(f"Log file not found: {log_path}")
        raise FileNotFoundError(log_path)

    print_info("Monitoring logs (Ctrl+C or press Enter to extract token)...")

    if os.name == 'nt':
        # Windows: no tail -f; read last 80 lines then wait briefly
        try:
            with open(log_path, errors='replace') as f:
                lines = f.readlines()
            for line in lines[-80:]:
                print(line.rstrip())
        except Exception:
            pass
        print_info("(Showing last 80 lines — re-run --monitor-logs for updates)")
        time.sleep(5)
    else:
        tail_proc = subprocess.Popen(["tail", "-f", log_path])
        try:
            select.select([sys.stdin], [], [], 60)
        except Exception:
            time.sleep(60)
        finally:
            tail_proc.terminate()

    print_info("\nExtracting initial token...")
    with open(log_path) as f:
        content = f.read()

    if "Temporary user access token:" in content:
        token = ""
        for line in content.splitlines():
            if "Temporary user access token:" in line:
                token = line.split("Temporary user access token:")[-1].strip().split()[0]
                break
        if not token:
            print_warning("Token line found but could not be parsed.")
            return
        print_success("\n=== Initial Temporary Token ===")
        print_info(f"Token: {token}")
        token_file = os.path.join(cfg.bkps_dir, ".initial_token")
        with open(token_file, "w") as f:
            f.write(token)
        print_success(f"Token saved to: {token_file}")
    else:
        print_warning("Token not found in logs yet. Server may still be starting.")


def get_bkps_token(cfg: Config) -> None:
    """Print the initial token from ``.initial_token`` or ``bkps.log``.

    Args:
        cfg: Config; uses ``cfg.bkps_dir``.
    """
    print_header("Initial Token")

    token_file = os.path.join(cfg.bkps_dir, ".initial_token")
    log_path = os.path.join(cfg.bkps_dir, "logs", "bkps.log")

    # Try to read from saved token file first
    if os.path.isfile(token_file):
        with open(token_file) as f:
            token = f.read().strip()
        if token:
            print_success("Token found in saved file:")
            print_info(f"File: {token_file}")
            print_info("")
            print_info(f"Token: {token}")
            print_info("")
            print_info("Use this token in Server Pipeline → Create + Activate Super Admin")
            return

    # Try to extract from logs if token file doesn't exist
    if os.path.isfile(log_path):
        from bkps_autosetup import extract_token_from_logs
        token = extract_token_from_logs(cfg)
        if token:
            print_success("Token extracted from logs:")
            print_info(f"Log file: {log_path}")
            print_info("")
            print_info(f"Token: {token}")
            print_info("")
            # Save it for future use
            with open(token_file, "w") as f:
                f.write(token)
            print_success(f"Token saved to: {token_file}")
            print_info("")
            print_info("Use this token in Server Pipeline → Create + Activate Super Admin")
            return

    # No token found anywhere
    print_warning("Initial token not found")
    print_info("")
    print_info("The token is generated when BKPS server starts for the first time.")
    print_info("")
    print_info("The token is written to bkps.log only on first-ever startup.")
    print_info("If a super admin already exists, no new token is generated.")
    print_info(f"Log file: {log_path}")


# ---------------------------------------------------------------------------
# check_bkps_health / diagnose_bkps_jar
# ---------------------------------------------------------------------------

# ── check_bkps_health / diagnose_bkps_jar ──────────────────────────────────────────

def check_bkps_health(cfg: Config) -> None:
    """Run ``runner.py health --detailed``.

    Args:
        cfg: Config forwarded to the admin-tools runner.
    """
    print_header("Checking BKPS Health")
    _runner(cfg, "health", "--detailed")


def diagnose_bkps_jar(cfg: Config) -> None:
    """List ``bkps*.jar`` and ``libs-ext`` and check for Spring Boot loader classes.

    Args:
        cfg: Config; uses ``cfg.bkps_dir``.
    """
    print_header("Diagnosing BKPS JAR Setup")

    print_info(f"BKPS Directory: {cfg.bkps_dir}")

    print()
    print_info("Checking JAR files:")
    jars = glob.glob(os.path.join(cfg.bkps_dir, "bkps*.jar"))
    if jars:
        for j in jars:
            size = os.path.getsize(j)
            print(f"  {os.path.basename(j)}  ({_human(size)})")
    else:
        print_error("No BKPS JAR files found")

    print()
    libs_ext = os.path.join(cfg.bkps_dir, "libs-ext")
    print_info("Checking libs-ext directory:")
    if os.path.isdir(libs_ext):
        entries = sorted(os.listdir(libs_ext))
        for e in entries[:20]:
            print(f"  {e}")
        if len(entries) > 20:
            print_info(f"... and {len(entries) - 20} more files")
    else:
        print_warning("libs-ext directory does not exist")

    print()
    print_info("Checking for spring-boot-loader:")
    sbl_files = glob.glob(os.path.join(libs_ext, "*spring-boot-loader*"))
    if sbl_files:
        for f in sbl_files:
            print(f"  {f}")
    else:
        print_warning("spring-boot-loader NOT found in libs-ext")
        print_info("This is required for PropertiesLauncher to work")

    print()
    if jars:
        jar = jars[0]
        print_info(f"JAR contents check: {os.path.basename(jar)}")
        result = subprocess.run(
            ["unzip", "-l", jar], capture_output=True, text=True
        )
        content = result.stdout
        if "org/springframework/boot/loader" in content:
            print_success("Contains Spring Boot loader classes - can be executed directly")
        else:
            print_warning("Does NOT contain Spring Boot loader classes")
            print_info("This is likely a thin JAR - needs spring-boot-loader in classpath")
        if "com/intel/bkp/bkps" in content:
            print_success("Contains BKPS application classes")
        else:
            print_warning("Does NOT contain BKPS application classes")


def _human(size: int) -> str:
    """Format a byte count as B/KB/MB/GB.

    Args:
        size: Size in bytes.
    """
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"

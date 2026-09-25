#!/usr/bin/env python3
"""Subprocess helpers (run, stream, get_output) and admin-tools runner.py invocation."""

import subprocess
import sys
import os
import select
import shutil
from typing import Optional, List, Union
from bkps_printer import print_error, print_warning
from bkps_config import Config


# ── Optional PTY support (Linux only) ───────────────────────────────────────
# pty / fcntl / termios are POSIX-only.  Import them conditionally so this
# module can be loaded on Windows (where stream() falls back to pipes).
try:
    import pty
    import fcntl
    import termios
    HAS_PTY = True
except ImportError:
    HAS_PTY = False


# ── Custom exception ────────────────────────────────────────────────────────
class AlreadyExistsError(RuntimeError):
    """Raised when a step is skipped because the resource already exists."""


# ── Line framing for streamed output ────────────────────────────────────────

def last_overwrite(line: str) -> str:
    """Return the final visible state of a line containing carriage returns."""
    if "\r" not in line:
        return line
    return line.rstrip("\r").split("\r")[-1]


def split_stream_chunk(buffer: str):
    """Split accumulated subprocess output into whole lines plus a remainder.

    Only newline-terminated lines are returned. A consumer such as the GUI's
    StdoutCapture frames on "\\n", so writing an unterminated fragment makes it
    hold the fragment and glue the next message onto its end. A trailing
    carriage-return group is resolved to its final overwrite state so progress
    indicators still advance, one line per read rather than one per update.
    """
    lines = []
    while "\n" in buffer:
        line, buffer = buffer.split("\n", 1)
        lines.append(last_overwrite(line))
    if "\r" in buffer:
        completed, _, buffer = buffer.rpartition("\r")
        state = last_overwrite(completed)
        if state.strip():
            lines.append(state)
    return lines, buffer


# ── PowerShell wrapper (Windows only) ────────────────────────────────────────
def _ps_run(
    cmd: Union[str, List[str]],
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    capture: bool = False,
    check: bool = True,
    input_text: Optional[str] = None):

    """Run cmd via PowerShell on Windows, or /bin/sh on POSIX."""
    if sys.platform.startswith("win"):
        return run(
            ["powershell.exe", "-NoProfile", "-Command", cmd],
            cwd=cwd, check=check, env=env, capture=capture, input_text=input_text
        )
    # POSIX path: shell=True keeps /bin/sh semantics identical to the pre-
    # refactor behaviour (all quartus_* invocations in this module used to
    # go through ``run([...], shell=True)``).
    return run(cmd, cwd=cwd, env=env, capture=capture, check=check, shell=True, input_text=input_text)


# ── Core execution helpers ────────────────────────────────────────────────────

def run(
    cmd: Union[str, List[str]],
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    capture: bool = False,
    check: bool = True,
    shell: bool = False,
    input_text: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Run a command, optionally capturing stdout/stderr.

    Args:
        cmd: Command string (requires shell=True) or argument list.
        capture: If True, capture stdout+stderr instead of streaming them.
        check: If True, raise CalledProcessError on non-zero exit.
        input_text: Optional text written to stdin.
    """
    full_env = {**os.environ, **(env or {})}  # caller's env overrides inherited env

    if capture:
        # Capture silently and return output in CompletedProcess
        kwargs = dict(
            cwd=cwd, env=full_env, shell=shell,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        if input_text is not None:
            kwargs["input"] = input_text
        try:
            result = subprocess.run(cmd, **kwargs)
        except FileNotFoundError as e:
            print_error(f"Command not found: {e}")
            if check:
                raise
            return subprocess.CompletedProcess(cmd, 127, "", str(e))
        if check and result.returncode != 0:
            if result.stderr:
                print_error(result.stderr.strip())
            raise subprocess.CalledProcessError(
                result.returncode, cmd, result.stdout, result.stderr
            )
        return result
    else:
        # Stream output through sys.stdout line-by-line.
        # This means GUI mode (StdoutCapture) intercepts every line,
        # while CLI mode sees it on the terminal as before.
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=cwd, env=full_env, shell=shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # merge stderr into stdout stream
                text=True,
                bufsize=1,             # line-buffered; reduces latency for long-running cmds
                stdin=subprocess.PIPE if input_text else None,
            )
            if input_text:
                try:
                    proc.stdin.write(input_text)
                    proc.stdin.close()
                except Exception:
                    pass
            for line in proc.stdout:
                sys.stdout.write(last_overwrite(line.rstrip("\r\n")) + "\n")
                sys.stdout.flush()
            proc.wait()
        except FileNotFoundError as e:
            print_error(f"Command not found: {e}")
            if check:
                raise
            return subprocess.CompletedProcess(cmd, 127, "", str(e))

        if check and proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, cmd)
        return subprocess.CompletedProcess(cmd, proc.returncode, "", "")


# ── Streaming execution (real-time output) ─────────────────────────────────────

def stream(
    cmd: Union[str, List[str]],
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    shell: bool = False,
    input_text: Optional[str] = None,
    log_file: Optional[str] = None,
) -> int:
    """Run a command and stream output to stdout (PTY on Linux, pipes otherwise).

    Args:
        log_file: If set, append the same output lines to this file.
    """
    full_env = {**os.environ, **(env or {})}  # caller's env overrides inherited env
    lf = open(log_file, "a") if log_file else None  # open in append mode; logs accumulate

    try:
        # Try PTY-based execution first (Linux only)
        # This tricks Gradle/Java into thinking they're connected to a real terminal
        if HAS_PTY and os.name == 'posix':
            return _stream_pty(cmd, cwd, full_env, shell, input_text, lf)
        else:
            return _stream_pipe(cmd, cwd, full_env, shell, input_text, lf)
    finally:
        if lf:
            lf.close()


def _stream_pty(cmd, cwd, env, shell, input_text, lf) -> int:
    """Stream subprocess output through a PTY (Linux)."""
    master_fd, slave_fd = pty.openpty()  # create a new PTY pair

    def emit(lines):
        for line in lines:
            sys.stdout.write(line + '\n')
            sys.stdout.flush()
            if lf:
                lf.write(line + '\n')

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            shell=shell,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,  # merge all streams through the PTY slave
        )
        os.close(slave_fd)  # parent doesn't need the slave end; only the subprocess does

        if input_text:
            os.write(master_fd, input_text.encode())

        # Read output from PTY master
        buffer = ""
        while True:
            try:
                # Use select to check if data is available
                rlist, _, _ = select.select([master_fd], [], [], 0.1)
                if not rlist:
                    # No data available; if process is done, drain then exit
                    if proc.poll() is not None:
                        # Drain any data still sitting in the PTY buffer
                        # (the kernel may buffer a few bytes after the process exits)
                        try:
                            while True:
                                r2, _, _ = select.select([master_fd], [], [], 0.05)
                                if not r2:
                                    break
                                chunk = os.read(master_fd, 4096)
                                if not chunk:
                                    break
                                buffer += chunk.decode('utf-8', errors='replace')
                                lines, buffer = split_stream_chunk(buffer)
                                emit(lines)
                        except OSError:
                            pass
                        break
                    continue

                data = os.read(master_fd, 4096)
                if not data:
                    break

                # 'replace' handles any non-UTF-8 bytes from the PTY
                buffer += data.decode('utf-8', errors='replace')
                lines, buffer = split_stream_chunk(buffer)
                emit(lines)

            except OSError:
                break

        # Output any remaining buffer
        if buffer.strip():
            emit([last_overwrite(buffer)])

        proc.wait()
        return proc.returncode
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass


def _stream_pipe(cmd, cwd, env, shell, input_text, lf) -> int:
    """Stream subprocess output through pipes (Windows / non-POSIX fallback)."""
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=env,
        shell=shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,  # Line buffered: each \n flushes the internal buffer
        stdin=subprocess.PIPE if input_text else None,
    )

    if input_text:
        proc.stdin.write(input_text)
        proc.stdin.close()

    # Read output in real-time; readline() blocks until '\n' or EOF,
    # so we break only when the line is empty AND the process has exited.
    while True:
        line = proc.stdout.readline()
        if not line and proc.poll() is not None:
            break
        if line:
            rendered = last_overwrite(line.rstrip("\r\n")) + "\n"
            sys.stdout.write(rendered)
            sys.stdout.flush()
            if lf:
                lf.write(rendered)

    proc.wait()
    return proc.returncode


# ── Utility helpers ────────────────────────────────────────────────────────────

def command_exists(name: str) -> bool:
    """Return True if ``name`` is on PATH."""
    return shutil.which(name) is not None


def get_output(
    cmd: Union[str, List[str]],
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    shell: bool = False,
    default: str = ""
) -> str:
    """Run cmd and return stripped stdout, or ``default`` on any error."""
    try:
        result = run(cmd, cwd=cwd, env=env, capture=True, check=False, shell=shell)
        return result.stdout.strip() if result.stdout else default
    except Exception:
        return default


def run_runner_tool(
    cfg: Config,
    *args,
    capture: bool = False,
    check: bool = True,
    env: Optional[dict] = None,
    skip_if: Optional[List[str]] = None,
):
    """Invoke admin-tools/runner.py with the given positional arguments.

    Args:
        capture: Always captures stdout; when False, also echo it after the call.
        check: Raise on non-zero exit or a non-2xx ``Status:`` line.
        skip_if: Substrings that treat a failed run as skipped instead of raising.
    """
    cmd = [sys.executable, "runner.py"] + list(args)
    cwd = os.path.join(cfg.bkps_dir, "admin-tools")
    safe_args, secret_values = _redact_sensitive_arguments(
        args, frozenset({"--token"})
    )
    safe_command = " ".join(safe_args)
    try:
        # Always capture — see the docstring "IMPORTANT" note.
        result = run(cmd, cwd=cwd, capture=True, check=False, env=env)
    except Exception:
        print_error(f"runner.py command failed: {safe_command}")
        print_error("Common causes:")
        print_error("  1. BKPS server is not running")
        print_error("  2. runner-config.json not configured")
        print_error("  3. Super admin not created yet (need initial token)")
        print_error("  4. Certificate authentication failed")
        raise

    safe_stdout = _redact_values(result.stdout or "", secret_values)
    safe_stderr = _redact_values(result.stderr or "", secret_values)
    safe_result = subprocess.CompletedProcess(
        [sys.executable, "runner.py", *safe_args],
        result.returncode,
        safe_stdout,
        safe_stderr,
    )

    if not capture and safe_stdout:
        for line in safe_stdout.splitlines():
            print(line)

    if check:
        http_failure = _scan_runner_http_status(safe_stdout, safe_stderr)
        if safe_result.returncode != 0 or http_failure is not None:
            if skip_if:
                for skip in skip_if:
                    if skip in safe_stdout:
                        print_warning(
                            "runner.py already in expected state, skipping: "
                            f"{safe_command}"
                        )
                        return safe_result
            print_error(f"runner.py command failed: {safe_command}")
            err_tail = (safe_stderr or "").strip()
            out_tail = (safe_stdout or "").strip()
            if err_tail:
                print_error(f"runner.py stderr: {err_tail[:800]}")
            if http_failure is not None:
                code, reason = http_failure
                raise RuntimeError(
                    f"runner.py {safe_command} failed: "
                    f"HTTP {code} {reason} "
                    f"(runner.py exit was {safe_result.returncode})"
                    + (f"\nstderr: {err_tail[:800]}" if err_tail else "")
                    + (f"\nstdout: {out_tail[:800]}" if out_tail else "")
                )
            raise RuntimeError(
                f"runner.py {safe_command} failed "
                f"(exit {safe_result.returncode})"
                + (f"\nstderr: {err_tail[:800]}" if err_tail else "")
                + (f"\nstdout: {out_tail[:800]}" if out_tail else "")
            )

    return safe_result


def _redact_sensitive_arguments(arguments, sensitive_options):
    """Return display-safe arguments and exact secret values to scrub."""
    values = [str(argument) for argument in arguments]
    redacted = list(values)
    secrets = []
    index = 0
    while index < len(values):
        argument = values[index]
        if argument in sensitive_options and index + 1 < len(values):
            secret = values[index + 1]
            if secret:
                secrets.append(secret)
            redacted[index + 1] = "[REDACTED]"
            index += 2
            continue
        for option in sensitive_options:
            prefix = option + "="
            if argument.startswith(prefix):
                secret = argument[len(prefix):]
                if secret:
                    secrets.append(secret)
                redacted[index] = prefix + "[REDACTED]"
                break
        index += 1
    return redacted, tuple(dict.fromkeys(secrets))


def _redact_values(text, secret_values):
    """Remove exact sensitive argument values from child-process output."""
    safe_text = text
    for value in secret_values:
        if value:
            safe_text = safe_text.replace(value, "[REDACTED]")
    return safe_text


def _scan_runner_http_status(stdout, stderr):
    """Return ``(code, reason)`` for the first non-2xx ``Status:`` line, else ``None``.
    """
    import re as _re
    combined = (stdout or "") + (stderr or "")
    for m in _re.finditer(r"Status:\s*(\d{3})\s*([^\r\n]*)", combined):
        code = int(m.group(1))
        if not (200 <= code < 300):
            return (code, m.group(2).strip())
    return None

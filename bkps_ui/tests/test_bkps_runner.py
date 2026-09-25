#!/usr/bin/env python3
"""Unit tests for bkps_runner subprocess helpers and runner.py invocation."""

from __future__ import annotations

import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

TOOL_ROOT = Path(__file__).resolve().parents[1]
if str(TOOL_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOL_ROOT))

import bkps_runner as runner  # noqa: E402

# Windows cannot import the POSIX-only pty module. The PTY helper tests mock
# every OS interaction, so provide only the namespace they need to patch.
if not hasattr(runner, "pty"):
    runner.pty = SimpleNamespace()


class FramingTests(unittest.TestCase):
    def test_last_overwrite_without_cr(self):
        self.assertEqual(runner.last_overwrite("hello"), "hello")

    def test_last_overwrite_with_cr(self):
        self.assertEqual(runner.last_overwrite("a\rb\rc"), "c")

    def test_split_stream_chunk_newlines(self):
        lines, rem = runner.split_stream_chunk("one\ntwo\npartial")
        self.assertEqual(lines, ["one", "two"])
        self.assertEqual(rem, "partial")

    def test_split_stream_chunk_cr_progress(self):
        lines, rem = runner.split_stream_chunk("prog\rprog2\r")
        self.assertEqual(lines, ["prog2"])
        self.assertEqual(rem, "")


class RedactionTests(unittest.TestCase):
    def test_redact_space_separated_token(self):
        redacted, secrets = runner._redact_sensitive_arguments(
            ["user", "list", "--token", "SECRET"],
            frozenset({"--token"}),
        )
        self.assertEqual(redacted[3], "[REDACTED]")
        self.assertEqual(secrets, ("SECRET",))

    def test_redact_equals_form_and_empty_secret(self):
        redacted, secrets = runner._redact_sensitive_arguments(
            ["--token=", "ok", "--token=ABC"],
            frozenset({"--token"}),
        )
        self.assertEqual(redacted[0], "--token=[REDACTED]")
        self.assertEqual(redacted[2], "--token=[REDACTED]")
        self.assertEqual(secrets, ("ABC",))

    def test_redact_values(self):
        self.assertEqual(
            runner._redact_values("token SECRET here", ("SECRET",)),
            "token [REDACTED] here",
        )


class HttpStatusScanTests(unittest.TestCase):
    def test_ignores_2xx(self):
        self.assertIsNone(
            runner._scan_runner_http_status("Status: 200 OK\n", "")
        )

    def test_returns_first_non_2xx(self):
        self.assertEqual(
            runner._scan_runner_http_status(
                "Status: 200 OK\nStatus: 401 Unauthorized\n", ""
            ),
            (401, "Unauthorized"),
        )


class RunHelperTests(unittest.TestCase):
    def test_capture_success(self):
        ok = subprocess.CompletedProcess(["echo"], 0, "hi", "")
        with patch("bkps_runner.subprocess.run", return_value=ok) as m:
            result = runner.run(["echo"], capture=True, check=True)
        self.assertEqual(result.stdout, "hi")
        m.assert_called_once()

    def test_capture_nonzero_raises(self):
        bad = subprocess.CompletedProcess(["x"], 1, "", "boom")
        with patch("bkps_runner.subprocess.run", return_value=bad):
            with self.assertRaises(subprocess.CalledProcessError):
                runner.run(["x"], capture=True, check=True)

    def test_capture_file_not_found_check_false(self):
        with patch(
            "bkps_runner.subprocess.run",
            side_effect=FileNotFoundError("missing"),
        ):
            result = runner.run(["missing"], capture=True, check=False)
        self.assertEqual(result.returncode, 127)

    def test_capture_file_not_found_check_true(self):
        with patch(
            "bkps_runner.subprocess.run",
            side_effect=FileNotFoundError("missing"),
        ):
            with self.assertRaises(FileNotFoundError):
                runner.run(["missing"], capture=True, check=True)

    def test_stream_path_reads_stdout(self):
        proc = MagicMock()
        proc.stdout = iter(["line1\n", "line2\n"])
        proc.returncode = 0
        proc.wait.return_value = 0
        with patch("bkps_runner.subprocess.Popen", return_value=proc):
            result = runner.run(["echo"], capture=False, check=True)
        self.assertEqual(result.returncode, 0)

    def test_stream_file_not_found_check_false(self):
        with patch(
            "bkps_runner.subprocess.Popen",
            side_effect=FileNotFoundError("gone"),
        ):
            result = runner.run(["gone"], capture=False, check=False)
        self.assertEqual(result.returncode, 127)

    def test_stream_nonzero_raises(self):
        proc = MagicMock()
        proc.stdout = iter([])
        proc.returncode = 3
        proc.wait.return_value = 3
        with patch("bkps_runner.subprocess.Popen", return_value=proc):
            with self.assertRaises(subprocess.CalledProcessError):
                runner.run(["fail"], capture=False, check=True)

    def test_stream_input_text_write_error_ignored(self):
        proc = MagicMock()
        proc.stdout = iter([])
        proc.returncode = 0
        proc.wait.return_value = 0
        proc.stdin.write.side_effect = OSError("broken")
        with patch("bkps_runner.subprocess.Popen", return_value=proc):
            result = runner.run(
                ["echo"], capture=False, check=True, input_text="x"
            )
        self.assertEqual(result.returncode, 0)


class StreamPipeTests(unittest.TestCase):
    def test_stream_forces_pipe_when_no_pty(self):
        proc = MagicMock()
        proc.stdout.readline.side_effect = ["hello\n", ""]
        proc.poll.return_value = 0
        proc.wait.return_value = 0
        proc.returncode = 0
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "out.log"
            with patch.object(runner, "HAS_PTY", False), patch(
                "bkps_runner.subprocess.Popen", return_value=proc
            ):
                code = runner.stream(
                    ["echo"], log_file=str(log_path), input_text="in"
                )
            self.assertEqual(code, 0)
            self.assertIn("hello", log_path.read_text())

    def test_stream_pipe_direct(self):
        proc = MagicMock()
        proc.stdout.readline.side_effect = ["a\n", ""]
        proc.poll.return_value = 0
        proc.wait.return_value = 0
        proc.returncode = 0
        with patch("bkps_runner.subprocess.Popen", return_value=proc):
            code = runner._stream_pipe(
                ["echo"], None, {}, False, None, None
            )
        self.assertEqual(code, 0)


class StreamPtyTests(unittest.TestCase):
    def test_stream_pty_happy_path(self):
        proc = MagicMock()
        proc.poll.side_effect = [None, 0]
        proc.wait.return_value = 0
        proc.returncode = 0
        master_fd, slave_fd = 10, 11
        reads = [b"line1\n", b""]

        def fake_select(rlist, _w, _x, _t):
            if rlist == [master_fd] and reads and reads[0]:
                return ([master_fd], [], [])
            return ([], [], [])

        def fake_read(_fd, _n):
            return reads.pop(0) if reads else b""

        with patch("bkps_runner.pty.openpty", return_value=(master_fd, slave_fd), create=True), patch(
            "bkps_runner.subprocess.Popen", return_value=proc
        ), patch("bkps_runner.os.close"), patch(
            "bkps_runner.select.select", side_effect=fake_select
        ), patch("bkps_runner.os.read", side_effect=fake_read), patch(
            "bkps_runner.os.write"
        ):
            code = runner._stream_pty(
                ["echo"], None, {}, False, "hi", None
            )
        self.assertEqual(code, 0)

    def test_stream_pty_oserror_breaks(self):
        proc = MagicMock()
        proc.poll.return_value = None
        proc.wait.return_value = 1
        proc.returncode = 1
        with patch("bkps_runner.pty.openpty", return_value=(10, 11), create=True), patch(
            "bkps_runner.subprocess.Popen", return_value=proc
        ), patch("bkps_runner.os.close"), patch(
            "bkps_runner.select.select", side_effect=OSError("gone")
        ):
            code = runner._stream_pty(["echo"], None, {}, False, None, None)
        self.assertEqual(code, 1)

    def test_stream_pty_drain_on_exit_and_remaining_buffer(self):
        proc = MagicMock()
        # First select timeout with process still running, then process done
        proc.poll.side_effect = [None, 0]
        proc.wait.return_value = 0
        proc.returncode = 0
        master_fd, slave_fd = 20, 21
        select_calls = {"n": 0}

        def fake_select(rlist, _w, _x, timeout):
            select_calls["n"] += 1
            # First call: no data, process still running (poll returns None)
            if select_calls["n"] == 1:
                return ([], [], [])
            # Second call: no data, process done -> enter drain
            if select_calls["n"] == 2:
                return ([], [], [])
            # Drain select finds data once then empty
            if select_calls["n"] == 3:
                return ([master_fd], [], [])
            return ([], [], [])

        reads = [b"leftover"]

        def fake_read(_fd, _n):
            return reads.pop(0) if reads else b""

        def fake_close(fd):
            if fd == master_fd:
                raise OSError("already")

        lf = MagicMock()
        with patch("bkps_runner.pty.openpty", return_value=(master_fd, slave_fd), create=True), patch(
            "bkps_runner.subprocess.Popen", return_value=proc
        ), patch("bkps_runner.os.close", side_effect=fake_close), patch(
            "bkps_runner.select.select", side_effect=fake_select
        ), patch("bkps_runner.os.read", side_effect=fake_read):
            code = runner._stream_pty(
                ["echo"], None, {}, False, None, lf
            )
        self.assertEqual(code, 0)
        lf.write.assert_called()

    def test_capture_with_input_text(self):
        ok = subprocess.CompletedProcess(["echo"], 0, "hi", "")
        with patch("bkps_runner.subprocess.run", return_value=ok) as m:
            runner.run(["echo"], capture=True, input_text="stdin")
        self.assertEqual(m.call_args.kwargs.get("input"), "stdin")

    def test_stream_file_not_found_check_true(self):
        with patch(
            "bkps_runner.subprocess.Popen",
            side_effect=FileNotFoundError("gone"),
        ):
            with self.assertRaises(FileNotFoundError):
                runner.run(["gone"], capture=False, check=True)

    def test_stream_uses_pty_when_available(self):
        with patch.object(runner, "HAS_PTY", True), patch(
            "bkps_runner.os.name", "posix"
        ), patch.object(runner, "_stream_pty", return_value=7) as pty_m:
            code = runner.stream(["echo"])
        self.assertEqual(code, 7)
        pty_m.assert_called_once()


class UtilityTests(unittest.TestCase):
    def test_command_exists(self):
        with patch("bkps_runner.shutil.which", return_value="/bin/true"):
            self.assertTrue(runner.command_exists("true"))
        with patch("bkps_runner.shutil.which", return_value=None):
            self.assertFalse(runner.command_exists("nope"))

    def test_get_output_success(self):
        ok = subprocess.CompletedProcess(["x"], 0, "  out  ", "")
        with patch.object(runner, "run", return_value=ok):
            self.assertEqual(runner.get_output(["x"]), "out")

    def test_get_output_default_on_exception(self):
        with patch.object(runner, "run", side_effect=RuntimeError("x")):
            self.assertEqual(runner.get_output(["x"], default="d"), "d")

    def test_ps_run_windows(self):
        with patch.object(runner.sys, "platform", "win32"), patch.object(
            runner, "run", return_value=subprocess.CompletedProcess([], 0)
        ) as m:
            runner._ps_run("echo hi")
        self.assertEqual(m.call_args.args[0][0], "powershell.exe")

    def test_ps_run_posix(self):
        with patch.object(runner.sys, "platform", "linux"), patch.object(
            runner, "run", return_value=subprocess.CompletedProcess([], 0)
        ) as m:
            runner._ps_run("echo hi")
        self.assertTrue(m.call_args.kwargs.get("shell"))


class RunRunnerToolTests(unittest.TestCase):
    def setUp(self):
        self.cfg = SimpleNamespace(bkps_dir="/tmp/bkps")

    def test_success_echoes_stdout(self):
        ok = subprocess.CompletedProcess(
            ["runner"], 0, "Status: 200 OK\nok\n", ""
        )
        buf = io.StringIO()
        with patch.object(runner, "run", return_value=ok), patch(
            "sys.stdout", buf
        ):
            result = runner.run_runner_tool(
                self.cfg, "health", capture=False, check=True
            )
        self.assertEqual(result.returncode, 0)
        self.assertIn("ok", buf.getvalue())

    def test_redacts_token_in_failure_message(self):
        bad = subprocess.CompletedProcess(
            ["runner"], 1, "Status: 401 Unauthorized\nSECRET leaked\n", "err"
        )
        with patch.object(runner, "run", return_value=bad):
            with self.assertRaises(RuntimeError) as ctx:
                runner.run_runner_tool(
                    self.cfg, "--token", "SECRET", "user", "list"
                )
        self.assertNotIn("SECRET", str(ctx.exception))
        self.assertIn("[REDACTED]", str(ctx.exception))

    def test_skip_if_swallows_failure(self):
        bad = subprocess.CompletedProcess(
            ["runner"], 1, "already exists here", ""
        )
        with patch.object(runner, "run", return_value=bad):
            result = runner.run_runner_tool(
                self.cfg,
                "root-signing-key",
                "add",
                check=True,
                skip_if=["already exists"],
            )
        self.assertEqual(result.returncode, 1)

    def test_check_false_returns_failure(self):
        bad = subprocess.CompletedProcess(["runner"], 5, "nope", "")
        with patch.object(runner, "run", return_value=bad):
            result = runner.run_runner_tool(
                self.cfg, "health", check=False, capture=True
            )
        self.assertEqual(result.returncode, 5)

    def test_run_exception_reraises(self):
        with patch.object(runner, "run", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                runner.run_runner_tool(self.cfg, "health")

    def test_nonzero_without_http_raises(self):
        bad = subprocess.CompletedProcess(["runner"], 2, "plain fail", "se")
        with patch.object(runner, "run", return_value=bad):
            with self.assertRaises(RuntimeError) as ctx:
                runner.run_runner_tool(self.cfg, "health")
        self.assertIn("exit 2", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

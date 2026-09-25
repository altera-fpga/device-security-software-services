#!/usr/bin/env python3
"""Unit tests for bkps_server with mocked sockets, subprocess, and filesystem."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

TOOL_DIR = Path(__file__).resolve().parents[1]
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

import bkps_server as srv  # noqa: E402


def setUpModule():
    # Progress messages contain Unicode glyphs; a narrow console codec (cp1252)
    # would turn an incidental print into a UnicodeEncodeError.
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(errors="replace")


def _cfg(root: str, **kwargs):
    base = dict(
        bkps_dir=root,
        bkps_server_port="8082",
        profile_name="agilex5",
        security_provider="bouncycastle",
    )
    base.update(kwargs)
    return SimpleNamespace(**base)


def _cp(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


def _prepare_runtime(root: str):
    Path(root, "bkps-app.jar").write_bytes(b"jar")
    Path(root, "keys").mkdir(parents=True, exist_ok=True)
    Path(root, "keys", "bkps_keystore.p12").write_bytes(b"p12")
    Path(root, "config").mkdir(parents=True, exist_ok=True)
    Path(root, "config", "application-agilex5.yml").write_text("x")


class HelperTests(unittest.TestCase):
    def test_is_bkps_server_running(self):
        cfg = _cfg(".", bkps_server_port="bad")
        self.assertFalse(srv.is_bkps_server_running(cfg))
        with mock.patch.object(srv, "_is_port_listening", return_value=True):
            cfg.bkps_server_port = "8082"
            self.assertTrue(srv.is_bkps_server_running(cfg))

    def test_human_sizes(self):
        self.assertIn("B", srv._human(10))
        self.assertIn("KB", srv._human(2048))
        self.assertIn("MB", srv._human(2 * 1024 * 1024))
        self.assertIn("GB", srv._human(2 * 1024 ** 3))
        self.assertIn("GB", srv._human(2 * 1024 ** 4))

    def test_parse_pid(self):
        self.assertEqual(srv._parse_pid_from_tool_output("1234\n"), 1234)
        self.assertEqual(srv._parse_pid_from_tool_output("abc"), 0)

    def test_is_port_listening(self):
        sock = mock.Mock()
        sock.connect_ex.return_value = 0
        with mock.patch.object(srv.socket, "socket", return_value=sock):
            self.assertTrue(srv._is_port_listening(8082))
        sock.connect_ex.side_effect = OSError("fail")
        with mock.patch.object(srv.socket, "socket", return_value=sock):
            self.assertFalse(srv._is_port_listening(8082))

    def test_validate_runtime(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(FileNotFoundError):
                srv._validate_bkps_server_runtime(_cfg(td))
            Path(td, "bkps.jar").write_bytes(b"x")
            with self.assertRaises(FileNotFoundError):
                srv._validate_bkps_server_runtime(_cfg(td))
            _prepare_runtime(td)
            self.assertTrue(srv._validate_bkps_server_runtime(_cfg(td)).endswith(".jar"))


class StartStopTests(unittest.TestCase):
    def test_start_bkps_server_linux_success(self):
        with tempfile.TemporaryDirectory() as td:
            _prepare_runtime(td)
            cfg = _cfg(td, security_provider="ncipher")
            with mock.patch.object(srv.os, "name", "posix"), \
                 mock.patch.object(srv, "_is_port_listening", side_effect=[False, True]), \
                 mock.patch.object(srv, "_find_pid_on_port", return_value=4242), \
                 mock.patch.object(srv, "_launch_in_terminal", return_value=True), \
                 mock.patch.object(srv.time, "sleep"):
                self.assertTrue(srv.start_bkps_server(cfg, extra_flags="--x"))
            self.assertTrue(Path(td, "start_bkps.sh").is_file())
            self.assertEqual(Path(td, "bkps.pid").read_text(), "4242")

    def test_start_bkps_server_windows_and_port_busy(self):
        with tempfile.TemporaryDirectory() as td:
            _prepare_runtime(td)
            cfg = _cfg(td, bkps_server_port="not-int")
            with mock.patch.object(srv.os, "name", "nt"), \
                 mock.patch.object(
                     srv, "_is_port_listening", side_effect=[True, False, True]
                 ), \
                 mock.patch.object(srv, "_find_pid_on_port", return_value=99), \
                 mock.patch.object(srv, "stop_bkps_server"), \
                 mock.patch.object(srv, "_launch_in_terminal", return_value=True), \
                 mock.patch.object(srv, "_find_pid_on_port", return_value=0), \
                 mock.patch.object(srv.time, "sleep"):
                # Re-patch carefully: first listening True with pid, then free, then up
                pass

            listen_seq = [True, False, True]
            find_seq = [55, 0]

            def listening(_port):
                return listen_seq.pop(0) if listen_seq else True

            def find_pid(_port):
                return find_seq.pop(0) if find_seq else 0

            with mock.patch.object(srv.os, "name", "nt"), \
                 mock.patch.object(srv, "_is_port_listening", side_effect=listening), \
                 mock.patch.object(srv, "_find_pid_on_port", side_effect=find_pid), \
                 mock.patch.object(srv, "stop_bkps_server"), \
                 mock.patch.object(srv, "_launch_in_terminal", return_value=True), \
                 mock.patch.object(srv.time, "sleep"):
                self.assertTrue(srv.start_bkps_server(cfg))
            self.assertTrue(Path(td, "start_bkps.bat").is_file())

    def test_start_port_still_busy_and_launch_fail(self):
        with tempfile.TemporaryDirectory() as td:
            _prepare_runtime(td)
            cfg = _cfg(td)
            with mock.patch.object(srv, "_is_port_listening", return_value=True), \
                 mock.patch.object(srv, "_find_pid_on_port", return_value=7), \
                 mock.patch.object(srv, "stop_bkps_server"), \
                 mock.patch.object(srv, "_describe_port_owner", return_value="owner"), \
                 mock.patch.object(srv.time, "sleep"):
                with self.assertRaises(RuntimeError):
                    srv.start_bkps_server(cfg)

            with mock.patch.object(srv, "_is_port_listening", return_value=False), \
                 mock.patch.object(srv, "_launch_in_terminal", return_value=False):
                self.assertFalse(srv.start_bkps_server(cfg))

            with mock.patch.object(srv, "_is_port_listening", side_effect=[False, False]), \
                 mock.patch.object(srv, "_launch_in_terminal", return_value=None), \
                 mock.patch.object(srv, "_find_pid_on_port", return_value=0), \
                 mock.patch.object(srv.time, "sleep"):
                self.assertFalse(srv.start_bkps_server(cfg))

            # PID write failure + port up without pid
            with mock.patch.object(srv, "_is_port_listening", side_effect=[False, True]), \
                 mock.patch.object(srv, "_launch_in_terminal", return_value=True), \
                 mock.patch.object(srv, "_find_pid_on_port", return_value=0), \
                 mock.patch.object(srv.time, "sleep"):
                self.assertTrue(srv.start_bkps_server(cfg))

            with mock.patch.object(srv, "_is_port_listening", side_effect=[False, True]), \
                 mock.patch.object(srv, "_launch_in_terminal", return_value=True), \
                 mock.patch.object(srv, "_find_pid_on_port", return_value=9), \
                 mock.patch.object(srv.time, "sleep"), \
                 mock.patch("builtins.open", side_effect=OSError("no write")):
                # open is used for log clear and script too — need more surgical mock
                pass

            real_open = open

            def selective_open(path, *a, **k):
                if str(path).endswith("bkps.pid"):
                    raise OSError("no write")
                return real_open(path, *a, **k)

            with mock.patch.object(srv, "_is_port_listening", side_effect=[False, True]), \
                 mock.patch.object(srv, "_launch_in_terminal", return_value=True), \
                 mock.patch.object(srv, "_find_pid_on_port", return_value=9), \
                 mock.patch.object(srv.time, "sleep"), \
                 mock.patch("builtins.open", side_effect=selective_open):
                self.assertTrue(srv.start_bkps_server(cfg))

    def test_launch_in_terminal(self):
        cfg = _cfg(".")
        with mock.patch.object(srv.subprocess, "Popen", return_value=mock.Mock()), \
             mock.patch.object(srv, "show_logs", return_value=True) as show:
            self.assertTrue(srv._launch_in_terminal(cfg, "/tmp/x.sh", "/tmp/l"))
            show.assert_called_once()
        with mock.patch.object(srv.subprocess, "Popen", return_value=None):
            self.assertIsNone(srv._launch_in_terminal(cfg, "/tmp/x.sh", "/tmp/l"))

    def test_stop_and_kill(self):
        cfg = _cfg(".", bkps_server_port="8082")
        with mock.patch.object(srv, "_find_pid_on_port", return_value=11), \
             mock.patch.object(srv, "_kill_pid") as kill:
            srv.stop_bkps_server(cfg)
            kill.assert_called_once()

        with mock.patch.object(srv, "_find_pid_on_port", return_value=0), \
             mock.patch.object(srv, "_is_port_listening", return_value=False):
            srv.stop_bkps_server(cfg)

        with mock.patch.object(srv, "_find_pid_on_port", return_value=0), \
             mock.patch.object(srv, "_is_port_listening", return_value=True):
            srv.stop_bkps_server(cfg)

        cfg.bkps_server_port = "0"
        srv.stop_bkps_server(cfg)
        cfg.bkps_server_port = "bad"
        with self.assertRaises(ValueError):
            srv.stop_bkps_server(cfg)

        srv._kill_pid(0)
        with mock.patch.object(srv.os, "name", "nt"), \
             mock.patch.object(srv.subprocess, "run") as run:
            srv._kill_pid(5)
            run.assert_called_once()
        with mock.patch.object(srv.os, "name", "nt"), \
             mock.patch.object(srv.subprocess, "run", side_effect=OSError("x")):
            srv._kill_pid(5)
        with mock.patch.object(srv.os, "name", "posix"), \
             mock.patch.object(srv.os, "kill") as kill:
            srv._kill_pid(5)
            kill.assert_called_once()
        with mock.patch.object(srv.os, "name", "posix"), \
             mock.patch.object(srv.os, "kill", side_effect=ProcessLookupError()):
            srv._kill_pid(5)


class PortOwnerTests(unittest.TestCase):
    def test_find_pid_windows(self):
        out = "  TCP    0.0.0.0:8082    0.0.0.0:0    LISTENING    1234\n"
        with mock.patch.object(srv.os, "name", "nt"), \
             mock.patch.object(srv.subprocess, "run", return_value=_cp(0, out=out)):
            self.assertEqual(srv._find_pid_on_port(8082), 1234)
        with mock.patch.object(srv.os, "name", "nt"), \
             mock.patch.object(srv.subprocess, "run", side_effect=OSError()):
            self.assertEqual(srv._find_pid_on_port(8082), 0)
        out_bad = "  TCP    0.0.0.0:8082    0.0.0.0:0    LISTENING    xyz\n"
        with mock.patch.object(srv.os, "name", "nt"), \
             mock.patch.object(srv.subprocess, "run", return_value=_cp(0, out=out_bad)):
            self.assertEqual(srv._find_pid_on_port(8082), 0)

    def test_find_pid_linux_tools(self):
        with mock.patch.object(srv.os, "name", "posix"), \
             mock.patch.object(srv, "command_exists", side_effect=lambda t: t == "lsof"), \
             mock.patch.object(
                 srv.subprocess, "run", return_value=_cp(0, out="999\n")
             ):
            self.assertEqual(srv._find_pid_on_port(1), 999)

        with mock.patch.object(srv.os, "name", "posix"), \
             mock.patch.object(srv, "command_exists", side_effect=lambda t: t == "lsof"), \
             mock.patch.object(srv.subprocess, "run", side_effect=OSError()):
            self.assertEqual(srv._find_pid_on_port(1), 0)

        ss_out = 'LISTEN 0 128 *:8082 users:(("java",pid=777,fd=42))\n'
        with mock.patch.object(srv.os, "name", "posix"), \
             mock.patch.object(
                 srv, "command_exists",
                 side_effect=lambda t: t in ("ss",),
             ), \
             mock.patch.object(
                 srv.subprocess, "run", return_value=_cp(0, out=ss_out)
             ):
            self.assertEqual(srv._find_pid_on_port(8082), 777)

        with mock.patch.object(srv.os, "name", "posix"), \
             mock.patch.object(
                 srv, "command_exists",
                 side_effect=lambda t: t == "ss",
             ), \
             mock.patch.object(srv.subprocess, "run", side_effect=OSError()):
            self.assertEqual(srv._find_pid_on_port(8082), 0)

        with mock.patch.object(srv.os, "name", "posix"), \
             mock.patch.object(
                 srv, "command_exists",
                 side_effect=lambda t: t == "fuser",
             ), \
             mock.patch.object(
                 srv.subprocess, "run", return_value=_cp(0, out="  321\n")
             ):
            self.assertEqual(srv._find_pid_on_port(8082), 321)

        with mock.patch.object(srv.os, "name", "posix"), \
             mock.patch.object(
                 srv, "command_exists",
                 side_effect=lambda t: t == "fuser",
             ), \
             mock.patch.object(srv.subprocess, "run", side_effect=OSError()):
            self.assertEqual(srv._find_pid_on_port(8082), 0)

        # ss with bad pid token
        ss_bad = 'LISTEN *:8082 users:(("java",pid=bad,fd=42))\n'
        with mock.patch.object(srv.os, "name", "posix"), \
             mock.patch.object(
                 srv, "command_exists", side_effect=lambda t: t == "ss"
             ), \
             mock.patch.object(
                 srv.subprocess, "run", return_value=_cp(0, out=ss_bad)
             ):
            self.assertEqual(srv._find_pid_on_port(8082), 0)

    def test_describe_port_owner(self):
        with mock.patch.object(srv.os, "name", "nt"), \
             mock.patch.object(
                 srv.subprocess, "run",
                 return_value=_cp(0, out="TCP :8082 LISTENING 1\n"),
             ):
            self.assertIn("8082", srv._describe_port_owner(8082))
        with mock.patch.object(srv.os, "name", "nt"), \
             mock.patch.object(srv.subprocess, "run", side_effect=OSError()):
            self.assertEqual(srv._describe_port_owner(8082), "")

        with mock.patch.object(srv.os, "name", "posix"), \
             mock.patch.object(
                 srv.subprocess, "run",
                 side_effect=[
                     _cp(0, out="LISTEN :8082 users\n"),
                 ],
             ):
            self.assertIn("8082", srv._describe_port_owner(8082))

        # ss fails, lsof works
        with mock.patch.object(srv.os, "name", "posix"), \
             mock.patch.object(
                 srv.subprocess, "run",
                 side_effect=[
                     OSError(),
                     _cp(0, out="COMMAND\njava 1\n"),
                 ],
             ):
            self.assertIn("java", srv._describe_port_owner(8082))

        # ss+lsof fail, netstat works
        with mock.patch.object(srv.os, "name", "posix"), \
             mock.patch.object(
                 srv.subprocess, "run",
                 side_effect=[
                     _cp(1, out=""),
                     OSError(),
                     _cp(0, out="tcp LISTEN :8082 java\n"),
                 ],
             ):
            self.assertIn("8082", srv._describe_port_owner(8082))

        with mock.patch.object(srv.os, "name", "posix"), \
             mock.patch.object(srv.subprocess, "run", side_effect=OSError()):
            self.assertEqual(srv._describe_port_owner(8082), "")


class LogsTokenHealthTests(unittest.TestCase):
    def test_monitor_bkps_logs(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with self.assertRaises(FileNotFoundError):
                srv.monitor_bkps_logs(cfg)

            logs = Path(td, "logs")
            logs.mkdir()
            log = logs / "bkps.log"
            log.write_text("hello\nTemporary user access token: TOK123 more\n")

            with mock.patch.object(srv.os, "name", "nt"), \
                 mock.patch.object(srv.time, "sleep"):
                srv.monitor_bkps_logs(cfg)
            self.assertTrue(Path(td, ".initial_token").is_file())

            Path(td, ".initial_token").unlink(missing_ok=True)
            log.write_text("no token yet\n")
            with mock.patch.object(srv.os, "name", "posix"), \
                 mock.patch.object(
                     srv.subprocess, "Popen", return_value=mock.Mock()
                 ) as popen, \
                 mock.patch.object(
                     srv.select, "select", return_value=([sys.stdin], [], [])
                 ):
                srv.monitor_bkps_logs(cfg)
                popen.return_value.terminate.assert_called()

            log.write_text("no token yet\n")
            with mock.patch.object(srv.os, "name", "posix"), \
                 mock.patch.object(
                     srv.subprocess, "Popen", return_value=mock.Mock()
                 ) as popen, \
                 mock.patch.object(srv.select, "select", side_effect=OSError()), \
                 mock.patch.object(srv.time, "sleep"):
                srv.monitor_bkps_logs(cfg)
                popen.return_value.terminate.assert_called()

            log.write_text("no token\n")

    def test_monitor_windows_read_exception(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            logs = Path(td, "logs")
            logs.mkdir()
            log = logs / "bkps.log"
            log.write_text("no token\n")
            real_open = open
            calls = {"n": 0}

            def open_side(path, *a, **k):
                calls["n"] += 1
                if calls["n"] == 1 and "bkps.log" in str(path):
                    raise OSError("boom")
                return real_open(path, *a, **k)

            with mock.patch.object(srv.os, "name", "nt"), \
                 mock.patch.object(srv.time, "sleep"), \
                 mock.patch("builtins.open", side_effect=open_side):
                srv.monitor_bkps_logs(cfg)

    def test_get_bkps_token(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            Path(td, ".initial_token").write_text("ABC")
            srv.get_bkps_token(cfg)

            Path(td, ".initial_token").unlink()
            Path(td, "logs").mkdir()
            Path(td, "logs", "bkps.log").write_text("x")
            with mock.patch(
                "bkps_autosetup.extract_token_from_logs", return_value="FROMLOG"
            ):
                srv.get_bkps_token(cfg)
            self.assertEqual(Path(td, ".initial_token").read_text(), "FROMLOG")

            Path(td, ".initial_token").write_text("")
            with mock.patch(
                "bkps_autosetup.extract_token_from_logs", return_value=""
            ):
                srv.get_bkps_token(cfg)

            Path(td, "logs", "bkps.log").unlink()
            Path(td, ".initial_token").unlink(missing_ok=True)
            srv.get_bkps_token(cfg)

    def test_health_and_diagnose(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with mock.patch.object(srv, "_runner") as runner:
                srv.check_bkps_health(cfg)
                runner.assert_called_once()

            # no jars / no libs
            srv.diagnose_bkps_jar(cfg)

            jar = Path(td, "bkps.jar")
            jar.write_bytes(b"x" * 2000)
            libs = Path(td, "libs-ext")
            libs.mkdir()
            for i in range(25):
                (libs / f"lib{i}.jar").write_bytes(b"x")
            (libs / "spring-boot-loader.jar").write_bytes(b"x")
            with mock.patch.object(
                srv.subprocess, "run",
                return_value=_cp(
                    0,
                    out="org/springframework/boot/loader\ncom/intel/bkp/bkps\n",
                ),
            ):
                srv.diagnose_bkps_jar(cfg)

            with mock.patch.object(
                srv.subprocess, "run",
                return_value=_cp(0, out="other\n"),
            ):
                # remove spring-boot-loader match via glob — already present; still ok
                Path(td, "libs-ext", "spring-boot-loader.jar").unlink()
                srv.diagnose_bkps_jar(cfg)


def real_open_for_token(log_path):
    return open(log_path)


if __name__ == "__main__":
    unittest.main()

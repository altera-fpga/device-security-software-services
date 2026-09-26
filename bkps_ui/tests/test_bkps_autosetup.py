#!/usr/bin/env python3
"""Unit tests for bkps_autosetup orchestration helpers."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

TOOL_ROOT = Path(__file__).resolve().parents[1]
if str(TOOL_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOL_ROOT))

import bkps_autosetup as autosetup  # noqa: E402


def setUpModule():
    # auto_setup_bkps catches print failures and reports only False, so ensure
    # Unicode status glyphs cannot fail on a narrow Windows console codec.
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(errors="replace")


TOKEN_64 = "a" * 64


def _cfg(root: Path) -> SimpleNamespace:
    return SimpleNamespace(
        bkps_dir=str(root),
        quartus_keys_dir=str(root / "qkeys"),
        bkps_server_port="8082",
        db_name="bkps_database",
    )


class CheckHelpersTests(unittest.TestCase):
    def test_check_server_running_true_false(self):
        cfg = SimpleNamespace(bkps_server_port="8082")
        with patch("bkps_autosetup.socket.create_connection") as conn:
            conn.return_value.__enter__ = MagicMock()
            conn.return_value.__exit__ = MagicMock(return_value=False)
            self.assertTrue(autosetup._check_server_running(cfg))
        with patch(
            "bkps_autosetup.socket.create_connection",
            side_effect=OSError("down"),
        ):
            self.assertFalse(autosetup._check_server_running(cfg))

    def test_super_admin_exists_branches(self):
        cfg = SimpleNamespace(db_name="db")
        with patch(
            "bkps_autosetup._admin_psql", return_value=(["psql"], {})
        ), patch(
            "bkps_autosetup._run",
            return_value=subprocess.CompletedProcess([], 0, "1\n", ""),
        ):
            self.assertTrue(autosetup._super_admin_exists(cfg))

        with patch(
            "bkps_autosetup._admin_psql", return_value=(["psql"], {})
        ), patch(
            "bkps_autosetup._run",
            return_value=subprocess.CompletedProcess([], 1, "", "err"),
        ):
            self.assertFalse(autosetup._super_admin_exists(cfg))

        with patch(
            "bkps_autosetup._admin_psql", side_effect=RuntimeError("no db")
        ):
            self.assertFalse(autosetup._super_admin_exists(cfg))

    def test_check_setup_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            qkeys = root / "qkeys"
            keys = root / "keys"
            qkeys.mkdir()
            keys.mkdir()
            cfg = _cfg(root)
            self.assertFalse(autosetup.check_setup_complete(cfg))
            (keys / "super_admin_bkps_signed.crt").write_text("c")
            (qkeys / "bkps_import_pubkey.pem").write_text("p")
            self.assertTrue(autosetup.check_setup_complete(cfg))


class ExtractTokenTests(unittest.TestCase):
    def test_missing_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                autosetup.extract_token_from_logs(_cfg(Path(tmp))), ""
            )

    def test_finds_token_with_ansi(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_dir = root / "logs"
            log_dir.mkdir()
            (log_dir / "bkps.log").write_text(
                f"\x1b[32mTemporary user access token: {TOKEN_64}\x1b[0m\n"
            )
            self.assertEqual(
                autosetup.extract_token_from_logs(_cfg(root)), TOKEN_64
            )

    def test_no_match_and_read_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_dir = root / "logs"
            log_dir.mkdir()
            (log_dir / "bkps.log").write_text("no token here\n")
            self.assertEqual(autosetup.extract_token_from_logs(_cfg(root)), "")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_dir = root / "logs"
            log_dir.mkdir()
            log = log_dir / "bkps.log"
            log.write_text("x")
            with patch("builtins.open", side_effect=OSError("denied")):
                self.assertEqual(
                    autosetup.extract_token_from_logs(_cfg(root)), ""
                )


class WaitForTokenTests(unittest.TestCase):
    def test_finds_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_dir = root / "logs"
            log_dir.mkdir()
            (log_dir / "bkps.log").write_text(
                f"Temporary user access token: {TOKEN_64}\n"
            )
            with patch("bkps_autosetup.time.sleep"), patch(
                "bkps_autosetup.time.time", side_effect=[0, 1]
            ):
                token = autosetup._wait_for_token(_cfg(root), timeout=10)
            self.assertEqual(token, TOKEN_64)

    def test_fail_pattern(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_dir = root / "logs"
            log_dir.mkdir()
            (log_dir / "bkps.log").write_text(
                "ERROR APPLICATION FAILED TO START\n"
            )
            with patch("bkps_autosetup.time.sleep"), patch(
                "bkps_autosetup.time.time", side_effect=[0, 1]
            ):
                self.assertEqual(
                    autosetup._wait_for_token(_cfg(root), timeout=10), ""
                )

    def test_cancel(self):
        cancel = threading.Event()
        cancel.set()
        with tempfile.TemporaryDirectory() as tmp:
            with patch("bkps_autosetup.time.sleep"), patch(
                "bkps_autosetup.time.time", return_value=0
            ):
                self.assertEqual(
                    autosetup._wait_for_token(
                        _cfg(Path(tmp)), timeout=10, _cancel_event=cancel
                    ),
                    "",
                )

    def test_process_dead_after_grace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_dir = root / "logs"
            log_dir.mkdir()
            (log_dir / "bkps.log").write_text("still starting\n")
            times = [0, 25]
            with patch("bkps_autosetup.time.sleep"), patch(
                "bkps_autosetup.time.time", side_effect=lambda: times[min(len(times) - 1, times.index(times[0]) if False else 0)] or times.pop(0) if times else 100
            ):
                # Simpler: patch time.time to return values advancing past grace
                pass

            clock = {"t": 0}

            def fake_time():
                clock["t"] += 21
                return clock["t"]

            with patch("bkps_autosetup.time.sleep"), patch(
                "bkps_autosetup.time.time", side_effect=fake_time
            ), patch(
                "bkps_autosetup._find_pid_on_port", return_value=0
            ):
                self.assertEqual(
                    autosetup._wait_for_token(_cfg(root), timeout=100), ""
                )

    def test_timeout_and_log_rotate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_dir = root / "logs"
            log_dir.mkdir()
            log = log_dir / "bkps.log"
            log.write_text("old content that will rotate\n")

            clock = {"t": 0}

            def fake_time():
                val = clock["t"]
                clock["t"] += 5
                return val

            sizes = [100, 10, 10]

            def fake_getsize(_path):
                return sizes.pop(0) if sizes else 10

            with patch("bkps_autosetup.time.sleep"), patch(
                "bkps_autosetup.time.time", side_effect=fake_time
            ), patch(
                "bkps_autosetup.os.path.getsize", side_effect=fake_getsize
            ), patch(
                "bkps_autosetup._find_pid_on_port", return_value=1
            ):
                self.assertEqual(
                    autosetup._wait_for_token(
                        _cfg(root), timeout=12, log_start_pos=50
                    ),
                    "",
                )

    def test_missing_log_then_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock = {"t": 0}

            def fake_time():
                val = clock["t"]
                clock["t"] += 5
                return val

            with patch("bkps_autosetup.time.sleep"), patch(
                "bkps_autosetup.time.time", side_effect=fake_time
            ):
                self.assertEqual(
                    autosetup._wait_for_token(_cfg(Path(tmp)), timeout=8), ""
                )

    def test_read_exception_continues_to_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_dir = root / "logs"
            log_dir.mkdir()
            (log_dir / "bkps.log").write_text("x")
            clock = {"t": 0}

            def fake_time():
                val = clock["t"]
                clock["t"] += 5
                return val

            with patch("bkps_autosetup.time.sleep"), patch(
                "bkps_autosetup.time.time", side_effect=fake_time
            ), patch(
                "bkps_autosetup.os.path.getsize",
                side_effect=OSError("race"),
            ):
                self.assertEqual(
                    autosetup._wait_for_token(_cfg(root), timeout=8), ""
                )


class WaitHealthAuthTests(unittest.TestCase):
    def test_health_pass(self):
        cfg = SimpleNamespace()
        ok = subprocess.CompletedProcess([], 0, "ok", "")
        with patch("bkps_autosetup._runner", return_value=ok), patch(
            "bkps_autosetup.time.sleep"
        ):
            self.assertTrue(autosetup._wait_for_runner_health(cfg, timeout=10))

    def test_health_cancel(self):
        cancel = threading.Event()
        cancel.set()
        with patch("bkps_autosetup.time.sleep"):
            self.assertFalse(
                autosetup._wait_for_runner_health(
                    SimpleNamespace(), timeout=10, _cancel_event=cancel
                )
            )

    def test_health_timeout_with_progress(self):
        bad = subprocess.CompletedProcess([], 1, "", "not ready")
        clock = {"t": 0}

        def fake_time():
            val = clock["t"]
            clock["t"] += 11
            return val

        with patch("bkps_autosetup._runner", return_value=bad), patch(
            "bkps_autosetup.time.sleep"
        ), patch("bkps_autosetup.time.time", side_effect=fake_time):
            self.assertFalse(
                autosetup._wait_for_runner_health(
                    SimpleNamespace(), timeout=20
                )
            )

    def test_health_exception_then_timeout(self):
        clock = {"t": 0}

        def fake_time():
            val = clock["t"]
            clock["t"] += 15
            return val

        with patch(
            "bkps_autosetup._runner", side_effect=RuntimeError("down")
        ), patch("bkps_autosetup.time.sleep"), patch(
            "bkps_autosetup.time.time", side_effect=fake_time
        ):
            self.assertFalse(
                autosetup._wait_for_runner_health(
                    SimpleNamespace(), timeout=10
                )
            )

    def test_auth_ready_two_successes(self):
        health_ok = subprocess.CompletedProcess([], 0, "", "")
        user_ok = subprocess.CompletedProcess([], 0, "users", "")
        with patch(
            "bkps_autosetup._wait_for_runner_health", return_value=True
        ), patch(
            "bkps_autosetup._runner", return_value=user_ok
        ), patch("bkps_autosetup.time.sleep"):
            self.assertTrue(
                autosetup._wait_for_authenticated_ready(
                    SimpleNamespace(), timeout=30
                )
            )

        # reset path: fail then succeed twice
        calls = {"n": 0}

        def flaky(*_a, **_k):
            calls["n"] += 1
            if calls["n"] == 1:
                return subprocess.CompletedProcess([], 1, "no", "")
            return user_ok

        with patch(
            "bkps_autosetup._wait_for_runner_health", return_value=True
        ), patch("bkps_autosetup._runner", side_effect=flaky), patch(
            "bkps_autosetup.time.sleep"
        ):
            self.assertTrue(
                autosetup._wait_for_authenticated_ready(
                    SimpleNamespace(), timeout=30
                )
            )

    def test_auth_ready_health_fail(self):
        with patch(
            "bkps_autosetup._wait_for_runner_health", return_value=False
        ):
            self.assertFalse(
                autosetup._wait_for_authenticated_ready(SimpleNamespace())
            )

    def test_auth_ready_cancel_and_timeout(self):
        cancel = threading.Event()
        cancel.set()
        with patch(
            "bkps_autosetup._wait_for_runner_health", return_value=True
        ), patch("bkps_autosetup.time.sleep"):
            self.assertFalse(
                autosetup._wait_for_authenticated_ready(
                    SimpleNamespace(), timeout=10, _cancel_event=cancel
                )
            )

        clock = {"t": 0}

        def fake_time():
            val = clock["t"]
            clock["t"] += 12
            return val

        with patch(
            "bkps_autosetup._wait_for_runner_health", return_value=True
        ), patch(
            "bkps_autosetup._runner",
            side_effect=RuntimeError("x"),
        ), patch("bkps_autosetup.time.sleep"), patch(
            "bkps_autosetup.time.time", side_effect=fake_time
        ):
            self.assertFalse(
                autosetup._wait_for_authenticated_ready(
                    SimpleNamespace(), timeout=10
                )
            )


class AutoSetupTests(unittest.TestCase):
    def test_missing_admin_cert(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(autosetup.auto_setup_bkps(_cfg(Path(tmp))))

    def test_server_already_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keys = root / "keys"
            keys.mkdir()
            (keys / "super_admin_cert.crt").write_text("cert")
            with patch(
                "bkps_autosetup._check_server_running", return_value=True
            ):
                self.assertTrue(autosetup.auto_setup_bkps(_cfg(root)))

    def test_happy_path_full(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keys = root / "keys"
            keys.mkdir()
            (keys / "super_admin_cert.crt").write_text("cert")
            with patch(
                "bkps_autosetup._check_server_running", return_value=False
            ), patch(
                "bkps_autosetup.start_bkps_server", return_value=True
            ), patch(
                "bkps_autosetup._super_admin_exists", return_value=False
            ), patch(
                "bkps_autosetup._wait_for_token", return_value=TOKEN_64
            ), patch(
                "bkps_autosetup.create_super_admin"
            ) as create_admin, patch(
                "bkps_autosetup._wait_for_authenticated_ready",
                return_value=True,
            ), patch(
                "bkps_autosetup.create_authentication_keys"
            ), patch(
                "bkps_autosetup.configure_bkps_keys"
            ):
                self.assertTrue(autosetup.auto_setup_bkps(_cfg(root)))
            create_admin.assert_called_once()
            self.assertTrue((root / ".bkps_setup_complete").is_file())
            self.assertEqual(
                (root / ".initial_token").read_text(), TOKEN_64
            )

    def test_admin_exists_skips_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keys = root / "keys"
            keys.mkdir()
            (keys / "super_admin_cert.crt").write_text("cert")
            with patch(
                "bkps_autosetup._check_server_running", return_value=False
            ), patch(
                "bkps_autosetup.start_bkps_server", return_value=True
            ), patch(
                "bkps_autosetup._super_admin_exists", return_value=True
            ), patch(
                "bkps_autosetup._wait_for_authenticated_ready",
                return_value=True,
            ), patch(
                "bkps_autosetup.create_authentication_keys"
            ), patch(
                "bkps_autosetup.configure_bkps_keys"
            ), patch(
                "bkps_autosetup._wait_for_token"
            ) as wait_tok:
                self.assertTrue(autosetup.auto_setup_bkps(_cfg(root)))
            wait_tok.assert_not_called()

    def test_start_server_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keys = root / "keys"
            keys.mkdir()
            (keys / "super_admin_cert.crt").write_text("cert")
            with patch(
                "bkps_autosetup._check_server_running", return_value=False
            ), patch(
                "bkps_autosetup.start_bkps_server", return_value=False
            ):
                self.assertFalse(autosetup.auto_setup_bkps(_cfg(root)))

    def test_token_fail_and_cancel(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keys = root / "keys"
            keys.mkdir()
            (keys / "super_admin_cert.crt").write_text("cert")
            with patch(
                "bkps_autosetup._check_server_running", return_value=False
            ), patch(
                "bkps_autosetup.start_bkps_server", return_value=True
            ), patch(
                "bkps_autosetup._super_admin_exists", return_value=False
            ), patch(
                "bkps_autosetup._wait_for_token", return_value=""
            ):
                self.assertFalse(autosetup.auto_setup_bkps(_cfg(root)))

            cancel = threading.Event()
            cancel.set()
            with patch(
                "bkps_autosetup._check_server_running", return_value=False
            ), patch(
                "bkps_autosetup.start_bkps_server", return_value=True
            ):
                # cancel before start is checked after start_bkps would run;
                # set cancel so start server checkpoint fires
                self.assertFalse(
                    autosetup.auto_setup_bkps(
                        _cfg(root), _cancel_event=cancel
                    )
                )

    def test_auth_ready_fail_and_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keys = root / "keys"
            keys.mkdir()
            (keys / "super_admin_cert.crt").write_text("cert")
            with patch(
                "bkps_autosetup._check_server_running", return_value=False
            ), patch(
                "bkps_autosetup.start_bkps_server", return_value=True
            ), patch(
                "bkps_autosetup._super_admin_exists", return_value=True
            ), patch(
                "bkps_autosetup._wait_for_authenticated_ready",
                return_value=False,
            ):
                self.assertFalse(autosetup.auto_setup_bkps(_cfg(root)))

            with patch(
                "bkps_autosetup._check_server_running",
                side_effect=RuntimeError("boom"),
            ):
                self.assertFalse(autosetup.auto_setup_bkps(_cfg(root)))

    def test_cancel_at_later_checkpoints(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keys = root / "keys"
            keys.mkdir()
            (keys / "super_admin_cert.crt").write_text("cert")

            class FlipEvent:
                """False for the first N is_set probes, True afterward."""

                def __init__(self, false_count):
                    self.n = 0
                    self.false_count = false_count

                def is_set(self):
                    self.n += 1
                    return self.n > self.false_count

            # Probe order when admin missing: start server, wait token, create admin
            for false_count in (1, 2):
                cancel = FlipEvent(false_count=false_count)
                with patch(
                    "bkps_autosetup._check_server_running", return_value=False
                ), patch(
                    "bkps_autosetup.start_bkps_server", return_value=True
                ), patch(
                    "bkps_autosetup._super_admin_exists", return_value=False
                ), patch(
                    "bkps_autosetup._wait_for_token", return_value=TOKEN_64
                ), patch(
                    "bkps_autosetup.create_super_admin"
                ):
                    self.assertFalse(
                        autosetup.auto_setup_bkps(
                            _cfg(root), _cancel_event=cancel
                        )
                    )

            # admin exists: start server, wait auth, create keys, configure
            for false_count in (1, 2, 3):
                cancel = FlipEvent(false_count=false_count)
                with patch(
                    "bkps_autosetup._check_server_running", return_value=False
                ), patch(
                    "bkps_autosetup.start_bkps_server", return_value=True
                ), patch(
                    "bkps_autosetup._super_admin_exists", return_value=True
                ), patch(
                    "bkps_autosetup._wait_for_authenticated_ready",
                    return_value=True,
                ), patch(
                    "bkps_autosetup.create_authentication_keys"
                ), patch(
                    "bkps_autosetup.configure_bkps_keys"
                ):
                    self.assertFalse(
                        autosetup.auto_setup_bkps(
                            _cfg(root), _cancel_event=cancel
                        )
                    )


if __name__ == "__main__":
    unittest.main()

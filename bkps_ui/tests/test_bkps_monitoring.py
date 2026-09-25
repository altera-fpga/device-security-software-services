#!/usr/bin/env python3
"""Regression / unit tests for bkps_monitoring.py."""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

TOOL_DIR = Path(__file__).resolve().parents[1]
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

import bkps_monitoring as m  # noqa: E402
from bkps_monitoring import show_logs  # noqa: E402


def RR(code=0, out="", err=""):
    return SimpleNamespace(returncode=code, stdout=out, stderr=err)


def _cfg(root: str) -> SimpleNamespace:
    return SimpleNamespace(
        bkps_dir=root,
        home=root,
        quartus_keys_dir=os.path.join(root, "qkeys"),
        keystore_password="ks",
    )


class BkpsMonitoringShowLogsTests(unittest.TestCase):
    def test_streaming_hint_uses_calling_tabs_control_label(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            log_dir = root / "logs"
            log_dir.mkdir()
            (log_dir / "bkps.log").touch()
            cancel = threading.Event()
            cancel.set()
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                show_logs(
                    SimpleNamespace(bkps_dir=str(root)),
                    _cancel_event=cancel,
                    stop_control_label="Detach Live Output",
                )

        self.assertIn("click 'Detach Live Output' to stop", output.getvalue())

    def test_missing_log_raises(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(FileNotFoundError):
                show_logs(SimpleNamespace(bkps_dir=td))

    def test_wait_for_file_cancel(self):
        with tempfile.TemporaryDirectory() as td:
            cancel = threading.Event()
            cancel.set()
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                ok = show_logs(
                    SimpleNamespace(bkps_dir=td),
                    _cancel_event=cancel,
                    wait_for_file=1.0,
                )
            self.assertFalse(ok)

    def test_wait_for_file_appears(self):
        with tempfile.TemporaryDirectory() as td:
            log_path = Path(td) / "logs" / "bkps.log"
            log_path.parent.mkdir()

            def _create():
                time.sleep(0.3)
                log_path.write_text("ready\n")

            threading.Thread(target=_create, daemon=True).start()
            cancel = threading.Event()

            def _stop():
                time.sleep(0.6)
                cancel.set()

            threading.Thread(target=_stop, daemon=True).start()
            with contextlib.redirect_stdout(io.StringIO()):
                show_logs(
                    SimpleNamespace(bkps_dir=td),
                    _cancel_event=cancel,
                    wait_for_file=2.0,
                )

    def test_stop_and_fail_patterns(self):
        with tempfile.TemporaryDirectory() as td:
            log_dir = Path(td) / "logs"
            log_dir.mkdir()
            log_file = log_dir / "bkps.log"
            log_file.write_text("")

            def _writer():
                time.sleep(0.2)
                with open(log_file, "a") as f:
                    f.write("BOOT_OK something\n")

            threading.Thread(target=_writer, daemon=True).start()
            with contextlib.redirect_stdout(io.StringIO()):
                ready = show_logs(
                    SimpleNamespace(bkps_dir=td),
                    stop_patterns=["BOOT_OK"],
                )
            self.assertTrue(ready)

        with tempfile.TemporaryDirectory() as td:
            log_dir = Path(td) / "logs"
            log_dir.mkdir()
            log_file = log_dir / "bkps.log"
            log_file.write_text("")

            def _writer_fail():
                time.sleep(0.2)
                with open(log_file, "a") as f:
                    f.write("FATAL boom\n")

            threading.Thread(target=_writer_fail, daemon=True).start()
            with contextlib.redirect_stdout(io.StringIO()):
                ready = show_logs(
                    SimpleNamespace(bkps_dir=td),
                    fail_patterns=["FATAL"],
                    stop_patterns=["NEVER"],
                )
            self.assertFalse(ready)


class ExportLogsTests(unittest.TestCase):
    def test_missing_log(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(FileNotFoundError):
                m.export_logs(_cfg(td))

    def test_export_recent_posix(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            log_dir = Path(td) / "logs"
            log_dir.mkdir()
            log_file = log_dir / "bkps.log"
            log_file.write_text("line1\nline2\n")
            with mock.patch.object(m.os, "name", "posix"), mock.patch.object(
                m.subprocess, "run", return_value=RR(0, out="line1\nline2\n")
            ):
                m.export_logs(cfg, days=1)
            exports = list(Path(td).glob("bkps_logs_export_*.log"))
            self.assertEqual(len(exports), 1)
            self.assertTrue(exports[0].stat().st_size > 0)

    def test_export_recent_windows(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            log_dir = Path(td) / "logs"
            log_dir.mkdir()
            (log_dir / "bkps.log").write_text("a\nb\nc\n")
            with mock.patch.object(m.os, "name", "nt"):
                m.export_logs(cfg, days=1)

    def test_export_old_file_and_empty_error(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            log_dir = Path(td) / "logs"
            log_dir.mkdir()
            log_file = log_dir / "bkps.log"
            log_file.write_text("old\n")
            old = time.time() - (10 * 86400)
            os.utime(log_file, (old, old))
            m.export_logs(cfg, days=1)

        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            log_dir = Path(td) / "logs"
            log_dir.mkdir()
            (log_dir / "bkps.log").write_text("x")
            with mock.patch.object(m.os, "name", "posix"), mock.patch.object(
                m.subprocess, "run", return_value=RR(0, out="")
            ), mock.patch.object(m.os.path, "getmtime", return_value=time.time()):
                with self.assertRaises(RuntimeError):
                    m.export_logs(cfg, days=1)


class CheckCertExpiryTests(unittest.TestCase):
    def test_check_cert_expiry_paths(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            Path(cfg.quartus_keys_dir).mkdir(parents=True)
            # missing certs → FILE NOT FOUND via _check_single_cert
            with contextlib.redirect_stdout(io.StringIO()):
                m.check_cert_expiry(cfg, warn_days=30)


class ValidateKeystoreTests(unittest.TestCase):
    def test_missing_keystore(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(FileNotFoundError):
                m.validate_keystore(_cfg(td))

    def test_valid_and_invalid(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            ks = Path(td) / "keys" / "bkps_keystore.p12"
            ks.parent.mkdir(parents=True)
            ks.write_text("ks")

            out = (
                "Alias name: a\n"
                "Entry type: PrivateKeyEntry\n"
                "Valid from: yesterday\n"
                "until: tomorrow\n"
                "Other junk\n"
            )
            with mock.patch.object(
                m, "run", side_effect=[RR(0, out=out), RR(0, out="ok")]
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    m.validate_keystore(cfg)

            with mock.patch.object(
                m, "run", side_effect=[RR(0, out=""), RR(1, err="bad")]
            ):
                with self.assertRaises(RuntimeError):
                    m.validate_keystore(cfg)


class HelperTests(unittest.TestCase):
    def test_human_size(self):
        self.assertTrue(m._human_size(500).endswith("B"))
        self.assertTrue(m._human_size(2048).endswith("KB"))
        self.assertTrue(m._human_size(2 * 1024 ** 2).endswith("MB"))
        self.assertTrue(m._human_size(2 * 1024 ** 3).endswith("GB"))
        self.assertTrue(m._human_size(2 * 1024 ** 4).endswith("TB"))

    def test_parse_openssl_date(self):
        ts = m._parse_openssl_date("Mar 25 12:00:00 2026 GMT")
        self.assertIsInstance(ts, float)
        ts2 = m._parse_openssl_date("Mar  5 12:00:00 2026 GMT")
        self.assertIsInstance(ts2, float)
        with self.assertRaises(ValueError):
            m._parse_openssl_date("not-a-date")

    def test_check_single_cert_branches(self):
        with tempfile.TemporaryDirectory() as td:
            missing = os.path.join(td, "no.crt")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                m._check_single_cert(missing, "X", 30)
            self.assertIn("FILE NOT FOUND", out.getvalue())

            bad = os.path.join(td, "bad.crt")
            Path(bad).write_text("x")
            with mock.patch.object(
                m.subprocess, "run", return_value=RR(1, err="bad")
            ), contextlib.redirect_stdout(out):
                m._check_single_cert(bad, "Y", 30)
            self.assertIn("INVALID", out.getvalue())

            good = os.path.join(td, "good.crt")
            Path(good).write_text("x")
            future = "Jan  1 00:00:00 2099 GMT"
            with mock.patch.object(
                m.subprocess, "run", return_value=RR(0, out=f"notAfter={future}")
            ), contextlib.redirect_stdout(io.StringIO()) as buf:
                m._check_single_cert(good, "Z", 30)

            soon = time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(time.time() + 5 * 86400))
            with mock.patch.object(
                m.subprocess, "run", return_value=RR(0, out=f"notAfter={soon}")
            ), contextlib.redirect_stdout(io.StringIO()):
                m._check_single_cert(good, "Soon", 30)

            past = "Jan  1 00:00:00 2000 GMT"
            with mock.patch.object(
                m.subprocess, "run", return_value=RR(0, out=f"notAfter={past}")
            ), contextlib.redirect_stdout(io.StringIO()):
                m._check_single_cert(good, "Old", 30)

            with mock.patch.object(
                m.subprocess, "run", return_value=RR(0, out="notAfter=bogus")
            ), contextlib.redirect_stdout(io.StringIO()) as buf2:
                m._check_single_cert(good, "Parse", 30)
            # parse failure path prints "?"
            with mock.patch.object(
                m.subprocess, "run", return_value=RR(0, out="notAfter=bogus-date")
            ), contextlib.redirect_stdout(io.StringIO()) as buf3:
                m._check_single_cert(good, "Parse2", 30)
            self.assertIn("could not parse", buf3.getvalue())


if __name__ == "__main__":
    unittest.main()

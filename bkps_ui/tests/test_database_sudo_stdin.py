#!/usr/bin/env python3
"""Regression tests for sudo credential handling in database administration.

``sudo -S`` reads a password from stdin only while its credential timestamp is
expired. Sharing one stdin stream between the password and SQL therefore sends
the password to psql as a statement as soon as sudo is already authenticated,
which produced a syntax error on the second administrative command.
"""

from __future__ import annotations

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

import bkps_database


def _cfg(root: str) -> SimpleNamespace:
    return SimpleNamespace(
        db_name="bkps_database",
        db_user="bkps_user",
        db_password="s3cret-db",
        pg_superuser_password="",
        db_host="localhost",
        sudo_password="1",
        bkps_dir=root,
    )


class SudoStdinTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(bkps_database.os, "name", "posix")
        patcher.start()
        self.addCleanup(patcher.stop)
        audit = mock.patch.object(bkps_database, "audit_log")
        audit.start()
        self.addCleanup(audit.stop)

    def test_privileged_prefixes_never_read_the_command_stdin(self):
        cfg = _cfg(".")
        self.assertEqual(["sudo", "-n"], bkps_database._sudo(cfg))
        self.assertEqual(
            ["sudo", "-n", "-u", "postgres"], bkps_database._sudo_pg(cfg)
        )

    def test_no_password_configured_keeps_plain_sudo(self):
        cfg = _cfg(".")
        cfg.sudo_password = ""
        self.assertEqual(["sudo"], bkps_database._sudo(cfg))
        self.assertEqual(["sudo", "-u", "postgres"], bkps_database._sudo_pg(cfg))

    def test_authentication_rejects_a_bad_password(self):
        cfg = _cfg(".")
        with mock.patch.object(
            bkps_database,
            "run",
            return_value=subprocess.CompletedProcess(
                [], 1, "", "Sorry, try again."
            ),
        ):
            with self.assertRaises(RuntimeError) as raised:
                bkps_database.authenticate_sudo(cfg)
        self.assertIn("sudo authentication failed", str(raised.exception))

    def test_authentication_reports_disabled_credential_caching(self):
        cfg = _cfg(".")
        results = [
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 1, "", "a password is required"),
        ]
        with mock.patch.object(
            bkps_database, "run", side_effect=results
        ):
            with self.assertRaises(RuntimeError) as raised:
                bkps_database.authenticate_sudo(cfg)
        self.assertIn("does not retain credentials", str(raised.exception))

    def test_reset_never_sends_the_sudo_password_to_psql(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = _cfg(root)
            calls: list[tuple[list, str | None]] = []

            def fake_run(cmd, *args, **kwargs):
                calls.append((list(cmd), kwargs.get("input_text")))
                stdout = cfg.db_name if "-lqt" in cmd else ""
                return subprocess.CompletedProcess(cmd, 0, stdout, "")

            with mock.patch.object(bkps_database, "run", side_effect=fake_run):
                bkps_database.reset_database(cfg)

            psql_inputs = [
                payload for cmd, payload in calls
                if "psql" in cmd and payload is not None
            ]
            self.assertTrue(psql_inputs)
            for payload in psql_inputs:
                self.assertNotIn(cfg.sudo_password + "\n", payload)
                self.assertTrue(
                    payload.lstrip().startswith(("DO ", "ALTER ", "CREATE ", "GRANT ")),
                    f"psql received a non-SQL first line: {payload!r}",
                )

            self.assertIn(
                (["sudo", "-S", "-v"], cfg.sudo_password + "\n"), calls
            )
            for cmd, _payload in calls:
                if "psql" in cmd:
                    self.assertNotIn("-S", cmd)


if __name__ == "__main__":
    unittest.main()

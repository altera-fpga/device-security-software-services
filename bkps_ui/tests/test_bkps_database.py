#!/usr/bin/env python3
"""Unit tests for bkps_database with mocked subprocess/psql/sudo."""

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

import bkps_database as db  # noqa: E402


def setUpModule():
    # Progress messages contain Unicode glyphs; a narrow console codec (cp1252)
    # would turn an incidental print into a UnicodeEncodeError.
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(errors="replace")


def _cfg(root: str, **kwargs) -> SimpleNamespace:
    base = dict(
        db_name="bkps_database",
        db_user="bkps_user",
        db_password="s3cret-db",
        pg_superuser_password="postgres",
        db_host="localhost",
        sudo_password="1",
        bkps_dir=root,
        quartus_keys_dir=os.path.join(root, "keys"),
    )
    base.update(kwargs)
    return SimpleNamespace(**base)


def _cp(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


class HelperTests(unittest.TestCase):
    def test_pg_env_and_literals(self):
        cfg = _cfg(".")
        self.assertEqual(db._pg_env(cfg)["PGPASSWORD"], "s3cret-db")
        self.assertEqual(db._sql_literal("a'b"), "'a''b'")
        self.assertEqual(db._db_identifier("bkps_user", "DB_USER"), "bkps_user")
        with self.assertRaises(ValueError):
            db._db_identifier("bad-name", "DB_NAME")

    def test_sudo_prefixes_windows(self):
        cfg = _cfg(".")
        with mock.patch.object(db.os, "name", "nt"):
            self.assertEqual(db._sudo(cfg), [])
            self.assertEqual(db._sudo_pg(cfg), [])

    def test_sudo_prefixes_posix_with_and_without_password(self):
        cfg = _cfg(".", sudo_password="pw")
        with mock.patch.object(db.os, "name", "posix"):
            self.assertEqual(db._sudo(cfg), ["sudo", "-n"])
            self.assertEqual(db._sudo_pg(cfg), ["sudo", "-n", "-u", "postgres"])
        cfg.sudo_password = ""
        with mock.patch.object(db.os, "name", "posix"):
            self.assertEqual(db._sudo(cfg), ["sudo"])
            self.assertEqual(db._sudo_pg(cfg), ["sudo", "-u", "postgres"])

    def test_admin_user_maint_psql_linux(self):
        cfg = _cfg(".")
        with mock.patch.object(db.os, "name", "posix"), \
             mock.patch.object(db, "authenticate_sudo") as auth:
            cmd, env = db._admin_psql(cfg, ["-c", "SELECT 1"])
            auth.assert_called_once()
            self.assertIn("psql", cmd)
            self.assertEqual(env, {})

            ucmd, uenv = db._user_psql(cfg, ["-d", "bkps_database"])
            self.assertEqual(ucmd[0], "psql")
            self.assertEqual(uenv["PGPASSWORD"], "s3cret-db")

            mcmd, _ = db._maint_psql(
                cfg, ["-d", "ignore", "--dbname=other", "-c", "x"]
            )
            self.assertIn("postgres", mcmd)
            self.assertNotIn("ignore", mcmd)

    def test_admin_psql_windows(self):
        cfg = _cfg(".")
        with mock.patch.object(db.os, "name", "nt"):
            cmd, env = db._admin_psql(cfg, ["-lqt"])
            self.assertEqual(cmd[:4], ["psql", "-h", "localhost", "-U"])
            self.assertEqual(env["PGPASSWORD"], "postgres")

        cfg.db_host = ""
        with mock.patch.object(db.os, "name", "nt"):
            cmd, _ = db._admin_psql(cfg, [])
            self.assertIn("localhost", cmd)

    def test_authenticate_sudo_paths(self):
        cfg = _cfg(".")
        with mock.patch.object(db.os, "name", "nt"):
            db.authenticate_sudo(cfg)
        cfg.sudo_password = ""
        with mock.patch.object(db.os, "name", "posix"):
            db.authenticate_sudo(cfg)

        cfg.sudo_password = "pw"
        with mock.patch.object(db.os, "name", "posix"), \
             mock.patch.object(db, "run", return_value=_cp(1, err="no")):
            with self.assertRaises(RuntimeError):
                db.authenticate_sudo(cfg)

        with mock.patch.object(db.os, "name", "posix"), \
             mock.patch.object(
                 db, "run",
                 side_effect=[_cp(0), _cp(1, err="need password")],
             ):
            with self.assertRaises(RuntimeError):
                db.authenticate_sudo(cfg)

        with mock.patch.object(db.os, "name", "posix"), \
             mock.patch.object(db, "run", side_effect=[_cp(0), _cp(0)]):
            db.authenticate_sudo(cfg)


class ServiceAndExistsTests(unittest.TestCase):
    def setUp(self):
        audit = mock.patch.object(db, "audit_log")
        audit.start()
        self.addCleanup(audit.stop)

    def test_postgresql_service_units(self):
        cfg = _cfg(".")
        with mock.patch.object(db.os, "name", "posix"), \
             mock.patch.object(db, "_sudo", return_value=["sudo", "-n"]), \
             mock.patch.object(
                 db, "run",
                 return_value=_cp(
                     0,
                     out="postgresql.service loaded\npostgresql@16-main.service loaded\npostgresql@.service loaded\n",
                 ),
             ):
            units = db._postgresql_service_units(cfg)
        self.assertIn("postgresql.service", units)
        self.assertIn("postgresql@16-main.service", units)
        self.assertNotIn("postgresql@.service", units)

        with mock.patch.object(db.os, "name", "posix"), \
             mock.patch.object(db, "_sudo", return_value=["sudo"]), \
             mock.patch.object(db, "run", return_value=_cp(0, out="\n  \n")):
            units2 = db._postgresql_service_units(cfg)
        self.assertEqual(units2, ["postgresql.service"])

    def test_start_postgresql_service(self):
        cfg = _cfg(".")
        with mock.patch.object(db, "authenticate_sudo"), \
             mock.patch.object(
                 db, "_postgresql_service_units",
                 return_value=["postgresql.service"],
             ), \
             mock.patch.object(db, "_sudo", return_value=["sudo"]), \
             mock.patch.object(db, "run", return_value=_cp(0)):
            db._start_postgresql_service(cfg)

        with mock.patch.object(db, "authenticate_sudo"), \
             mock.patch.object(
                 db, "_postgresql_service_units",
                 return_value=["postgresql.service"],
             ), \
             mock.patch.object(db, "_sudo", return_value=["sudo"]), \
             mock.patch.object(db, "run", return_value=_cp(1)):
            with self.assertRaises(RuntimeError):
                db._start_postgresql_service(cfg)

    def test_db_exists(self):
        cfg = _cfg(".")
        with mock.patch.object(
            db, "_maint_psql", return_value=(["psql"], {})
        ), mock.patch.object(
            db, "run", return_value=_cp(0, out=" bkps_database |")
        ):
            self.assertTrue(db._db_exists(cfg))

        with mock.patch.object(
            db, "_maint_psql", return_value=(["psql"], {})
        ), mock.patch.object(
            db, "run", return_value=_cp(1, err="fail")
        ), mock.patch.object(db.os, "name", "posix"):
            with self.assertRaises(RuntimeError):
                db._db_exists(cfg)

        with mock.patch.object(
            db, "_maint_psql", return_value=(["psql"], {})
        ), mock.patch.object(
            db, "run", return_value=_cp(1, err="fail")
        ), mock.patch.object(db.os, "name", "nt"):
            with self.assertRaises(RuntimeError):
                db._db_exists(cfg)


class SetupResetTests(unittest.TestCase):
    def setUp(self):
        audit = mock.patch.object(db, "audit_log")
        audit.start()
        self.addCleanup(audit.stop)

    def test_setup_database_already_exists_with_tables(self):
        cfg = _cfg(".")
        with mock.patch.object(db, "_db_exists", return_value=True), \
             mock.patch.object(
                 db, "run",
                 return_value=_cp(0, out=" count\n-------\n     5\n"),
             ):
            db.setup_database(cfg)

    def test_setup_database_exists_empty(self):
        cfg = _cfg(".")
        with mock.patch.object(db, "_db_exists", return_value=True), \
             mock.patch.object(
                 db, "run",
                 return_value=_cp(0, out=" count\n-------\n     0\n"),
             ):
            db.setup_database(cfg)

    def test_setup_database_create_with_sql(self):
        with tempfile.TemporaryDirectory() as td:
            sql = Path(td) / "bkps_schema.sql"
            sql.write_text("-- schema")
            cfg = _cfg(td)
            with mock.patch.object(db, "_db_exists", return_value=False), \
                 mock.patch.object(db.os, "name", "posix"), \
                 mock.patch.object(db, "_start_postgresql_service"), \
                 mock.patch.object(
                     db, "_maint_psql", return_value=(["psql"], {})
                 ), \
                 mock.patch.object(
                     db, "_user_psql", return_value=(["psql"], {"PGPASSWORD": "x"})
                 ), \
                 mock.patch.object(db, "run", return_value=_cp(0)):
                db.setup_database(cfg)

    def test_setup_database_liquibase_and_missing(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            Path(td, "liquibase").mkdir()
            with mock.patch.object(db, "_db_exists", return_value=False), \
                 mock.patch.object(db.os, "name", "posix"), \
                 mock.patch.object(db, "_start_postgresql_service"), \
                 mock.patch.object(
                     db, "_maint_psql", return_value=(["psql"], {})
                 ), \
                 mock.patch.object(db, "run", return_value=_cp(0)):
                db.setup_database(cfg)

            empty = tempfile.mkdtemp()
            cfg2 = _cfg(empty)
            with mock.patch.object(db, "_db_exists", return_value=False), \
                 mock.patch.object(db.os, "name", "nt"), \
                 mock.patch.object(
                     db.subprocess, "run", return_value=_cp(0)
                 ), \
                 mock.patch.object(
                     db, "_maint_psql", return_value=(["psql"], {})
                 ), \
                 mock.patch.object(db, "run", return_value=_cp(0)):
                with self.assertRaises(RuntimeError):
                    db.setup_database(cfg2)

    def test_reset_database_success_and_marker_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            sql = Path(td) / "bkps.sql"
            sql.write_text("CREATE TABLE t(i int);")
            keys = Path(td) / "keys"
            keys.mkdir()
            (keys / "bkps_import_pubkey.pem").write_text("k")
            (Path(td) / ".bkps_setup_complete").write_text("1")
            cfg = _cfg(td, quartus_keys_dir=str(keys))

            with mock.patch.object(db, "_db_exists", return_value=True), \
                 mock.patch.object(
                     db, "_maint_psql", return_value=(["psql"], {})
                 ), \
                 mock.patch.object(db, "run", return_value=_cp(0)), \
                 mock.patch.object(
                     db.subprocess, "run",
                     return_value=_cp(0, out="ok" * 300),
                 ):
                db.reset_database(cfg)
            self.assertFalse(os.path.isfile(os.path.join(td, ".bkps_setup_complete")))
            self.assertFalse((keys / "bkps_import_pubkey.pem").is_file())

    def test_reset_database_no_sql_and_import_fail(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with mock.patch.object(db, "_db_exists", return_value=False), \
                 mock.patch.object(
                     db, "_maint_psql", return_value=(["psql"], {})
                 ), \
                 mock.patch.object(db, "run", return_value=_cp(0)):
                db.reset_database(cfg)

            Path(td, "liquibase").mkdir()
            with mock.patch.object(db, "_db_exists", return_value=False), \
                 mock.patch.object(
                     db, "_maint_psql", return_value=(["psql"], {})
                 ), \
                 mock.patch.object(db, "run", return_value=_cp(0)):
                db.reset_database(cfg)

            sql = Path(td) / "bkps.sql"
            sql.write_text("bad")
            with mock.patch.object(db, "_db_exists", return_value=False), \
                 mock.patch.object(
                     db, "_maint_psql", return_value=(["psql"], {})
                 ), \
                 mock.patch.object(db, "run", return_value=_cp(0)), \
                 mock.patch.object(
                     db.subprocess, "run",
                     return_value=_cp(1, err="fail" * 100),
                 ):
                with self.assertRaises(RuntimeError):
                    db.reset_database(cfg)


class ConnectionPasswordStatsTests(unittest.TestCase):
    def test_check_sql_connection_success(self):
        cfg = _cfg(".")
        with mock.patch.object(db, "run", return_value=_cp(0)):
            self.assertTrue(db.check_sql_connection(cfg))

    def test_check_sql_connection_fail_linux_and_windows(self):
        cfg = _cfg(".")
        with mock.patch.object(db, "run", return_value=_cp(1, err="nope\nline2")), \
             mock.patch.object(db.os, "name", "posix"):
            self.assertFalse(db.check_sql_connection(cfg))
        with mock.patch.object(db, "run", return_value=_cp(1, err="nope")), \
             mock.patch.object(db.os, "name", "nt"):
            self.assertFalse(db.check_sql_connection(cfg))

    def test_reset_database_password(self):
        cfg = _cfg(".")
        with mock.patch.object(
            db, "_maint_psql", return_value=(["psql"], {})
        ), mock.patch.object(db, "run", return_value=_cp(0)):
            db.reset_database_password(cfg)
        with mock.patch.object(
            db, "_maint_psql", return_value=(["psql"], {})
        ), mock.patch.object(db, "run", return_value=_cp(1)):
            with self.assertRaises(RuntimeError):
                db.reset_database_password(cfg)

    def test_show_db_stats(self):
        cfg = _cfg(".")
        with mock.patch.object(
            db.subprocess, "run",
            side_effect=[
                _cp(0, out="size"),
                _cp(0, out="tables", err="warn"),
                Exception("boom"),
            ],
        ):
            # Exception path inside helper is caught
            with mock.patch.object(
                db.subprocess, "run",
                side_effect=[
                    _cp(0, out="size"),
                    _cp(0, out="tables", err="warn"),
                    mock.Mock(side_effect=Exception("boom")),
                ],
            ):
                pass

        def run_side_effect(*args, **kwargs):
            # third call raises
            if not hasattr(run_side_effect, "n"):
                run_side_effect.n = 0
            run_side_effect.n += 1
            if run_side_effect.n == 3:
                raise OSError("boom")
            return _cp(0, out="ok", err="e" if run_side_effect.n == 2 else "")

        with mock.patch.object(db.subprocess, "run", side_effect=run_side_effect):
            db.show_db_stats(cfg)


if __name__ == "__main__":
    unittest.main()

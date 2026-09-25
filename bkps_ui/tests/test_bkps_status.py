#!/usr/bin/env python3
"""Unit tests for bkps_status with mocked openssl/keytool/network/fs."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOL_DIR = Path(__file__).resolve().parents[1]
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

import bkps_status as st  # noqa: E402
from bkps_config import Config  # noqa: E402


def _cfg(root: str) -> Config:
    cfg = Config()
    cfg.home = os.path.join(root, "home")
    os.makedirs(cfg.home, exist_ok=True)
    cfg.bkps_dir = os.path.join(root, "bkps")
    os.makedirs(cfg.bkps_dir, exist_ok=True)
    cfg.quartus_keys_dir = os.path.join(root, "qkeys")
    cfg.cm_provisioning_dir = os.path.join(root, "cm")
    cfg.db_user = "u"
    cfg.db_name = "d"
    cfg.db_password = "p"
    cfg.keystore_password = "k"
    cfg.yes = True
    return cfg


def _cp(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


class StatusCoreTests(unittest.TestCase):
    def test_show_status_variants(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            Path(cfg.quartus_keys_dir).mkdir(exist_ok=True)
            Path(cfg.cm_provisioning_dir).mkdir(exist_ok=True)
            Path(cfg.bkps_dir, "bkps.pid").write_text("99999")
            with mock.patch.object(st.os, "name", "posix"), \
                 mock.patch.object(st.os, "kill", side_effect=ProcessLookupError()), \
                 mock.patch.object(st.subprocess, "run", return_value=_cp(1)):
                st.show_status(cfg)
            Path(cfg.bkps_dir, "bkps.pid").write_text("bad")
            with mock.patch.object(st.subprocess, "run", return_value=_cp(0)):
                st.show_status(cfg)
            Path(cfg.bkps_dir, "bkps.pid").write_text("1")
            with mock.patch.object(st.os, "name", "nt"), \
                 mock.patch.object(
                     st.subprocess, "run",
                     side_effect=[_cp(0, out="image 1"), _cp(0)],
                 ):
                st.show_status(cfg)
            with mock.patch.object(st.os, "name", "posix"), \
                 mock.patch.object(st.os, "kill"), \
                 mock.patch.object(st.subprocess, "run", return_value=_cp(0)):
                st.show_status(cfg)
            Path(cfg.bkps_dir, "bkps.pid").unlink()
            with mock.patch.object(st.subprocess, "run", return_value=_cp(1)):
                st.show_status(cfg)

    def test_keys_certs_helpers(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            Path(cfg.quartus_keys_dir).mkdir(exist_ok=True)
            self.assertFalse(st.check_keys(cfg))
            for name in (
                "root0_private.pem", "root0.qky", "design0_sign_chain.qky",
                "aesccert1_sign_chain.qky", "signed_aes_efuse.ccert", "aes_hsm_root.qek",
            ):
                Path(cfg.quartus_keys_dir, name).write_text("x")
            self.assertTrue(st.check_keys(cfg))

            with mock.patch.object(st, "get_output", return_value="notAfter=Jan"):
                self.assertFalse(st.check_certs(cfg))
            keys = Path(cfg.bkps_dir, "keys")
            (keys / "bkps_ssl_cert").mkdir(parents=True)
            (keys / "tsci_cert").mkdir(parents=True)
            (keys / "bkps_ssl_cert" / "bkps_ssl_cert.crt").write_text("c")
            (keys / "super_admin_cert.crt").write_text("c")
            (keys / "tsci_cert" / "tsci_altera_com.pem").write_text("c")
            with mock.patch.object(st, "get_output", return_value="notAfter=Jan"):
                self.assertTrue(st.check_certs(cfg))

            # Exercise real _check_local_cert paths
            cert = str(keys / "bkps_ssl_cert" / "bkps_ssl_cert.crt")
            with mock.patch.object(st, "_cert_is_expired", return_value=False), \
                 mock.patch.object(st, "get_output", return_value="notAfter=2099"), \
                 mock.patch.object(st, "_is_self_signed", return_value=True):
                self.assertEqual(st._check_local_cert(cert, "lab", ca_path=cert), 0)
            with mock.patch.object(st, "_cert_is_expired", return_value=True), \
                 mock.patch.object(st, "_is_self_signed", return_value=False), \
                 mock.patch.object(st.os.path, "isfile", side_effect=lambda p: p == cert), \
                 mock.patch.object(st, "_verify_chain", return_value=(False, "bad")):
                self.assertGreater(st._check_local_cert(cert, "lab", ca_path="/no/ca"), 0)
            with mock.patch.object(st, "_cert_is_expired", side_effect=RuntimeError("e")), \
                 mock.patch.object(st, "_is_self_signed", side_effect=RuntimeError("s")), \
                 mock.patch.object(st, "_verify_chain", side_effect=RuntimeError("v")):
                self.assertGreater(st._check_local_cert(cert, "lab", ca_path=cert), 0)

        with mock.patch.object(st, "run", return_value=_cp(1)):
            self.assertTrue(st._cert_is_expired("x"))
        with mock.patch.object(st, "get_output", return_value="serial=0A"):
            self.assertEqual(st._cert_serial("x"), "A")
        with mock.patch.object(st, "get_output", return_value="noserial"):
            self.assertEqual(st._cert_serial("x"), "")
        self.assertEqual(st._norm_serial("0x00"), "0")
        self.assertEqual(st._norm_serial("0X0A:0B"), "A0B")

        sample = (
            "Alias name: foo\n"
            "Entry type: trustedCertEntry\n"
            "Owner: CN=A\n"
            "Issuer: CN=B\n"
            "Serial number: ab\n"
            "Alias name: bar\n"
            "Entry type: PrivateKeyEntry\n"
        )
        with mock.patch.object(st.os.path, "isfile", return_value=True), \
             mock.patch.object(st, "run", return_value=_cp(0, out=sample)):
            self.assertTrue(st._parse_keystore_trusted_entries("k", "p"))
        with mock.patch.object(st.os.path, "isfile", return_value=False):
            self.assertEqual(st._parse_keystore_trusted_entries("k", "p"), [])

        with mock.patch.object(st, "get_output", return_value="subject=CN=X\n"):
            self.assertIn("CN", st._cert_subject("c"))
        with mock.patch.object(st, "get_output", return_value=""):
            self.assertEqual(st._cert_subject("c"), "")
        with mock.patch.object(st, "get_output", return_value="issuer=CN=Y"):
            self.assertIn("CN", st._cert_issuer("c"))
        with mock.patch.object(st, "_cert_subject", return_value="CN=A"), \
             mock.patch.object(st, "_cert_issuer", return_value="CN=A"):
            self.assertTrue(st._is_self_signed("c"))

        with mock.patch.object(st, "run", return_value=_cp(0)):
            ok, _msg = st._verify_chain("c", "ca")
            self.assertTrue(ok)
        with mock.patch.object(st, "run", return_value=_cp(1, err="bad")):
            ok, _msg = st._verify_chain("c", "ca", untrusted_paths=["i"])
            self.assertFalse(ok)
        with mock.patch.object(st.os.path, "isfile", return_value=True), \
             mock.patch.object(st, "run", return_value=_cp(0, out="OK\n")):
            ok, _msg = st._verify_chain("c", "", untrusted_paths=["i"])
            self.assertTrue(ok)

        with mock.patch.object(st.os.path, "isfile", return_value=False):
            self.assertGreater(st._check_local_cert("c", "lab"), 0)
        with mock.patch.object(st.os.path, "isfile", return_value=True), \
             mock.patch.object(st, "_cert_is_expired", return_value=False), \
             mock.patch.object(st, "get_output", return_value="notAfter=2099"), \
             mock.patch.object(st, "_cert_subject", return_value="CN=A"), \
             mock.patch.object(st, "_cert_issuer", return_value="CN=B"), \
             mock.patch.object(st, "_cert_serial", return_value="1"), \
             mock.patch.object(st, "_is_self_signed", return_value=False), \
             mock.patch.object(st, "_verify_chain", return_value=(True, "OK")):
            self.assertEqual(st._check_local_cert("c", "lab", ca_path="ca"), 0)
        with mock.patch.object(st.os.path, "isfile", return_value=True), \
             mock.patch.object(st, "_cert_is_expired", return_value=True), \
             mock.patch.object(st, "_cert_subject", return_value="CN=A"), \
             mock.patch.object(st, "_cert_issuer", return_value="CN=B"), \
             mock.patch.object(st, "_cert_serial", return_value="1"), \
             mock.patch.object(st, "_is_self_signed", return_value=True), \
             mock.patch.object(st, "_verify_chain", return_value=(False, "bad")):
            self.assertGreater(st._check_local_cert("c", "lab", ca_path="ca"), 0)
        with mock.patch.object(st.os.path, "isfile", return_value=True), \
             mock.patch.object(st, "_cert_is_expired", return_value=False), \
             mock.patch.object(st, "get_output", return_value="notAfter=2099"), \
             mock.patch.object(st, "_cert_subject", return_value="CN=A"), \
             mock.patch.object(st, "_cert_issuer", return_value="CN=B"), \
             mock.patch.object(st, "_cert_serial", return_value="1"), \
             mock.patch.object(st, "_is_self_signed", return_value=False), \
             mock.patch.object(st, "_verify_chain", side_effect=RuntimeError("x")):
            self.assertGreater(st._check_local_cert("c", "lab", ca_path="ca"), 0)

    def test_trusted_validate_backup_restore_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            keys = Path(cfg.bkps_dir, "keys")
            (keys / "bkps_ssl_cert").mkdir(parents=True)
            (keys / "tsci_cert").mkdir(parents=True)
            (keys / "bkps_ssl_cert" / "bkps_ssl_cert.crt").write_text("c")
            (keys / "tsci_cert" / "tsci_altera_com.pem").write_text("t")
            (keys / "super_admin_cert.crt").write_text("a")
            (keys / "bkps_keystore.p12").write_bytes(b"k")
            Path(cfg.quartus_keys_dir).mkdir(exist_ok=True)
            Path(cfg.quartus_keys_dir, "programmer_cert.crt").write_text("p")
            Path(cfg.quartus_keys_dir, "programmer_bkps_signed.crt").write_text("p")
            Path(cfg.cm_provisioning_dir).mkdir(exist_ok=True)

            with mock.patch.object(st, "_check_local_cert", return_value=0), \
                 mock.patch.object(st, "_is_self_signed", return_value=True), \
                 mock.patch.object(
                     st, "_parse_keystore_trusted_entries",
                     return_value=[{"alias": "a", "serial": "1", "owner": "CN=x"}],
                 ), \
                 mock.patch.object(st, "_cert_serial", return_value="1"):
                self.assertTrue(st._check_trusted_certs(cfg))

            with mock.patch.object(st, "_check_local_cert", return_value=0), \
                 mock.patch.object(st, "_is_self_signed", return_value=True), \
                 mock.patch.object(
                     st, "_parse_keystore_trusted_entries",
                     return_value=[{"alias": "a", "serial": "99", "owner": "CN=x"}],
                 ), \
                 mock.patch.object(st, "_cert_serial", return_value="1"):
                self.assertFalse(st._check_trusted_certs(cfg))

            with mock.patch.object(st, "_check_local_cert", return_value=1), \
                 mock.patch.object(st, "_is_self_signed", return_value=False), \
                 mock.patch.object(
                     st, "_parse_keystore_trusted_entries",
                     side_effect=RuntimeError("x"),
                 ), \
                 mock.patch.object(st, "_cert_serial", side_effect=RuntimeError("s")):
                self.assertFalse(st._check_trusted_certs(cfg))

            with mock.patch.object(st, "_check_local_cert", return_value=0), \
                 mock.patch.object(st, "_is_self_signed", return_value=True), \
                 mock.patch.object(st, "_parse_keystore_trusted_entries", return_value=[]), \
                 mock.patch.object(st, "_cert_serial", return_value=""):
                self.assertFalse(st._check_trusted_certs(cfg))

            # server leaf present
            (keys / "bkps_ssl_cert" / "bkps_ssl_signed_certificate.crt").write_text("s")
            with mock.patch.object(st, "_check_local_cert", return_value=0), \
                 mock.patch.object(st, "_is_self_signed", return_value=False), \
                 mock.patch.object(
                     st, "_parse_keystore_trusted_entries",
                     return_value=[{"alias": "a", "serial": "1", "owner": "CN=x"}],
                 ), \
                 mock.patch.object(st, "_cert_serial", return_value="1"):
                self.assertTrue(st._check_trusted_certs(cfg))

            with mock.patch("socket.create_connection", return_value=mock.MagicMock()):
                self.assertTrue(st._check_server_connection(cfg))
            cfg.bkps_server_port = "bad"
            with mock.patch("socket.create_connection", side_effect=OSError("no")):
                self.assertFalse(st._check_server_connection(cfg))
            cfg.bkps_server_port = "8082"

            with mock.patch.object(st, "check_dependencies", return_value=(True, [])), \
                 mock.patch.object(st, "check_sql_connection", return_value=True), \
                 mock.patch.object(st, "_check_server_connection", return_value=True), \
                 mock.patch.object(st, "_check_trusted_certs", return_value=True), \
                 mock.patch.object(st, "check_keys", return_value=True):
                self.assertTrue(st.validate_setup(cfg))
            with mock.patch.object(st, "check_dependencies", side_effect=RuntimeError("d")), \
                 mock.patch.object(st, "check_sql_connection", side_effect=RuntimeError("db")), \
                 mock.patch.object(st, "_check_server_connection", side_effect=RuntimeError("s")), \
                 mock.patch.object(st, "_check_trusted_certs", return_value=False), \
                 mock.patch.object(st, "check_keys", return_value=False):
                self.assertFalse(st.validate_setup(cfg))

            Path(cfg.bkps_dir, "config").mkdir(exist_ok=True)
            with mock.patch.object(st.subprocess, "run", return_value=_cp(0)):
                st.backup_setup(cfg)

            backups = [p for p in Path(cfg.home).iterdir() if p.name.startswith("bkps_backup_")]
            self.assertTrue(backups)
            bak = backups[0]
            with mock.patch.object(st, "_maint_psql", return_value=(["psql"], {})), \
                 mock.patch.object(st, "run", return_value=_cp(0)), \
                 mock.patch.object(st.subprocess, "run", return_value=_cp(0)):
                st.restore_setup(cfg, str(bak))
            with mock.patch.object(st, "ask_confirmation", return_value=False):
                st.restore_setup(cfg, str(bak))
            with self.assertRaises(ValueError):
                st.restore_setup(cfg, "")
            with self.assertRaises(FileNotFoundError):
                st.restore_setup(cfg, "/no/such/backup")

            with mock.patch.object(st, "_maint_psql", return_value=(["psql"], {})), \
                 mock.patch.object(st, "run", return_value=_cp(0)), \
                 mock.patch.object(st, "stop_bkps_server"), \
                 mock.patch.object(st.shutil, "rmtree"):
                st.cleanup(cfg)
            with mock.patch.object(st, "ask_confirmation", return_value=False):
                st.cleanup(cfg)

    def test_prechecks_connectivity_cert_debug(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            Path(cfg.bkps_dir, "keys", "bkps_ssl_cert").mkdir(parents=True)
            Path(cfg.bkps_dir, "keys", "bkps_ssl_cert", "bkps_ssl_cert.crt").write_text("c")
            Path(cfg.quartus_keys_dir).mkdir(exist_ok=True)
            Path(cfg.quartus_keys_dir, "programmer_bkps_signed.crt").write_text("c")
            Path(cfg.quartus_keys_dir, "programmer_private.pem").write_text(
                "-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----"
            )
            with mock.patch.object(st, "command_exists", return_value=True), \
                 mock.patch.object(st, "check_dependencies", return_value=(True, [])), \
                 mock.patch.object(st, "run", return_value=_cp(0, out="ok")), \
                 mock.patch.object(st, "get_output", return_value="ok"), \
                 mock.patch.object(st, "check_sql_connection", return_value=True), \
                 mock.patch.object(st.subprocess, "run", return_value=_cp(0, out="ok")), \
                 mock.patch("socket.create_connection", return_value=mock.MagicMock()):
                st.run_prechecks(cfg)
            with mock.patch.object(st, "command_exists", return_value=False), \
                 mock.patch.object(st, "check_dependencies", return_value=(False, ["j"])), \
                 mock.patch.object(st, "check_sql_connection", return_value=False), \
                 mock.patch("socket.create_connection", side_effect=OSError()):
                st.run_prechecks(cfg)

            def _sub_run(cmd, **kwargs):
                if kwargs.get("text"):
                    out = '{"version": "1.2.3"}' if "health" in " ".join(map(str, cmd)) else "2051"
                    return subprocess.CompletedProcess(cmd, 0, out, "")
                # openssl s_client binary mode
                return subprocess.CompletedProcess(
                    cmd, 0, b"Verify return code: 0\n", b""
                )

            cfg.verbose = True
            with mock.patch.object(st, "command_exists", return_value=True), \
                 mock.patch.object(st.subprocess, "run", side_effect=_sub_run), \
                 mock.patch.object(st, "get_output", return_value="ok"), \
                 mock.patch.object(st, "run", return_value=_cp(0, out="ok")), \
                 mock.patch.object(st.time, "sleep"), \
                 mock.patch("socket.create_connection", return_value=mock.MagicMock()):
                st.run_connectivity_tests(cfg)

            def _sub_run_fail(cmd, **kwargs):
                if kwargs.get("text"):
                    return subprocess.CompletedProcess(cmd, 1, "", "err")
                return subprocess.CompletedProcess(cmd, 1, b"fail", b"fail")

            cfg.verbose = False
            with mock.patch.object(st, "command_exists", return_value=False), \
                 mock.patch.object(st.time, "sleep"), \
                 mock.patch.object(st.subprocess, "run", side_effect=_sub_run_fail), \
                 mock.patch("socket.create_connection", side_effect=OSError()):
                st.run_connectivity_tests(cfg)

            def _cert_run(cmd, **kwargs):
                joined = " ".join(map(str, cmd))
                if "-issuer" in joined:
                    return subprocess.CompletedProcess(cmd, 0, "issuer=CN=A", "")
                if "-subject" in joined:
                    return subprocess.CompletedProcess(cmd, 0, "subject=CN=A", "")
                if "-text" in joined:
                    return subprocess.CompletedProcess(
                        cmd, 0, "Subject: CN=A\nIssuer: CN=A\nNot After: 2099\n", ""
                    )
                if "md5" in joined:
                    return subprocess.CompletedProcess(cmd, 0, "MD5=abc", "")
                return subprocess.CompletedProcess(cmd, 0, "ok", "")

            with mock.patch.object(st, "check_cert_expiry"), \
                 mock.patch.object(st, "run", return_value=_cp(0, out="ok")), \
                 mock.patch.object(st, "get_output", return_value="notAfter=2099"), \
                 mock.patch.object(st.subprocess, "run", side_effect=_cert_run):
                st.run_cert_validity_tests(cfg)

            def _cert_run2(cmd, **kwargs):
                joined = " ".join(map(str, cmd))
                if "-issuer" in joined:
                    return subprocess.CompletedProcess(cmd, 0, "issuer=CN=CA", "")
                if "-subject" in joined:
                    return subprocess.CompletedProcess(cmd, 0, "subject=CN=Leaf", "")
                return subprocess.CompletedProcess(cmd, 0, "Subject: X\n", "")

            with mock.patch.object(st.subprocess, "run", side_effect=_cert_run2):
                st.run_cert_validity_tests(cfg)

            with mock.patch.object(st, "run_prechecks"), \
                 mock.patch.object(st, "run_connectivity_tests"), \
                 mock.patch.object(st, "run_cert_validity_tests"):
                st.run_debug_tests(cfg)

            st._dir_ok(cfg.bkps_dir, "lab")
            st._dir_ok("/no/dir", "lab")
            st._file_ok(str(Path(cfg.bkps_dir, "keys", "bkps_ssl_cert", "bkps_ssl_cert.crt")), "lab")
            st._file_ok("/no", "lab")
            with mock.patch.object(st, "get_output", return_value="notAfter=2099"):
                st._check_cert_expiry_brief(
                    str(Path(cfg.bkps_dir, "keys", "bkps_ssl_cert", "bkps_ssl_cert.crt"))
                )
            with mock.patch.object(st, "get_output", return_value=""):
                st._check_cert_expiry_brief("/no")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Unit tests for bkps_server_setup with mocked openssl/keytool/network."""

from __future__ import annotations

import hashlib
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

import bkps_server_setup as ss  # noqa: E402


def _cfg(root: str, **kwargs):
    base = dict(
        bkps_dir=root,
        # Provider profiles are copied from the checkout's stock config.
        bkps_repo_dir=str(TOOL_DIR.parent),
        bc_keystore_password="bcpw",
        hsm_keystore_password="hsmpw",
        hsm_keystore_path="",
        local_override_bouncycastle_jar="",
        local_override_tsci_cert="",
        ssl_password="sslpw",
        pkcs11_password="pkcspw",
        keystore_password="kspw",
        profile_name="agilex5",
        libspdm_wrapper_path="",
        db_host="localhost",
        db_port="5432",
        db_name="bkps_database",
        db_user="bkps_user",
        db_password="dbpw",
        bkps_server_port="8082",
        bkps_server_ip="localhost",
        log_level="INFO",
    )
    base.update(kwargs)
    return SimpleNamespace(**base)


def _cp(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


class ProviderSetupTests(unittest.TestCase):
    def test_setup_bouncycastle_skip_and_download(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            jar = Path(td, "libs-ext", "bcprov-jdk18on-1.78.1.jar")
            yml = Path(td, "config", "application-bouncycastle.yml")
            jar.parent.mkdir(parents=True)
            yml.parent.mkdir(parents=True)
            jar.write_bytes(b"j")
            yml.write_text("y")
            ss.setup_bouncycastle(cfg)

            jar.unlink()
            yml.unlink()
            override = Path(td, "local.jar")
            override.write_bytes(b"local")
            cfg.local_override_bouncycastle_jar = str(override)
            ss.setup_bouncycastle(cfg)
            self.assertTrue(jar.is_file())

            jar.unlink()
            yml.unlink(missing_ok=True)
            cfg.local_override_bouncycastle_jar = "/missing.jar"
            with self.assertRaises(RuntimeError):
                ss.setup_bouncycastle(cfg)

            cfg.local_override_bouncycastle_jar = ""
            with mock.patch.object(ss.shutil, "which", return_value=None), \
                 mock.patch.object(ss, "run", return_value=_cp(1)):
                with self.assertRaises(RuntimeError):
                    ss.setup_bouncycastle(cfg)

            def which(name):
                return f"/bin/{name}"

            def run_side(cmd, **kwargs):
                # create jar when wget/curl "succeeds"
                Path(td, "libs-ext", "bcprov-jdk18on-1.78.1.jar").write_bytes(b"d")
                return _cp(0)

            with mock.patch.object(ss.shutil, "which", side_effect=which), \
                 mock.patch.object(ss, "run", side_effect=run_side), \
                 mock.patch.object(ss.os, "symlink", side_effect=OSError("no")):
                # need jar missing and yml missing
                Path(td, "config", "application-bouncycastle.yml").unlink(missing_ok=True)
                Path(td, "libs-ext", "bcprov-jdk18on-1.78.1.jar").unlink(missing_ok=True)
                ss.setup_bouncycastle(cfg)

            # jar exists, yml missing — skip download branch
            Path(td, "config", "application-bouncycastle.yml").unlink(missing_ok=True)
            Path(td, "config", "application-bc.yml").unlink(missing_ok=True)
            jar.write_bytes(b"j")
            with mock.patch.object(ss.os, "symlink"):
                ss.setup_bouncycastle(cfg)

            # curl fallback after wget fail
            jar.unlink(missing_ok=True)
            Path(td, "config", "application-bouncycastle.yml").unlink(missing_ok=True)
            Path(td, "config", "application-bc.yml").unlink(missing_ok=True)

            def which2(name):
                return "/bin/x" if name in ("wget", "curl") else None

            calls = {"n": 0}

            def run2(cmd, **kwargs):
                calls["n"] += 1
                if calls["n"] == 1:
                    return _cp(1)
                Path(td, "libs-ext", "bcprov-jdk18on-1.78.1.jar").write_bytes(b"d")
                return _cp(0)

            with mock.patch.object(ss.shutil, "which", side_effect=which2), \
                 mock.patch.object(ss, "run", side_effect=run2):
                ss.setup_bouncycastle(cfg)

    def test_setup_luna_and_ncipher(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            ss.setup_luna_config(cfg)
            self.assertTrue(Path(td, "config", "application-luna.yml").is_file())
            ss.setup_luna_config(cfg)  # skip

            cfg.hsm_keystore_path = "tokenlabel:X"
            ss.setup_luna_config  # already exists
            Path(td, "config", "application-luna.yml").unlink()
            ss.setup_luna_config(cfg)

            ss.setup_ncipher_config(cfg)
            ss.setup_ncipher_config(cfg)
            Path(td, "config", "application-ncipher.yml").unlink()
            cfg.hsm_keystore_path = ""
            ss.setup_ncipher_config(cfg)
            Path(td, "config", "application-ncipher.yml").unlink()
            cfg.hsm_keystore_path = "C:/ks.jks"
            ss.setup_ncipher_config(cfg)


class SslAndCertTests(unittest.TestCase):
    def test_thumbprint_and_windows_helpers(self):
        with self.assertRaises(RuntimeError):
            ss._certificate_sha1_thumbprint("/no/such.crt")
        der = b"\x30\x03\x02\x01\x01"
        with mock.patch("builtins.open", mock.mock_open(read_data="PEM")), \
             mock.patch.object(ss.ssl, "PEM_cert_to_DER_cert", return_value=der):
            tp = ss._certificate_sha1_thumbprint("x.crt")
        self.assertEqual(tp, hashlib.sha1(der).hexdigest().upper())

        with mock.patch.object(ss.subprocess, "run", return_value=_cp(0)):
            self.assertTrue(ss._windows_current_user_root_contains("AA"))
        with mock.patch.object(ss.subprocess, "run", side_effect=OSError("x")):
            with self.assertRaises(RuntimeError):
                ss._windows_current_user_root_contains("AA")

        with mock.patch.object(ss.sys, "platform", "linux"):
            ss._install_windows_demo_ca("x.crt")
        with mock.patch.object(ss.sys, "platform", "win32"), \
             mock.patch.object(ss.os.path, "isfile", return_value=False):
            with self.assertRaises(RuntimeError):
                ss._install_windows_demo_ca("x.crt")

        with mock.patch.object(ss.sys, "platform", "win32"), \
             mock.patch.object(ss.os.path, "isfile", return_value=True), \
             mock.patch.object(ss, "_certificate_sha1_thumbprint", return_value="T"), \
             mock.patch.object(ss, "_windows_current_user_root_contains", return_value=True):
            ss._install_windows_demo_ca("x.crt")

        with mock.patch.object(ss.sys, "platform", "win32"), \
             mock.patch.object(ss.os.path, "isfile", return_value=True), \
             mock.patch.object(ss, "_certificate_sha1_thumbprint", return_value="T"), \
             mock.patch.object(
                 ss, "_windows_current_user_root_contains", side_effect=[False, True]
             ), \
             mock.patch.object(ss.subprocess, "run", return_value=_cp(0)):
            ss._install_windows_demo_ca("x.crt")

        with mock.patch.object(ss.sys, "platform", "win32"), \
             mock.patch.object(ss.os.path, "isfile", return_value=True), \
             mock.patch.object(ss, "_certificate_sha1_thumbprint", return_value="T"), \
             mock.patch.object(ss, "_windows_current_user_root_contains", return_value=False), \
             mock.patch.object(ss.subprocess, "run", side_effect=OSError("fail")):
            with self.assertRaises(RuntimeError):
                ss._install_windows_demo_ca("x.crt")

        with mock.patch.object(ss.sys, "platform", "win32"), \
             mock.patch.object(ss.os.path, "isfile", return_value=True), \
             mock.patch.object(ss, "_certificate_sha1_thumbprint", return_value="T"), \
             mock.patch.object(ss, "_windows_current_user_root_contains", return_value=False), \
             mock.patch.object(ss.subprocess, "run", return_value=_cp(1, err="bad")):
            with self.assertRaises(RuntimeError):
                ss._install_windows_demo_ca("x.crt")

        with mock.patch.object(ss.sys, "platform", "win32"), \
             mock.patch.object(ss.os.path, "isfile", return_value=True), \
             mock.patch.object(ss, "_certificate_sha1_thumbprint", return_value="T"), \
             mock.patch.object(
                 ss, "_windows_current_user_root_contains", side_effect=[False, False]
             ), \
             mock.patch.object(ss.subprocess, "run", return_value=_cp(0)):
            with self.assertRaises(RuntimeError):
                ss._install_windows_demo_ca("x.crt")

    def test_create_ssl_certificates_paths(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            # complete outputs with CA:TRUE
            ssl_dir = Path(td, "keys", "bkps_ssl_cert")
            ssl_dir.mkdir(parents=True)
            for name in ("bkps_ssl_cert.crt", "bkps_ssl_private.pem", "bkps_ssl.p12"):
                (ssl_dir / name).write_text("x")
            Path(td, "keys", "super_admin_cert.crt").write_text("a")
            tsci = Path(td, "keys", "tsci_cert")
            tsci.mkdir(parents=True)
            (tsci / "tsci_altera_com.pem").write_text("t")
            with mock.patch.object(
                ss.subprocess, "run", return_value=_cp(0, out="CA:TRUE")
            ), mock.patch.object(ss, "_install_windows_demo_ca"):
                ss.create_ssl_certificates(cfg)

            # lacks CA:TRUE — regenerate
            with mock.patch.object(
                ss.subprocess, "run", return_value=_cp(0, out="CA:FALSE")
            ), mock.patch.object(ss, "run"), \
                 mock.patch.object(ss, "_download_tsci_cert"), \
                 mock.patch.object(ss, "_install_windows_demo_ca"), \
                 mock.patch.object(ss, "_ssl_certificate_outputs_complete",
                                   side_effect=[False, True]):
                # after remove, force incomplete then generate
                for p in ssl_dir.iterdir():
                    p.unlink()
                Path(td, "keys", "super_admin_cert.crt").unlink(missing_ok=True)
                (tsci / "tsci_altera_com.pem").unlink(missing_ok=True)

                def run_create(cmd, **kwargs):
                    # create artifacts when openssl runs
                    if "req" in cmd and "super_admin" not in " ".join(cmd):
                        (ssl_dir / "bkps_ssl_cert.crt").write_text("c")
                        (ssl_dir / "bkps_ssl_private.pem").write_text("k")
                    if "pkcs12" in cmd:
                        (ssl_dir / "bkps_ssl.p12").write_text("p")
                    if "superadmin" in " ".join(cmd) or (
                        "req" in cmd and any("super_admin" in str(x) for x in cmd)
                    ):
                        Path(td, "keys", "super_admin_cert.crt").write_text("a")
                        Path(td, "keys", "super_admin_private.pem").write_text("k")
                    return _cp(0)

                with mock.patch.object(ss, "run", side_effect=run_create), \
                     mock.patch.object(
                         ss, "_download_tsci_cert",
                         side_effect=lambda p: Path(p).write_text("t"),
                     ), \
                     mock.patch.object(ss, "_install_windows_demo_ca"), \
                     mock.patch.object(
                         ss.subprocess, "run",
                         return_value=_cp(0, out="no ca"),
                     ):
                    # recreate incomplete state
                    for p in list(ssl_dir.glob("*")):
                        p.unlink()
                    Path(td, "keys", "super_admin_cert.crt").unlink(missing_ok=True)
                    (tsci / "tsci_altera_com.pem").unlink(missing_ok=True)
                    ss.create_ssl_certificates(cfg)

            # timeout on openssl check for existing
            for name in ("bkps_ssl_cert.crt", "bkps_ssl_private.pem", "bkps_ssl.p12"):
                (ssl_dir / name).write_text("x")
            Path(td, "keys", "super_admin_cert.crt").write_text("a")
            (tsci / "tsci_altera_com.pem").write_text("t")
            with mock.patch.object(
                ss.subprocess, "run", side_effect=subprocess.TimeoutExpired("o", 1)
            ), mock.patch.object(ss, "_install_windows_demo_ca"):
                ss.create_ssl_certificates(cfg)

    def test_create_ssl_with_overrides_and_failures(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            ssl_dir = Path(td, "keys", "bkps_ssl_cert")
            ssl_dir.mkdir(parents=True)

            def run_create(cmd, **kwargs):
                joined = " ".join(str(x) for x in cmd)
                if "pkcs12" in joined:
                    (ssl_dir / "bkps_ssl.p12").write_text("p")
                if "req" in cmd and "super_admin" in joined:
                    Path(td, "keys", "super_admin_cert.crt").write_text("a")
                    Path(td, "keys", "super_admin_private.pem").write_text("k")
                if "req" in cmd and "bkps_ssl" in joined:
                    (ssl_dir / "bkps_ssl_cert.crt").write_text("c")
                    (ssl_dir / "bkps_ssl_private.pem").write_text("k")
                # also handle keyout/out paths in argv
                for i, x in enumerate(cmd):
                    if x == "-out" and i + 1 < len(cmd):
                        Path(cmd[i + 1]).parent.mkdir(parents=True, exist_ok=True)
                        Path(cmd[i + 1]).write_text("out")
                    if x == "-keyout" and i + 1 < len(cmd):
                        Path(cmd[i + 1]).parent.mkdir(parents=True, exist_ok=True)
                        Path(cmd[i + 1]).write_text("key")
                    if x == "-out" and "bkps_ssl.p12" in str(cmd[i + 1] if i + 1 < len(cmd) else ""):
                        Path(cmd[i + 1]).write_text("p12")
                return _cp(0)

            ov = Path(td, "tsci.pem")
            ov.write_text("override")
            cfg.local_override_tsci_cert = str(ov)
            with mock.patch.object(ss, "run", side_effect=run_create), \
                 mock.patch.object(ss, "_install_windows_demo_ca"):
                ss.create_ssl_certificates(cfg)

            # missing override
            for p in Path(td, "keys").rglob("*"):
                if p.is_file():
                    p.unlink()
            cfg.local_override_tsci_cert = "/no/tsci.pem"
            with mock.patch.object(ss, "run", side_effect=run_create), \
                 mock.patch.object(ss, "_install_windows_demo_ca"):
                with self.assertRaises(RuntimeError):
                    ss.create_ssl_certificates(cfg)

            # p12 not created
            cfg.local_override_tsci_cert = ""
            for p in Path(td, "keys").rglob("*"):
                if p.is_file():
                    p.unlink()

            def run_no_p12(cmd, **kwargs):
                for i, x in enumerate(cmd):
                    if x in ("-out", "-keyout") and i + 1 < len(cmd):
                        if str(cmd[i + 1]).endswith(".p12"):
                            continue
                        Path(cmd[i + 1]).parent.mkdir(parents=True, exist_ok=True)
                        Path(cmd[i + 1]).write_text("x")
                return _cp(0)

            with mock.patch.object(ss, "run", side_effect=run_no_p12):
                with self.assertRaises(RuntimeError):
                    ss.create_ssl_certificates(cfg)

    def test_download_tsci_and_warning(self):
        with tempfile.TemporaryDirectory() as td:
            dest = os.path.join(td, "t.pem")
            pem = b"-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n"
            with mock.patch.object(
                ss.subprocess, "run", return_value=_cp(0, out=pem.decode())
            ):
                # need bytes on stdout
                with mock.patch.object(
                    ss.subprocess, "run",
                    return_value=SimpleNamespace(stdout=pem, returncode=0),
                ):
                    ss._download_tsci_cert(dest)
            self.assertTrue(os.path.isfile(dest))

            dest2 = os.path.join(td, "t2.pem")
            with mock.patch.object(
                ss.subprocess, "run",
                return_value=SimpleNamespace(stdout=b"no cert", returncode=0),
            ):
                ss._download_tsci_cert(dest2)
            with mock.patch.object(ss.subprocess, "run", side_effect=OSError()):
                ss._download_tsci_cert(dest2)
            ss._tsci_warning()


class KeystoreConfigImportTests(unittest.TestCase):
    def test_create_keystore_and_config(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            ks = Path(td, "keys", "bkps_keystore.p12")
            ks.parent.mkdir(parents=True)
            ks.write_bytes(b"x")
            ss.create_bkps_keystore(cfg)
            ks.unlink()
            with mock.patch.object(ss, "run", return_value=_cp(0)):
                ss.create_bkps_keystore(cfg)

            # config with wrapper path and without
            Path(td, "libspdm_wrapper.so").write_bytes(b"so")
            cfg.libspdm_wrapper_path = ""
            ss.create_bkps_config(cfg)
            cfg.profile_name = "agilex"
            cfg.libspdm_wrapper_path = str(Path(td, "libspdm_wrapper.so"))
            ss.create_bkps_config(cfg)

            # placeholder path
            Path(td, "libspdm_wrapper.so").unlink()
            cfg.libspdm_wrapper_path = "/missing.so"
            with mock.patch.object(ss.os, "name", "posix"):
                ss.create_bkps_config(cfg)

    def test_openssl_cnf_variants(self):
        cfg = _cfg(".", bkps_server_ip="10.0.0.1")
        text = ss._bkps_openssl_cnf(cfg)
        self.assertIn("IP.2 = 10.0.0.1", text)
        cfg.bkps_server_ip = "bkps.example.com"
        text = ss._bkps_openssl_cnf(cfg)
        self.assertIn("DNS.2 = bkps.example.com", text)
        cfg.bkps_server_ip = "localhost"
        self.assertIn("localhost", ss._bkps_openssl_cnf(cfg))
        self.assertIn("clientAuth", ss._superadmin_openssl_cnf())

    def test_import_aes_key(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with self.assertRaises(ValueError):
                ss.import_aes_key_to_bc_keystore(cfg, "short")
            with self.assertRaises(RuntimeError):
                ss.import_aes_key_to_bc_keystore(cfg, "A" * 64)

            jar = Path(td, "libs-ext", "bcprov-jdk18on-1.78.1.jar")
            jar.parent.mkdir(parents=True)
            jar.write_bytes(b"j")
            keys = Path(td, "keys")
            keys.mkdir(exist_ok=True)

            with mock.patch.object(
                ss.subprocess, "run",
                side_effect=[
                    _cp(1, err="compile fail"),
                ],
            ):
                with self.assertRaises(RuntimeError):
                    ss.import_aes_key_to_bc_keystore(cfg, "A" * 64)

            def run_ok(cmd, **kwargs):
                if cmd[0] == "javac":
                    Path(td, "keys", "_ImportAesKey.class").write_bytes(b"c")
                    return _cp(0, out="compiled\n")
                if cmd[0] == "java":
                    return _cp(0, out="AES key imported\n")
                return _cp(0, out="list\n")

            with mock.patch.object(ss.subprocess, "run", side_effect=run_ok):
                ss.import_aes_key_to_bc_keystore(cfg, "B" * 64, parent_step=1)

            def run_java_fail(cmd, **kwargs):
                if cmd[0] == "javac":
                    Path(td, "keys", "_ImportAesKey.class").write_bytes(b"c")
                    return _cp(0)
                if cmd[0] == "java":
                    return _cp(1, err="fail")
                return _cp(0)

            with mock.patch.object(ss.subprocess, "run", side_effect=run_java_fail):
                with self.assertRaises(RuntimeError):
                    ss.import_aes_key_to_bc_keystore(cfg, "C" * 64)

            # cleanup OSError on remove
            def run_then_remove_fail(cmd, **kwargs):
                if cmd[0] == "javac":
                    Path(td, "keys", "_ImportAesKey.class").write_bytes(b"c")
                    return _cp(0)
                if cmd[0] == "java":
                    return _cp(0)
                return _cp(0, out="ok")

            with mock.patch.object(ss.subprocess, "run", side_effect=run_then_remove_fail), \
                 mock.patch.object(ss.os, "remove", side_effect=OSError()):
                ss.import_aes_key_to_bc_keystore(cfg, "D" * 64)


if __name__ == "__main__":
    unittest.main()

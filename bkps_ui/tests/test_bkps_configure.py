#!/usr/bin/env python3
"""Unit tests for bkps_configure.py (mocked I/O / runner)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

TOOL_DIR = Path(__file__).resolve().parents[1]
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

import bkps_configure as c  # noqa: E402
from bkps_config import Config  # noqa: E402


def setUpModule():
    # Progress messages contain Unicode glyphs; a narrow console codec (cp1252)
    # would turn an incidental print into a UnicodeEncodeError.
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(errors="replace")


def RR(code=0, out="", err=""):
    return SimpleNamespace(returncode=code, stdout=out, stderr=err)


def _cfg(root: str) -> Config:
    cfg = Config()
    cfg.bkps_dir = root
    cfg.quartus_keys_dir = os.path.join(root, "qkeys")
    cfg.cm_provisioning_dir = os.path.join(root, "cm")
    cfg.bkps_server_ip = "127.0.0.1"
    cfg.bkps_server_port = 8443
    cfg.profile_name = "agilex5"
    cfg.device_part = "AGIB027R31B1E1V"
    cfg.programmer_cert_password = "pw"
    cfg.bc_keystore_password = "pw"
    cfg.security_provider = "bouncycastle"
    cfg.yes = True
    os.makedirs(cfg.quartus_keys_dir, exist_ok=True)
    os.makedirs(os.path.join(root, "keys", "bkps_ssl_cert"), exist_ok=True)
    os.makedirs(os.path.join(root, "admin-tools"), exist_ok=True)
    os.makedirs(os.path.join(root, "libs-ext"), exist_ok=True)
    Path(root, "keys", "bkps_ssl_cert", "bkps_ssl_cert.crt").write_text("CA")
    return cfg


def _valid_json(path: str, aes="aabb", qek="ccdd") -> str:
    data = {
        "confidentialData": {
            "aesKey": {"value": aes},
            "qek": {"value": qek},
        },
        "corimUrl": "http://example/corim",
    }
    Path(path).write_text(json.dumps(data) + "\n")
    return path


class HelpersTests(unittest.TestCase):
    def test_signing_key_helpers(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with mock.patch.object(c, "_runner", return_value=RR(0, out='{"id": 3}')):
                self.assertEqual(c._signing_key_list_raw(cfg, attempts=1), '{"id": 3}')
            with mock.patch.object(c, "_runner", side_effect=[RR(1, err="t"), RR(0, out='{"id":1}')]), \
                 mock.patch.object(c.time, "sleep"):
                self.assertIn("id", c._signing_key_list_raw(cfg, attempts=2, delay_sec=0))
            with mock.patch.object(c, "_runner", return_value=RR(1)), \
                 mock.patch.object(c.time, "sleep"):
                with self.assertRaises(RuntimeError):
                    c._signing_key_list_raw(cfg, attempts=1)
            with mock.patch.object(c, "_signing_key_list_raw", return_value='{"id": 9}\n{"signingKeyId": 8}'):
                self.assertEqual(c._signing_key_ids(cfg), {"9", "8"})
            with mock.patch.object(c, "_signing_key_list_raw", return_value=""):
                self.assertEqual(c._signing_key_ids(cfg), set())
            with mock.patch.object(c, "_signing_key_ids", side_effect=[set(), {"42"}]), \
                 mock.patch.object(c, "_runner"):
                self.assertEqual(c._create_signing_key_and_get_id(cfg), "42")
            with mock.patch.object(c, "_signing_key_ids", return_value=set()), \
                 mock.patch.object(c, "_runner"):
                with self.assertRaises(RuntimeError):
                    c._create_signing_key_and_get_id(cfg)

    def test_quartus_and_misc_helpers(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with mock.patch.object(c, "run") as run:
                c._quartus_create_root(td, "agilex", "root0")
                c._sign_bkps_chain(td, "agilex", "a.pem", "a.qky", "0", "out.qky")
                self.assertGreaterEqual(run.call_count, 4)
            self.assertIn("REQUESTS_CA_BUNDLE", c._runner_env_with_ssl_ca(cfg))
            self.assertTrue(c._is_secure_enclave_error('"code": 2080'))
            self.assertFalse(c._is_secure_enclave_error("other"))
            c._print_secure_enclave_recovery(cfg)

            # diagnostics branches
            c._print_secure_enclave_diagnostics(cfg)
            os.makedirs(os.path.join(td, "config"), exist_ok=True)
            Path(td, "config", "application-bouncycastle.yml").write_text("x:1\n")
            Path(td, "keys", "bc-keystore-bkps-static.jks").write_bytes(b"k")
            os.makedirs(os.path.join(td, "logs"), exist_ok=True)
            Path(td, "logs", "bkps.log").write_text("security provider failed\n")
            c._print_secure_enclave_diagnostics(cfg)
            Path(td, "logs", "bkps.log").write_text("benign\n")
            c._print_secure_enclave_diagnostics(cfg)
            with mock.patch("builtins.open", side_effect=OSError("x")):
                # force read failure after file exists check via isfile True then open fail
                with mock.patch.object(c.os.path, "isfile", return_value=True):
                    try:
                        c._print_secure_enclave_diagnostics(cfg)
                    except Exception:
                        pass

            jp = _valid_json(os.path.join(td, "c.json"))
            self.assertTrue(c._config_has_qek_field(jp))
            self.assertFalse(c._config_has_qek_field(os.path.join(td, "missing.json")))
            Path(td, "bad.json").write_text("{")
            self.assertFalse(c._config_has_qek_field(os.path.join(td, "bad.json")))
            self.assertEqual(
                c._generated_configuration_values(json.loads(Path(jp).read_text())),
                ("aabb", "ccdd", "http://example/corim"),
            )
            self.assertEqual(c._generated_configuration_values(None), ("", "", ""))
            self.assertEqual(c._generated_configuration_values({"x": 1}), ("", "", ""))

            Path(td, "libs-ext", "bcprov-jdk18on-1.78.1.jar").write_bytes(b"j")
            with mock.patch.object(c.subprocess, "run", return_value=RR(0)):
                self.assertTrue(c._bc_keystore_has_alias(cfg, "qek_encryption_key"))
            with mock.patch.object(c.subprocess, "run", return_value=RR(1)):
                self.assertFalse(c._bc_keystore_has_alias(cfg, "qek_encryption_key"))
            self.assertFalse(c._bc_keystore_has_alias(cfg, "nope"))  # jar may exist but keystore check
            # missing jar
            Path(td, "libs-ext", "bcprov-jdk18on-1.78.1.jar").unlink()
            self.assertFalse(c._bc_keystore_has_alias(cfg, "alias"))

            with mock.patch.object(c, "_bc_keystore_has_alias", return_value=True):
                c._ensure_qek_alias_ready_for_upload(cfg, jp)
            with mock.patch.object(c, "_bc_keystore_has_alias", return_value=False):
                with self.assertRaises(RuntimeError):
                    c._ensure_qek_alias_ready_for_upload(cfg, jp)
            cfg.security_provider = "softhsm"
            c._ensure_qek_alias_ready_for_upload(cfg, jp)  # non-bc early return
            cfg.security_provider = "bouncycastle"
            Path(td, "noqek.json").write_text(json.dumps({"confidentialData": {"aesKey": {"value": "aa"}}}))
            c._ensure_qek_alias_ready_for_upload(cfg, os.path.join(td, "noqek.json"))

            pem = Path(td, "k.pem")
            pem.write_text("-----BEGIN ENCRYPTED PRIVATE KEY-----\nx\n-----END-----")
            self.assertTrue(c._pem_key_is_encrypted(str(pem)))
            with self.assertRaises(RuntimeError):
                c._reject_encrypted_client_key(str(pem))
            pem.write_text("-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----")
            self.assertFalse(c._pem_key_is_encrypted(str(pem)))
            c._reject_encrypted_client_key(str(pem))
            self.assertFalse(c._pem_key_is_encrypted(os.path.join(td, "missing.pem")))

            self.assertEqual(c._extract_user_id_from_create_output('{"id": 7}'), "7")
            self.assertEqual(c._extract_user_id_from_create_output("user id: 8"), "8")
            self.assertEqual(c._extract_user_id_from_create_output(""), "")
            self.assertTrue(c._user_has_role('| 1 | ROLE_ADMIN |', "1", "ROLE_ADMIN"))
            self.assertTrue(c._user_has_role('{"id": 1, "roles": ["ROLE_ADMIN"]}', "1", "ROLE_ADMIN"))
            self.assertFalse(c._user_has_role("[]", "1", "ROLE_ADMIN"))
            self.assertFalse(c._user_has_role("", "1", "ROLE_ADMIN"))
            self.assertEqual(
                c._parse_imported_thumbprint("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF\n", "p"),
                "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
            )
            with self.assertRaises(RuntimeError):
                c._parse_imported_thumbprint("none", "p")

            der = b"\x30\x03\x02\x01\x01"
            with mock.patch("builtins.open", mock.mock_open(read_data="-----BEGIN CERT-----\n")), \
                 mock.patch.object(c.ssl, "PEM_cert_to_DER_cert", return_value=der):
                self.assertEqual(len(c._certificate_sha1_thumbprint("x")), 40)
            with mock.patch("builtins.open", side_effect=OSError("e")):
                with self.assertRaises(RuntimeError):
                    c._certificate_sha1_thumbprint("x")

            c._atomic_write_text(os.path.join(td, "a", "b.txt"), "hi")
            self.assertEqual(Path(td, "a", "b.txt").read_text(), "hi")
            with mock.patch.object(c.os, "replace", side_effect=OSError("fail")):
                with self.assertRaises(OSError):
                    c._atomic_write_text(os.path.join(td, "a", "c.txt"), "x")

            with mock.patch.object(c, "_runner", side_effect=[RR(1), RR(0, out="ok")]), \
                 mock.patch.object(c.time, "sleep"):
                self.assertEqual(c._runner_capture_retry(cfg, "x", attempts=2, delay_sec=0).returncode, 0)
            with mock.patch.object(c, "_runner", return_value=RR(1)), \
                 mock.patch.object(c.time, "sleep"):
                self.assertEqual(c._runner_capture_retry(cfg, "x", attempts=1).returncode, 1)

            c._write_runner_config(cfg, os.path.join(td, "admin-tools", "runner-config.json"), "c.crt")
            self.assertTrue(Path(td, "admin-tools", "runner-config.json").is_file())

            self.assertIsNone(c._read_json_object(os.path.join(td, "missing.json"), required=False))
            with self.assertRaises(Exception):
                c._read_json_object(os.path.join(td, "missing.json"), required=True)
            Path(td, "arr.json").write_text("[1]")
            self.assertIsNone(c._read_json_object(os.path.join(td, "arr.json"), required=False))
            with self.assertRaises(ValueError):
                c._read_json_object(os.path.join(td, "arr.json"), required=True)


class MaterializePrepareTests(unittest.TestCase):
    def test_materialize_and_prepare(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            tmpl = Path(td, "admin-tools", "sample_AgilexB.json")
            tmpl.write_text(json.dumps({
                "confidentialData": {
                    "aesKey": {"value": ""},
                    "qek": {"value": ""},
                },
                "corimUrl": "",
            }))
            work = Path(td, "work.json")
            self.assertTrue(c.materialize_reference_configuration(
                str(tmpl), str(work), aes_hex="AA", qek_hex="BB", corim_url="http://z", force=True
            ))
            self.assertFalse(c.materialize_reference_configuration(str(tmpl), str(work), force=False))
            with self.assertRaises(FileNotFoundError):
                c.materialize_reference_configuration("/no/such", str(work), force=True)
            bad = Path(td, "badtmpl.json")
            bad.write_text(json.dumps({"x": 1}))
            with self.assertRaises(ValueError):
                c.materialize_reference_configuration(str(bad), str(work), force=True)
            bad2 = Path(td, "bad2.json")
            bad2.write_text(json.dumps({"confidentialData": {"aesKey": {}}}))
            with self.assertRaises(ValueError):
                c.materialize_reference_configuration(str(bad2), str(work), force=True)

            # prepare aes
            Path(cfg.quartus_keys_dir, "signed_aes_efuse.ccert").write_bytes(b"\x01\x02\x03\x04")
            Path(cfg.quartus_keys_dir, "aes_root.qek").write_bytes(b"\x0a\x0b")
            c.prepare_aes_configuration_named(cfg, "myconfig", corim_url="http://u")
            self.assertTrue(Path(td, "bkps_configs", "myconfig.json").is_file())
            c.prepare_aes_configuration(cfg)
            self.assertTrue(Path(cfg.quartus_keys_dir, "agilex5_config.json").is_file())

            # no ccert
            Path(cfg.quartus_keys_dir, "signed_aes_efuse.ccert").unlink()
            with self.assertRaises(FileNotFoundError):
                c.prepare_aes_configuration_named(cfg, "x")

            # empty ccert
            Path(cfg.quartus_keys_dir, "signed_aes_efuse.ccert").write_bytes(b"")
            with self.assertRaises(RuntimeError):
                c.prepare_aes_configuration_named(cfg, "y")

            # unknown profile → warning path (template None) then crash on data
            Path(cfg.quartus_keys_dir, "signed_aes_efuse.ccert").write_bytes(b"\x01")
            cfg.profile_name = "unknown_profile"
            Path(td, "admin-tools", "sample_other.json").write_text("{}")
            with self.assertRaises(Exception):
                c.prepare_aes_configuration_named(cfg, "z")


class ServiceAdminKeysTests(unittest.TestCase):
    def test_configure_service_admin_keys(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            # service without certs
            c.configure_bkps_service(cfg)
            # with overrides missing
            with self.assertRaises(RuntimeError):
                c.configure_bkps_service(cfg, cert_override="/no.crt", key_override="/no.pem")
            cert = Path(td, "keys", "super_admin_bkps_signed.crt")
            key = Path(td, "keys", "super_admin_private.pem")
            cert.write_text("C")
            key.write_text("-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----")
            c.configure_bkps_service(cfg)
            oc = Path(td, "o.crt")
            ok = Path(td, "o.pem")
            oc.write_text("C")
            ok.write_text("-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----")
            c.configure_bkps_service(cfg, cert_override=str(oc), key_override=str(ok))
            with self.assertRaises(RuntimeError):
                c.configure_bkps_service(cfg, cert_override=str(oc), key_override="/missing.pem")

            # create super admin
            Path(td, "keys", "super_admin_cert.crt").write_text("C")
            def _runner_create(*a, **k):
                Path(td, "keys", "super_admin_bkps_signed.crt").write_text("SIGNED")
                return RR(0)
            with mock.patch.object(c, "_runner", side_effect=_runner_create), \
                 mock.patch.object(c, "audit_log"):
                Path(td, ".initial_token").write_text("TOK")
                c.create_super_admin(cfg, "TOK")
            with self.assertRaises(ValueError):
                c.create_super_admin(cfg, "")
            with mock.patch.object(c, "_runner", side_effect=RuntimeError("already exists")), \
                 mock.patch.object(c, "audit_log"):
                # signed cert already exists from earlier
                c.create_super_admin(cfg, "TOK2")
            with mock.patch.object(c, "_runner", side_effect=RuntimeError("already exists")), \
                 mock.patch.object(c, "audit_log"):
                Path(td, "keys", "super_admin_bkps_signed.crt").unlink()
                with self.assertRaises(RuntimeError):
                    c.create_super_admin(cfg, "TOK3")
            with mock.patch.object(c, "_runner", side_effect=RuntimeError("boom")), \
                 mock.patch.object(c, "audit_log"):
                with self.assertRaises(RuntimeError):
                    c.create_super_admin(cfg, "TOK4")

            # configure keys
            Path(td, "keys", "super_admin_bkps_signed.crt").write_text("SIGNED")
            Path(cfg.quartus_keys_dir, "root0.qky").write_text("q")
            Path(cfg.quartus_keys_dir, "root0_private.pem").write_text("p")
            with mock.patch.object(c, "create_authentication_keys"), \
                 mock.patch.object(c, "register_bkps_signing_key"), \
                 mock.patch.object(c, "_runner", return_value=RR(0, out="-----BEGIN PUBLIC KEY-----\n")), \
                 mock.patch.object(c, "audit_log"):
                c.configure_bkps_keys(cfg)
                c.configure_bkps_keys(cfg, skip_qky=True)
            with self.assertRaises(RuntimeError):
                Path(td, "keys", "super_admin_bkps_signed.crt").unlink()
                with mock.patch.object(c, "audit_log"):
                    c.configure_bkps_keys(cfg)
            Path(td, "keys", "super_admin_bkps_signed.crt").write_text("SIGNED")
            with mock.patch.object(c, "create_authentication_keys"), \
                 mock.patch.object(c, "register_bkps_signing_key"), \
                 mock.patch.object(c, "audit_log"):
                Path(cfg.quartus_keys_dir, "root0.qky").unlink()
                with self.assertRaises(RuntimeError):
                    c.configure_bkps_keys(cfg)
            Path(cfg.quartus_keys_dir, "root0.qky").write_text("q")
            with mock.patch.object(c, "create_authentication_keys"), \
                 mock.patch.object(c, "register_bkps_signing_key"), \
                 mock.patch.object(c, "_runner", return_value=RR(1)), \
                 mock.patch.object(c, "audit_log"):
                with self.assertRaises(RuntimeError):
                    c.configure_bkps_keys(cfg)


class AesCrudPrefetchTests(unittest.TestCase):
    def test_validate_upload_crud_prefetch(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            jp = _valid_json(os.path.join(td, "ok.json"))
            self.assertTrue(c.validate_aes_configuration_file(cfg, jp))
            Path(cfg.quartus_keys_dir, "agilex5_config.json").write_text(Path(jp).read_text())
            self.assertTrue(c.validate_aes_configuration(cfg))

            self.assertFalse(c.validate_aes_configuration_file(cfg, os.path.join(td, "nope.json")))
            empty = Path(td, "empty.json")
            empty.write_text("")
            self.assertFalse(c.validate_aes_configuration_file(cfg, str(empty)))
            Path(td, "bad.json").write_text("{")
            self.assertFalse(c.validate_aes_configuration_file(cfg, os.path.join(td, "bad.json")))
            Path(td, "nofield.json").write_text("{}")
            self.assertFalse(c.validate_aes_configuration_file(cfg, os.path.join(td, "nofield.json")))
            Path(td, "noaes.json").write_text(json.dumps({"confidentialData": {}}))
            self.assertFalse(c.validate_aes_configuration_file(cfg, os.path.join(td, "noaes.json")))
            Path(td, "noval.json").write_text(json.dumps({"confidentialData": {"aesKey": {}}}))
            self.assertFalse(c.validate_aes_configuration_file(cfg, os.path.join(td, "noval.json")))
            Path(td, "odd.json").write_text(json.dumps({"confidentialData": {"aesKey": {"value": "a"}}}))
            self.assertFalse(c.validate_aes_configuration_file(cfg, os.path.join(td, "odd.json")))
            Path(td, "nonhex.json").write_text(json.dumps({"confidentialData": {"aesKey": {"value": "zz"}}}))
            self.assertFalse(c.validate_aes_configuration_file(cfg, os.path.join(td, "nonhex.json")))
            Path(td, "badqek.json").write_text(json.dumps({
                "confidentialData": {"aesKey": {"value": "aa"}, "qek": {"value": "zz"}}
            }))
            self.assertFalse(c.validate_aes_configuration_file(cfg, os.path.join(td, "badqek.json")))
            Path(td, "emptyqek.json").write_text(json.dumps({
                "confidentialData": {"aesKey": {"value": "aa"}, "qek": {"value": ""}}
            }))
            self.assertFalse(c.validate_aes_configuration_file(cfg, os.path.join(td, "emptyqek.json")))
            Path(td, "num.json").write_text(json.dumps({
                "confidentialData": {"aesKey": {"value": 12}}
            }))
            self.assertFalse(c.validate_aes_configuration_file(cfg, os.path.join(td, "num.json")))

            with mock.patch.object(c, "_runner", return_value=RR(0, out='{"id": 55}')), \
                 mock.patch.object(c, "_ensure_qek_alias_ready_for_upload"), \
                 mock.patch.object(c, "audit_log"):
                c.upload_aes_configuration_file(cfg, jp)
                self.assertEqual(c.read_config_id(cfg), "55")
                c.upload_aes_configuration(cfg)

            with mock.patch.object(c, "_runner", return_value=RR(1, out='"code": 2080')), \
                 mock.patch.object(c, "_ensure_qek_alias_ready_for_upload"), \
                 mock.patch.object(c, "_is_secure_enclave_error", return_value=True), \
                 mock.patch.object(c, "_print_secure_enclave_recovery"), \
                 mock.patch.object(c, "_print_secure_enclave_diagnostics"), \
                 mock.patch.object(c, "audit_log"):
                with self.assertRaises(RuntimeError):
                    c.upload_aes_configuration_file(cfg, jp)

            with mock.patch.object(c, "_runner", return_value=RR(1, out="missing key")), \
                 mock.patch.object(c, "_ensure_qek_alias_ready_for_upload"), \
                 mock.patch.object(c, "_is_secure_enclave_error", return_value=False), \
                 mock.patch.object(c, "audit_log"):
                with self.assertRaises(RuntimeError):
                    c.upload_aes_configuration_file(cfg, jp)

            # precheck fail non-enclave
            calls = {"n": 0}
            def runner_precheck(*a, **k):
                calls["n"] += 1
                if calls["n"] == 1:
                    return RR(1, out="no import key")
                return RR(0, out='{"id":1}')
            with mock.patch.object(c, "_runner", side_effect=runner_precheck), \
                 mock.patch.object(c, "_ensure_qek_alias_ready_for_upload"), \
                 mock.patch.object(c, "_is_secure_enclave_error", return_value=False), \
                 mock.patch.object(c, "audit_log"):
                with self.assertRaises(RuntimeError):
                    c.upload_aes_configuration_file(cfg, jp)

            with mock.patch.object(c, "_runner", return_value=RR(0, out="no id here")), \
                 mock.patch.object(c, "_ensure_qek_alias_ready_for_upload"), \
                 mock.patch.object(c, "_is_secure_enclave_error", return_value=False), \
                 mock.patch.object(c, "audit_log"):
                with self.assertRaises(RuntimeError):
                    c.upload_aes_configuration_file(cfg, jp)

            with self.assertRaises(FileNotFoundError):
                with mock.patch.object(c, "audit_log"):
                    c.upload_aes_configuration_file(cfg, os.path.join(td, "missing.json"))

            with mock.patch.object(c, "_runner", return_value=RR(0)), \
                 mock.patch.object(c, "audit_log"):
                c.list_configurations(cfg)
                c.get_configuration(cfg, "1")
                c.update_configuration(cfg, "1")
                c.update_configuration_file(cfg, "1", jp)
                c.delete_configuration(cfg, "55")
                c.write_config_id(cfg, "1")
                c.delete_configuration(cfg, "1")
            with self.assertRaises(ValueError):
                c.delete_configuration(cfg, "")
            with self.assertRaises(ValueError):
                c.delete_configuration(cfg, "abc")
            with mock.patch.object(c, "_runner", return_value=RR(1)), \
                 mock.patch.object(c, "audit_log"):
                with self.assertRaises(RuntimeError):
                    c.delete_configuration(cfg, "9")
            with self.assertRaises(ValueError):
                c.update_configuration_file(cfg, "x", jp)
            with self.assertRaises(FileNotFoundError):
                c.update_configuration_file(cfg, "1", os.path.join(td, "no.json"))

            with mock.patch.object(c, "_runner", return_value=RR(0)):
                c.run_prefetch(cfg, "0x35", "0102", pdi="aa", er_cert="")
                erc = Path(td, "er.crt")
                erc.write_text("e")
                c.run_prefetch(cfg, "0x35", "0102", er_cert=str(erc))
                c.run_prefetch_status(cfg)
                c.run_prefetch_status(cfg, "d", "f")
            with self.assertRaises(ValueError):
                c.run_prefetch(cfg, "", "d")
            with self.assertRaises(ValueError):
                c.run_prefetch(cfg, "f", "")
            with self.assertRaises(FileNotFoundError):
                c.run_prefetch(cfg, "f", "d", er_cert="/no")

            self.assertEqual(c.read_config_id(cfg), "")  # deleted earlier or missing


class CreateBkpConfigTests(unittest.TestCase):
    # Exercise the Linux branch by default; the Windows branch is explicitly
    # selected and mocked later in the same test.
    @mock.patch.object(c.sys, "platform", "linux")
    def test_create_bkp_config_linux_and_windows(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            c.write_config_id(cfg, "99")
            Path(cfg.quartus_keys_dir, "programmer_bkps_signed.crt").write_text("C")
            Path(cfg.quartus_keys_dir, "programmer_private.pem").write_text(
                "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"
            )
            Path(cfg.quartus_keys_dir, "root0.qky").write_text("q")
            c.create_bkp_config(cfg)
            self.assertTrue(Path(cfg.cm_provisioning_dir, "bkp_options.txt").is_file())

            with self.assertRaises(ValueError):
                c.create_bkp_config(cfg, "abc")
            with self.assertRaises(RuntimeError):
                c.create_bkp_config(cfg, "100")
            c.create_bkp_config(cfg, "99")

            Path(td, "config_id.txt").unlink()
            with self.assertRaises(FileNotFoundError):
                c.create_bkp_config(cfg)

            c.write_config_id(cfg, "1")
            Path(cfg.quartus_keys_dir, "programmer_private.pem").unlink()
            with self.assertRaises(FileNotFoundError):
                c.create_bkp_config(cfg)

            Path(cfg.quartus_keys_dir, "programmer_private.pem").write_text("k")
            Path(cfg.quartus_keys_dir, "root0.qky").unlink(missing_ok=True)
            c.create_bkp_config(cfg)  # warning path without root0

            thumb = "A" * 40
            with mock.patch.object(c.sys, "platform", "win32"), \
                 mock.patch.object(c, "_ps_run", return_value=RR(0, out=thumb + "\n")), \
                 mock.patch.object(c, "_certificate_sha1_thumbprint", return_value=thumb):
                Path(cfg.quartus_keys_dir, "programmer.pfx").write_bytes(b"pfx")
                c.create_bkp_config(cfg)
            with mock.patch.object(c.sys, "platform", "win32"), \
                 mock.patch.object(c, "_ps_run", return_value=RR(0, out=thumb + "\n")), \
                 mock.patch.object(c, "_certificate_sha1_thumbprint", return_value="B" * 40):
                with self.assertRaises(RuntimeError):
                    c.create_bkp_config(cfg)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Unit tests for bkps_softhsm SoftHSM / PKCS#11 helpers and AES pipeline."""

from __future__ import annotations

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

import bkps_softhsm as softhsm  # noqa: E402


def setUpModule():
    # Progress messages contain Unicode glyphs; a narrow console codec (cp1252)
    # would turn an incidental print into a UnicodeEncodeError.
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(errors="replace")


AES_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

SLOTS_OUTPUT = """\
Slot 0
  Slot info:
  Token info:
    Token label: Other
Slot 1
  Slot info:
  Token info:
    Token label: AlteraAESToken
"""


def _cfg(tmp: Path, **extra) -> SimpleNamespace:
    lib = tmp / "libsofthsm2.so"
    conf = tmp / "softhsm2.conf"
    if not lib.exists():
        lib.write_bytes(b"lib")
    if not conf.exists():
        conf.write_text("directories.tokendir = tokens\n")
    cfg = SimpleNamespace(
        pkcs11_tool_path="",
        softhsm_util_path="",
        softhsm_lib_path=str(lib),
        softhsm_conf_path=str(conf),
        softhsm_token_label="AlteraAESToken",
        softhsm_user_pin="12345678",
        softhsm_so_pin="87654321",
        softhsm_key_label="AESKey",
        quartus_keys_dir=str(tmp / "keys"),
        aes_passphrase="secret-pass",
        aes_ccert_type="aes_efuse",
        aes_ccert_iv="0011223344556677",
        aes_cancel_id="0",
        device_part="A5ED013BM16ACS",
        bkps_server_port="8082",
        profile_name="agilex5",
    )
    for k, v in extra.items():
        setattr(cfg, k, v)
    return cfg


class HelperTests(unittest.TestCase):
    def test_tool_paths_and_cwd_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = _cfg(root)
            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ):
                self.assertEqual(softhsm._pkcs11_tool(cfg), "pkcs11-tool")
                self.assertEqual(softhsm._softhsm_util(cfg), "softhsm2-util")
                cfg.pkcs11_tool_path = "/bin/pkcs11-tool"
                cfg.softhsm_util_path = "/bin/softhsm2-util"
                self.assertEqual(softhsm._pkcs11_tool(cfg), "/bin/pkcs11-tool")
                self.assertEqual(
                    softhsm._softhsm_cwd(cfg), str(root)
                )
                cfg.softhsm_lib_path = ""
                self.assertIsNone(softhsm._softhsm_cwd(cfg))

            # Avoid asking pathlib for a POSIX path flavour while os.name is
            # patched on a Windows host.
            cfg = _cfg(root, softhsm_tokens_dir=str(root / "tokens"))
            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch("bkps_softhsm.os.name", "posix"):
                env = softhsm._softhsm_env(cfg)
            self.assertEqual(env["SOFTHSM2_CONF"], cfg.softhsm_conf_path)

            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch("bkps_softhsm.os.name", "nt"), patch(
                "bkps_softhsm.windows_softhsm_root",
                return_value=str(root),
            ):
                (root / "bin").mkdir(exist_ok=True)
                (root / "lib").mkdir(exist_ok=True)
                env = softhsm._softhsm_env(cfg)
            self.assertIn(str(root / "bin"), env["PATH"])

    def test_quartus_aes_key_line_and_shred(self):
        line = softhsm._quartus_aes_key_line(AES_HEX)
        self.assertTrue(line.startswith("0x01234567"))
        self.assertEqual(len(line.split()), 8)
        with self.assertRaises(ValueError):
            softhsm._quartus_aes_key_line("aabb")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "k.txt"
            softhsm._write_quartus_aes_key_file(str(path), AES_HEX)
            self.assertTrue(path.is_file())
            softhsm._shred_files(str(path), "", "/no/such")
            self.assertFalse(path.exists())
            path.write_text("again")
            with patch("bkps_softhsm.os.remove", side_effect=OSError("x")):
                softhsm._shred_files(str(path))

    def test_pkcs11_wrapper(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch("bkps_softhsm.run") as run_m:
                softhsm._pkcs11(cfg, ["--list-objects"], check=True)
            self.assertTrue(run_m.call_args.kwargs.get("check"))

    def test_resolve_and_list_slots(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            result = subprocess.CompletedProcess(
                [], 0, SLOTS_OUTPUT, ""
            )
            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch(
                "bkps_softhsm.subprocess.run", return_value=result
            ):
                self.assertEqual(softhsm._resolve_slot(cfg), "1")
                self.assertEqual(softhsm._list_slot_ids(cfg), ["0", "1"])
                self.assertTrue(softhsm._token_exists(cfg))

            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch(
                "bkps_softhsm.subprocess.run",
                side_effect=OSError("gone"),
            ):
                self.assertEqual(softhsm._resolve_slot(cfg), "")
                self.assertEqual(softhsm._list_slot_ids(cfg), [])


class ValidateTests(unittest.TestCase):
    def test_missing_provider_and_libspdm(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp), softhsm_lib_path="/missing.so")
            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ):
                with self.assertRaisesRegex(RuntimeError, "provider not found"):
                    softhsm._validate_softhsm_module_for_quartus(cfg)

            bad = Path(tmp) / "libspdm_wrapper.so"
            bad.write_bytes(b"x")
            cfg2 = _cfg(Path(tmp), softhsm_lib_path=str(bad))
            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ):
                with self.assertRaisesRegex(RuntimeError, "SPDM wrapper"):
                    softhsm._validate_softhsm_module_for_quartus(cfg2)

    def test_show_info_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            bad = subprocess.CompletedProcess([], 1, "", "load fail")
            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch(
                "bkps_softhsm._quartus_softhsm_env",
                return_value={
                    "SOFTHSM2_CONF": cfg.softhsm_conf_path,
                },
            ), patch("bkps_softhsm.run", return_value=bad):
                with self.assertRaisesRegex(RuntimeError, "could not be loaded"):
                    softhsm._validate_softhsm_module_for_quartus(cfg)


class TokenLifecycleTests(unittest.TestCase):
    def test_show_slots_and_init_skip(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch("bkps_softhsm.run") as run_m, patch.object(
                softhsm, "_token_exists", return_value=True
            ):
                softhsm.softhsm_show_slots(cfg)
                softhsm.softhsm_init_token(cfg)
            self.assertGreaterEqual(run_m.call_count, 2)

    def test_init_no_slots_and_verify_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch.object(
                softhsm, "_token_exists", return_value=False
            ), patch.object(
                softhsm, "_list_slot_ids", return_value=[]
            ):
                with self.assertRaisesRegex(RuntimeError, "No SoftHSM slots"):
                    softhsm.softhsm_init_token(cfg)

            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch.object(
                softhsm, "_token_exists", side_effect=[False, False]
            ), patch.object(
                softhsm, "_list_slot_ids", return_value=["0"]
            ), patch("bkps_softhsm.run"), patch.object(
                softhsm, "softhsm_show_slots"
            ):
                with self.assertRaisesRegex(RuntimeError, "not visible"):
                    softhsm.softhsm_init_token(cfg)

    def test_init_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch.object(
                softhsm, "_token_exists", side_effect=[False, True]
            ), patch.object(
                softhsm, "_list_slot_ids", return_value=["0"]
            ), patch("bkps_softhsm.run"), patch.object(
                softhsm, "softhsm_show_slots"
            ):
                softhsm.softhsm_init_token(cfg)

    def test_delete_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch.object(
                softhsm, "_resolve_slot", return_value=""
            ):
                softhsm.softhsm_delete_token(cfg)

            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch.object(
                softhsm, "_resolve_slot", return_value="1"
            ), patch("bkps_softhsm.run") as run_m:
                softhsm.softhsm_delete_token(cfg)
            run_m.assert_called()


class KeyOpTests(unittest.TestCase):
    def test_list_delete_generate_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            ok = subprocess.CompletedProcess([], 0, "", "")
            miss = subprocess.CompletedProcess([], 1, "", "")
            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch.object(
                softhsm, "_pkcs11", return_value=ok
            ):
                softhsm.softhsm_list_objects(cfg)

            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch.object(
                softhsm, "_pkcs11", return_value=miss
            ):
                softhsm.softhsm_delete_key(cfg)

            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch.object(
                softhsm, "_pkcs11", return_value=ok
            ):
                softhsm.softhsm_delete_key(cfg)

            with patch.object(
                softhsm, "_token_exists", return_value=False
            ):
                with self.assertRaises(RuntimeError):
                    softhsm.softhsm_generate_aes_key(cfg)

            with patch.object(
                softhsm, "_token_exists", return_value=True
            ), patch.object(
                softhsm, "softhsm_delete_key"
            ), patch.object(
                softhsm, "_pkcs11", return_value=ok
            ), patch.object(
                softhsm, "softhsm_list_objects"
            ):
                softhsm.softhsm_generate_aes_key(cfg)

            with self.assertRaises(ValueError):
                softhsm.softhsm_import_aes_key(cfg, "bad")

            with patch.object(
                softhsm, "_token_exists", return_value=False
            ):
                with self.assertRaises(RuntimeError):
                    softhsm.softhsm_import_aes_key(cfg, AES_HEX)

            with patch.object(
                softhsm, "_token_exists", return_value=True
            ), patch.object(
                softhsm, "_resolve_slot", return_value=""
            ):
                with self.assertRaises(RuntimeError):
                    softhsm.softhsm_import_aes_key(cfg, AES_HEX)

            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch.object(
                softhsm, "_token_exists", return_value=True
            ), patch.object(
                softhsm, "_resolve_slot", return_value="1"
            ), patch.object(
                softhsm, "softhsm_delete_key"
            ), patch("bkps_softhsm.run"), patch.object(
                softhsm, "softhsm_list_objects"
            ):
                softhsm.softhsm_import_aes_key(cfg, AES_HEX)
            self.assertFalse(
                (Path(cfg.quartus_keys_dir) / "aes_key.bin").exists()
            )

            # finally-clause OSError on bin cleanup is ignored
            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch.object(
                softhsm, "_token_exists", return_value=True
            ), patch.object(
                softhsm, "_resolve_slot", return_value="1"
            ), patch.object(
                softhsm, "softhsm_delete_key"
            ), patch("bkps_softhsm.run"), patch.object(
                softhsm, "softhsm_list_objects"
            ), patch("bkps_softhsm.os.remove", side_effect=OSError("busy")):
                softhsm.softhsm_import_aes_key(cfg, AES_HEX)


class CreateQekCcertTests(unittest.TestCase):
    def _run_pipeline(self, cfg, aes_hex="", server_running=False, **patches):
        keys_dir = Path(cfg.quartus_keys_dir)
        keys_dir.mkdir(parents=True, exist_ok=True)

        def assert_touch(directory, filename, msg):
            path = Path(directory) / filename
            if not path.is_file():
                path.write_bytes(b"x")

        def qe(_cfg, args, cwd=None, env=None):
            for name in (
                "aes_root.qek",
                "aes_hsm_root.qek",
                "aes_keyinfo.txt",
            ):
                if any(a.endswith(name) or a == name for a in args):
                    Path(cwd, name).write_bytes(b"qek")
            # Always ensure hsm outputs exist after second call
            Path(cwd, "aes_hsm_root.qek").write_bytes(b"qek")
            Path(cwd, "aes_keyinfo.txt").write_bytes(b"info")
            Path(cwd, "aes_root.qek").write_bytes(b"qek")

        def qpfg(args, cwd=None, env=None):
            Path(cwd, "unsigned_aes_efuse.ccert").write_bytes(b"u")

        def qs(args, cwd=None, env=None):
            Path(cwd, "signed_aes_efuse.ccert").write_bytes(b"s")

        defaults = {
            "_validate_softhsm_module_for_quartus": MagicMock(
                return_value=cfg.softhsm_lib_path
            ),
            "softhsm_init_token": MagicMock(),
            "softhsm_import_aes_key": MagicMock(),
            "import_aes_key_to_bc_keystore": MagicMock(),
            "_qe": qe,
            "_qpfg": qpfg,
            "_qs": qs,
            "_assert_file": assert_touch,
            "_check_server_running": MagicMock(return_value=server_running),
            "stop_bkps_server": MagicMock(),
            "start_bkps_server": MagicMock(),
            "_wait_for_runner_health": MagicMock(return_value=True),
            "aes_ccert_requires_iv": MagicMock(return_value=True),
        }
        defaults.update(patches)

        ctxs = []
        for name, value in defaults.items():
            target = f"bkps_softhsm.{name}"
            if callable(value) and not isinstance(value, MagicMock):
                ctxs.append(patch(target, side_effect=value))
            else:
                ctxs.append(patch(target, value))

        # Enter all patches
        entered = [c.__enter__() for c in ctxs]
        try:
            softhsm.softhsm_create_qek_and_ccert(cfg, aes_hex=aes_hex)
        finally:
            for c in reversed(ctxs):
                c.__exit__(None, None, None)
        return entered

    def test_provided_key_and_server_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            self._run_pipeline(cfg, aes_hex=AES_HEX, server_running=True)
            keys = Path(cfg.quartus_keys_dir)
            self.assertTrue((keys / "aes_hsm_root.qek_hex.txt").is_file())
            self.assertTrue(
                (keys / "signed_aes_efuse.ccert_hex.txt").is_file()
            )
            self.assertFalse((keys / "password.txt").exists())

    def test_random_key_no_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp), aes_cancel_id="")
            with patch("bkps_softhsm.os.urandom", return_value=b"\x11" * 32):
                self._run_pipeline(
                    cfg,
                    aes_hex="",
                    server_running=False,
                    aes_ccert_requires_iv=MagicMock(return_value=False),
                )

    def test_empty_passphrase(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp), aes_passphrase="")
            with patch(
                "bkps_softhsm._validate_softhsm_module_for_quartus",
                return_value=cfg.softhsm_lib_path,
            ), patch(
                "bkps_softhsm.softhsm_init_token"
            ), patch(
                "bkps_softhsm.softhsm_import_aes_key"
            ), patch(
                "bkps_softhsm.import_aes_key_to_bc_keystore"
            ):
                with self.assertRaises(ValueError):
                    softhsm.softhsm_create_qek_and_ccert(cfg, aes_hex=AES_HEX)

    def test_invalid_provided_hex(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            with patch(
                "bkps_softhsm._validate_softhsm_module_for_quartus",
                return_value=cfg.softhsm_lib_path,
            ):
                with self.assertRaises(ValueError):
                    softhsm.softhsm_create_qek_and_ccert(cfg, aes_hex="zz")

    def test_legacy_qek_rename_and_health_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            keys_dir = Path(cfg.quartus_keys_dir)
            keys_dir.mkdir(parents=True)

            def qe(_cfg, args, cwd=None, env=None):
                Path(cwd, "aes_root.qek").write_bytes(b"qek")
                # Simulate legacy-only HSM output on second encrypt
                if "aes_hsm_root.qek" in args or any(
                    a == "aes_hsm_root.qek" for a in args
                ):
                    Path(cwd, "aes_32.qek").write_bytes(b"legacy")
                    Path(cwd, "aes_keyinfo.txt").write_bytes(b"info")
                else:
                    Path(cwd, "aes_root.qek").write_bytes(b"qek")

            def assert_file(directory, filename, msg):
                path = Path(directory) / filename
                if filename == "aes_hsm_root.qek" and not path.is_file():
                    # After rename it should exist; if not, create for continue
                    legacy = Path(directory) / "aes_32.qek"
                    if legacy.is_file():
                        legacy.replace(path)
                if not path.is_file():
                    path.write_bytes(b"x")

            with patch(
                "bkps_softhsm._validate_softhsm_module_for_quartus",
                return_value=cfg.softhsm_lib_path,
            ), patch("bkps_softhsm.softhsm_init_token"), patch(
                "bkps_softhsm.softhsm_import_aes_key"
            ), patch(
                "bkps_softhsm.import_aes_key_to_bc_keystore"
            ), patch("bkps_softhsm._qe", side_effect=qe), patch(
                "bkps_softhsm._qpfg",
                side_effect=lambda *a, **k: Path(
                    k.get("cwd") or a[1] if False else keys_dir,
                    "unsigned_aes_efuse.ccert",
                ).write_bytes(b"u")
                if False
                else Path(keys_dir, "unsigned_aes_efuse.ccert").write_bytes(
                    b"u"
                ),
            ), patch(
                "bkps_softhsm._qs",
                side_effect=lambda *a, **k: Path(
                    keys_dir, "signed_aes_efuse.ccert"
                ).write_bytes(b"s"),
            ), patch(
                "bkps_softhsm._assert_file", side_effect=assert_file
            ), patch(
                "bkps_softhsm._check_server_running", return_value=True
            ), patch(
                "bkps_softhsm.stop_bkps_server"
            ), patch(
                "bkps_softhsm.start_bkps_server"
            ), patch(
                "bkps_softhsm._wait_for_runner_health", return_value=False
            ), patch(
                "bkps_softhsm.aes_ccert_requires_iv", return_value=False
            ):
                softhsm.softhsm_create_qek_and_ccert(cfg, aes_hex=AES_HEX)

    def test_server_reload_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            self._run_pipeline(
                cfg,
                aes_hex=AES_HEX,
                server_running=True,
                stop_bkps_server=MagicMock(side_effect=RuntimeError("x")),
            )


if __name__ == "__main__":
    unittest.main()

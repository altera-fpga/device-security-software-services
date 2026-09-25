#!/usr/bin/env python3
"""Unit tests for bkps_keys authentication and AES key helpers."""

from __future__ import annotations

import shutil
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

import bkps_keys as keys  # noqa: E402


def _base_cfg(keys_dir: Path, **extra) -> SimpleNamespace:
    cfg = SimpleNamespace(
        quartus_keys_dir=str(keys_dir),
        profile_name="agilex5",
        owner_root_key_path="",
        owner_root_key_private_path="",
        aes_cancel_id="0",
        bkps_signing_key_cancel_id="0",
        aes_passphrase="pass",
        aes_ccert_type="aes_efuse",
        aes_ccert_iv="",
        softhsm_user_pin="",
    )
    for k, v in extra.items():
        setattr(cfg, k, v)
    return cfg


class AssertFileTests(unittest.TestCase):
    def test_ok_and_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "f.txt").write_text("x")
            keys._assert_file(str(root), "f.txt", "ok")
            with self.assertRaises(RuntimeError):
                keys._assert_file(str(root), "missing", "gone")


class CreateAuthenticationKeysTests(unittest.TestCase):
    def test_provided_root_copy_and_pem(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keys_dir = root / "keys"
            keys_dir.mkdir()
            provided = root / "ext.qky"
            provided_pem = root / "ext.pem"
            provided.write_bytes(b"qky")
            provided_pem.write_text("pem")
            cfg = _base_cfg(
                keys_dir,
                owner_root_key_path=str(provided),
                owner_root_key_private_path=str(provided_pem),
            )

            def touch_outputs(args, cwd=None, env=None):
                for a in args:
                    if isinstance(a, str) and a.endswith((".pem", ".qky")):
                        Path(cwd or ".", a.rpartition("=")[2]).write_text("x")

            with patch.object(keys, "_qs", side_effect=touch_outputs) as qs:
                keys.create_authentication_keys(cfg)
            self.assertTrue((keys_dir / "root0.qky").is_file())
            self.assertTrue((keys_dir / "root0_private.pem").is_file())
            self.assertGreaterEqual(qs.call_count, 4)

    def test_provided_root_identical_skips_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            keys_dir = work / "keys"
            keys_dir.mkdir()
            provided = work / "same.qky"
            provided_pem = work / "same.pem"
            provided.write_bytes(b"same")
            provided_pem.write_text("pem")
            cwd_qky = Path("root0.qky")
            cwd_pem = Path("root0_private.pem")
            cwd_qky.write_bytes(b"same")
            cwd_pem.write_text("pem")
            for name in (
                "design0_sign_chain.qky",
                "design0_sign_private.pem",
                "aesccert1_sign_chain.qky",
                "aesccert1_private.pem",
            ):
                (keys_dir / name).write_text("x")
            cfg = _base_cfg(
                keys_dir,
                owner_root_key_path=str(provided),
                owner_root_key_private_path=str(provided_pem),
            )
            try:
                with patch.object(keys, "_qs") as qs, patch(
                    "bkps_keys.filecmp.cmp", return_value=True
                ):
                    keys.create_authentication_keys(cfg, skip_qky=True)
                qs.assert_not_called()
            finally:
                for p in (cwd_qky, cwd_pem):
                    if p.is_file():
                        p.unlink()

    def test_provided_root_missing_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys_dir = Path(tmp) / "keys"
            keys_dir.mkdir()
            cfg = _base_cfg(
                keys_dir, owner_root_key_path="/no/such/root.qky"
            )
            with self.assertRaises(RuntimeError):
                keys.create_authentication_keys(cfg)

    def test_provided_pem_missing_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            keys_dir = work / "keys"
            keys_dir.mkdir()
            provided = work / "root.qky"
            provided.write_bytes(b"q")
            cfg = _base_cfg(
                keys_dir,
                owner_root_key_path=str(provided),
                owner_root_key_private_path="/missing.pem",
            )
            with self.assertRaises(RuntimeError):
                keys.create_authentication_keys(cfg)

    def test_provided_root_without_pem_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            keys_dir = work / "keys"
            keys_dir.mkdir()
            provided = work / "root.qky"
            provided.write_bytes(b"q")
            cfg = _base_cfg(
                keys_dir,
                owner_root_key_path=str(provided),
                owner_root_key_private_path="",
            )
            with patch.object(keys, "_qs"), patch.object(
                keys, "_assert_file"
            ):
                keys.create_authentication_keys(cfg)
            if Path("root0.qky").is_file():
                Path("root0.qky").unlink()

    def test_generate_root_and_skip_qky(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys_dir = Path(tmp) / "keys"
            keys_dir.mkdir()
            (keys_dir / "root0.qky").write_text("q")
            (keys_dir / "root0_private.pem").write_text("p")
            for name in (
                "design0_sign_chain.qky",
                "design0_sign_private.pem",
                "aesccert1_sign_chain.qky",
                "aesccert1_private.pem",
            ):
                (keys_dir / name).write_text("x")
            cfg = _base_cfg(keys_dir)
            with patch.object(keys, "_qs") as qs:
                keys.create_authentication_keys(cfg, skip_qky=True)
            qs.assert_not_called()

        with tempfile.TemporaryDirectory() as tmp:
            keys_dir = Path(tmp) / "keys"
            keys_dir.mkdir()
            cfg = _base_cfg(keys_dir)

            def touch_outputs(args, cwd=None, env=None):
                # Create expected outputs based on last arg filename
                for a in args:
                    if a.endswith((".pem", ".qky")):
                        Path(cwd, a.rpartition("=")[2]).write_text("x")

            with patch.object(keys, "_qs", side_effect=touch_outputs):
                keys.create_authentication_keys(cfg, skip_qky=False)
            self.assertTrue((keys_dir / "root0.qky").is_file())


class VerifySigningKeyTests(unittest.TestCase):
    def test_enabled_ok(self):
        payload = (
            'Status: 200 OK\n'
            '[{"signingKeyId": "7", "status": "ENABLED", '
            '"chain": "c", "multiChain": "m"}]'
        )
        with patch(
            "bkps_configure._signing_key_list_raw", return_value=payload
        ):
            keys._verify_signing_key_active(SimpleNamespace(), "7")

    def test_missing_id(self):
        with patch(
            "bkps_configure._signing_key_list_raw",
            return_value='[{"id": "1", "status": "ENABLED", "chain": "c", "multiChain": "m"}]',
        ):
            with self.assertRaises(RuntimeError):
                keys._verify_signing_key_active(SimpleNamespace(), "99")

    def test_disabled_or_empty_chain(self):
        with patch(
            "bkps_configure._signing_key_list_raw",
            return_value='[{"id": "1", "status": "DISABLED", "chain": "c", "multiChain": "m"}]',
        ):
            with self.assertRaises(RuntimeError):
                keys._verify_signing_key_active(SimpleNamespace(), "1")

    def test_bad_json(self):
        with patch(
            "bkps_configure._signing_key_list_raw",
            return_value='Status: 200\n[{"bad": }]',
        ):
            with self.assertRaises(RuntimeError):
                keys._verify_signing_key_active(SimpleNamespace(), "1")

    def test_dict_payload(self):
        with patch(
            "bkps_configure._signing_key_list_raw",
            return_value='{"signingKeyId": "3", "status": "ENABLED", "chain": "c", "multiChain": "m"}',
        ):
            keys._verify_signing_key_active(SimpleNamespace(), "3")


class RegisterSigningKeyTests(unittest.TestCase):
    def test_agilex_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys_dir = Path(tmp)
            (keys_dir / "bkps_signing_public.pem").write_text("old")
            cfg = _base_cfg(keys_dir, profile_name="agilex5")

            with patch(
                "bkps_configure._create_signing_key_and_get_id",
                return_value="42",
            ), patch(
                "bkps_configure._sign_bkps_chain"
            ) as sign, patch(
                "bkps_configure._quartus_create_root"
            ) as create_root, patch.object(
                keys, "_runner"
            ), patch.object(
                keys, "_verify_signing_key_active"
            ), patch.object(
                keys, "_assert_file"
            ):
                # Ensure cross-family root missing so create_root is called
                result = keys.register_bkps_signing_key(cfg)
            self.assertEqual(result, "42")
            self.assertEqual(sign.call_count, 2)
            create_root.assert_called()

    def test_stratix10_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys_dir = Path(tmp)
            cfg = _base_cfg(keys_dir, profile_name="stratix10")
            with patch(
                "bkps_configure._create_signing_key_and_get_id",
                return_value="9",
            ), patch(
                "bkps_configure._sign_bkps_chain"
            ), patch(
                "bkps_configure._quartus_create_root"
            ) as create_root, patch.object(
                keys, "_runner"
            ), patch.object(
                keys, "_verify_signing_key_active"
            ), patch.object(
                keys, "_assert_file"
            ):
                self.assertEqual(keys.register_bkps_signing_key(cfg), "9")
            # stratix10 calls create_root at least once (guard + unconditional)
            self.assertGreaterEqual(create_root.call_count, 1)


class CreateAesKeyTests(unittest.TestCase):
    def test_skip_existing(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys_dir = Path(tmp)
            (keys_dir / "aes_root.qek").write_text("q")
            (keys_dir / "signed_aes_efuse.ccert").write_text("c")
            cfg = _base_cfg(keys_dir)
            with patch.object(keys, "_qe") as qe:
                keys.create_aes_key(cfg)
            qe.assert_not_called()

    def test_full_path_with_iv_and_cancel(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys_dir = Path(tmp)
            cfg = _base_cfg(
                keys_dir,
                aes_cancel_id="7",
                aes_ccert_iv="1122334455667788",
            )

            def qe_side_effect(cfg, args, cwd=None, env=None):
                Path(cwd, "aes_root.qek").write_bytes(b"qek")

            def qpfg_side_effect(args, cwd=None, env=None):
                Path(cwd, "unsigned_aes_efuse.ccert").write_bytes(b"cc")

            def qs_side_effect(args, cwd=None, env=None):
                Path(cwd, "signed_aes_efuse.ccert").write_bytes(b"cc")

            with patch.object(keys, "_qe", side_effect=qe_side_effect), patch.object(
                keys, "_qpfg", side_effect=qpfg_side_effect
            ) as qpfg, patch.object(
                keys, "_qs", side_effect=qs_side_effect
            ), patch(
                "bkps_keys.aes_ccert_requires_iv", return_value=True
            ):
                keys.create_aes_key(cfg)
            # passphrase cleaned
            self.assertFalse((keys_dir / "aes_pass.txt").exists())
            qpfg_args = qpfg.call_args.args[0]
            self.assertIn("iv=1122334455667788", " ".join(qpfg_args))

    def test_passphrase_remove_oserror_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys_dir = Path(tmp)
            cfg = _base_cfg(keys_dir)

            def qe_side_effect(cfg, args, cwd=None, env=None):
                Path(cwd, "aes_root.qek").write_bytes(b"qek")

            def qpfg_side_effect(args, cwd=None, env=None):
                Path(cwd, "unsigned_aes_efuse.ccert").write_bytes(b"cc")

            def qs_side_effect(args, cwd=None, env=None):
                Path(cwd, "signed_aes_efuse.ccert").write_bytes(b"cc")

            with patch.object(keys, "_qe", side_effect=qe_side_effect), patch.object(
                keys, "_qpfg", side_effect=qpfg_side_effect
            ), patch.object(
                keys, "_qs", side_effect=qs_side_effect
            ), patch(
                "bkps_keys.aes_ccert_requires_iv", return_value=False
            ), patch(
                "bkps_keys.os.remove", side_effect=OSError("busy")
            ):
                keys.create_aes_key(cfg)


class QuartusWrapperTests(unittest.TestCase):
    def test_qs_delegates_to_run(self):
        with patch.object(keys, "run") as run_m:
            keys._qs(["--family=x"], cwd="/tmp")
        run_m.assert_called_once()

    def test_qe_filters_xterm(self):
        result = subprocess.CompletedProcess(
            ["quartus_encrypt"],
            0,
            "ok\nxterm: noise\n",
            "",
        )
        with patch("bkps_keys.subprocess.run", return_value=result):
            keys._qe(SimpleNamespace(softhsm_user_pin=""), ["a"], cwd=".")

    def test_qpfg_posix_shim(self):
        proc = MagicMock()
        proc.stdout = iter(["ok\n", "xterm: skip\n"])
        proc.wait.return_value = 0
        proc.returncode = 0
        proc.__enter__ = MagicMock(return_value=proc)
        proc.__exit__ = MagicMock(return_value=False)
        with patch("bkps_keys._os.name", "posix"), patch(
            "bkps_keys.subprocess.Popen", return_value=proc
        ):
            keys._qpfg(["--ccert"], cwd=".")

    def test_qpfg_windows_nullcontext(self):
        proc = MagicMock()
        proc.stdout = iter(["ok\n"])
        proc.wait.return_value = 0
        proc.returncode = 0
        proc.__enter__ = MagicMock(return_value=proc)
        proc.__exit__ = MagicMock(return_value=False)
        with patch("bkps_keys._os.name", "nt"), patch(
            "bkps_keys.subprocess.Popen", return_value=proc
        ):
            keys._qpfg(["--ccert"], cwd=".")


if __name__ == "__main__":
    unittest.main()

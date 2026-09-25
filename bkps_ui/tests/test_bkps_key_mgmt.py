"""Unit tests for bkps_key_mgmt."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))

import bkps_key_mgmt as km  # noqa: E402


def _cfg(root: str, yes: bool = True):
    return SimpleNamespace(
        bkps_dir=root,
        quartus_keys_dir=str(Path(root) / "keys"),
        yes=yes,
    )


class KeyMgmtTests(unittest.TestCase):
    def test_list_and_create_wrappers(self):
        cfg = _cfg("/tmp")
        with patch.object(km, "_runner") as runner:
            km.list_signing_keys(cfg)
            km.list_root_signing_keys(cfg)
            km.create_sealing_key(cfg)
            km.list_sealing_keys(cfg)
            km.create_import_key(cfg)
            self.assertGreaterEqual(runner.call_count, 5)

    def test_rotate_sealing_key_confirm_paths(self):
        cfg = _cfg("/tmp", yes=False)
        with patch.object(km, "audit_log"), \
             patch.object(km, "ask_confirmation", return_value=False), \
             patch.object(km, "_runner") as runner:
            km.rotate_sealing_key(cfg)
            runner.assert_not_called()
        with patch.object(km, "audit_log"), \
             patch.object(km, "ask_confirmation", return_value=True), \
             patch.object(km, "_runner", return_value=MagicMock(returncode=0)):
            km.rotate_sealing_key(cfg)
        with patch.object(km, "audit_log"), \
             patch.object(km, "ask_confirmation", return_value=True), \
             patch.object(km, "_runner", return_value=MagicMock(returncode=1)):
            with self.assertRaises(RuntimeError):
                km.rotate_sealing_key(cfg)

    def test_delete_import_key_and_pubkey(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = _cfg(root)
            Path(cfg.quartus_keys_dir).mkdir(parents=True)
            with patch.object(km, "audit_log"), \
                 patch.object(km, "_runner", return_value=MagicMock(returncode=0)):
                km.delete_import_key(cfg)
            with patch.object(km, "audit_log"), \
                 patch.object(km, "_runner", return_value=MagicMock(returncode=1)):
                with self.assertRaises(RuntimeError):
                    km.delete_import_key(cfg)

            with patch.object(
                km, "_runner",
                return_value=MagicMock(returncode=0, stdout="PUBKEY"),
            ):
                km.get_import_pubkey(cfg)
            out = Path(cfg.quartus_keys_dir) / "bkps_import_pubkey.pem"
            self.assertEqual(out.read_text(), "PUBKEY")
            with patch.object(
                km, "_runner",
                return_value=MagicMock(returncode=1, stdout=""),
            ):
                with self.assertRaises(RuntimeError):
                    km.get_import_pubkey(cfg)

    def test_backup_and_restore_sealing_keys(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = _cfg(root)
            keys = Path(cfg.quartus_keys_dir)
            keys.mkdir(parents=True)
            pubkey = keys / "bkps_import_pubkey.pem"
            pubkey.write_text("PUB")

            def _runner(cfg_arg, *args, **kwargs):
                if "backup" in args:
                    for i, a in enumerate(args):
                        if a == "--output":
                            Path(args[i + 1]).write_text("{}")
                    return MagicMock(returncode=0, stdout="")
                return MagicMock(returncode=0, stdout="PUB")

            with patch.object(km, "_runner", side_effect=_runner):
                km.backup_sealing_keys(cfg)

            pubkey.unlink()
            with patch.object(km, "_runner", side_effect=_runner):
                km.backup_sealing_keys(cfg)

            with patch.object(
                km, "_runner",
                return_value=MagicMock(returncode=1, stdout=""),
            ):
                with self.assertRaises(RuntimeError):
                    km.backup_sealing_keys(cfg)

            backup = Path(root) / "sealing_key_backup_test.json"
            backup.write_text("{}")
            with patch.object(km, "audit_log"), \
                 patch.object(km, "ask_confirmation", return_value=False), \
                 patch.object(km, "_runner") as runner:
                km.restore_sealing_keys(cfg, str(backup))
                runner.assert_not_called()
            with patch.object(km, "audit_log"), \
                 patch.object(km, "ask_confirmation", return_value=True), \
                 patch.object(km, "_runner", return_value=MagicMock(returncode=0)):
                km.restore_sealing_keys(cfg, str(backup))
            with patch.object(km, "audit_log"), \
                 patch.object(km, "ask_confirmation", return_value=True), \
                 patch.object(km, "_runner", return_value=MagicMock(returncode=1)):
                with self.assertRaises(RuntimeError):
                    km.restore_sealing_keys(cfg, str(backup))
            with self.assertRaises(ValueError):
                km.restore_sealing_keys(cfg, "")
            with self.assertRaises(FileNotFoundError):
                km.restore_sealing_keys(cfg, str(Path(root) / "missing.json"))

    def test_rotate_context_key(self):
        cfg = _cfg("/tmp")
        with patch.object(km, "audit_log"), \
             patch.object(km, "_runner", return_value=MagicMock(returncode=0)):
            km.rotate_context_key(cfg)
        with patch.object(km, "audit_log"), \
             patch.object(km, "_runner", return_value=MagicMock(returncode=1)):
            with self.assertRaises(RuntimeError):
                km.rotate_context_key(cfg)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Unit tests for bkps_users.py (mocked runner / openssl)."""

from __future__ import annotations

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

import bkps_users as u  # noqa: E402


def RR(code=0, out="", err=""):
    return SimpleNamespace(returncode=code, stdout=out, stderr=err)


def _cfg(root: str) -> SimpleNamespace:
    keys = os.path.join(root, "keys", "quartus")
    os.makedirs(keys, exist_ok=True)
    os.makedirs(os.path.join(root, "admin-tools"), exist_ok=True)
    return SimpleNamespace(
        bkps_dir=root,
        quartus_keys_dir=keys,
        programmer_cert_password="secret",
    )


class ListUsersTests(unittest.TestCase):
    def test_missing_runner_config(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with self.assertRaises(FileNotFoundError):
                u.list_users(cfg)

    def test_list_ok(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            Path(cfg.bkps_dir, "admin-tools", "runner-config.json").write_text("{}")
            with mock.patch.object(u, "_runner") as runner:
                u.list_users(cfg)
            runner.assert_called_once_with(cfg, "user", "list")


class DeleteUserTests(unittest.TestCase):
    def test_prompt_when_empty_and_tty(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with mock.patch.object(u, "audit_log"), mock.patch.object(
                u, "_runner", return_value=RR(0)
            ) as runner, mock.patch.object(
                u.sys.stdin, "isatty", return_value=True
            ), mock.patch("builtins.input", return_value="42"):
                u.delete_user(cfg, "")
            self.assertEqual(runner.call_args_list[-1].args[3:], ("--id", "42"))

    def test_requires_id_non_tty(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with mock.patch.object(u, "audit_log"), mock.patch.object(
                u, "_runner", return_value=RR(0)
            ), mock.patch.object(u.sys.stdin, "isatty", return_value=False):
                with self.assertRaises(ValueError) as ctx:
                    u.delete_user(cfg, "")
                self.assertIn("User ID required", str(ctx.exception))

    def test_non_numeric(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with mock.patch.object(u, "audit_log"):
                with self.assertRaises(ValueError):
                    u.delete_user(cfg, "abc")

    def test_delete_success(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with mock.patch.object(u, "audit_log"), mock.patch.object(
                u, "_runner", return_value=RR(0)
            ):
                u.delete_user(cfg, "7")

    def test_delete_failure(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with mock.patch.object(u, "audit_log"), mock.patch.object(
                u, "_runner", return_value=RR(1, err="nope\nline2")
            ):
                with self.assertRaises(RuntimeError):
                    u.delete_user(cfg, "7")


class CreateUserTests(unittest.TestCase):
    def _patch_common(self, cfg, before='{"id": 1}', after='{"id": 1}\n{"id": 99}', verify='{"id": 99, "roles": ["ROLE_ADMIN"]}'):
        signed = os.path.join(cfg.quartus_keys_dir, "admin_bkps_signed.crt")

        def runner(cfg_arg, *args, **kwargs):
            if args[:2] == ("user", "list"):
                return RR(0, out='ROLE_SUPER_ADMIN present')
            if args[:2] == ("user", "create"):
                Path(signed).write_text("signed")
                return RR(0, out="created")
            if args[:2] == ("user", "role-set"):
                return RR(0)
            return RR(0)

        def capture_retry(cfg_arg, *args, **kwargs):
            stage = kwargs.get("stage", "")
            if "pre-create" in stage:
                return RR(0, out=before)
            if "post-create" in stage:
                return RR(0, out=after)
            if "verify" in stage:
                return RR(0, out=verify)
            return RR(0, out=after)

        return mock.patch.object(u, "_runner", side_effect=runner), mock.patch.object(
            u, "_runner_capture_retry", side_effect=capture_retry
        ), mock.patch.object(u, "run", return_value=RR(0)), mock.patch.object(
            u, "_user_has_role", return_value=True
        )

    def test_create_success_linux(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            p1, p2, p3, p4 = self._patch_common(cfg)
            with p1, p2, p3, p4, mock.patch.object(u.sys, "platform", "linux"):
                u.create_user(cfg, "ROLE_ADMIN")
            self.assertTrue(
                os.path.isfile(os.path.join(cfg.quartus_keys_dir, "openssl.cnf"))
            )

    def test_warns_without_admin_roles(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            signed = os.path.join(cfg.quartus_keys_dir, "admin_bkps_signed.crt")

            def runner(cfg_arg, *args, **kwargs):
                if args[:2] == ("user", "list"):
                    return RR(0, out="no roles here")
                if args[:2] == ("user", "create"):
                    Path(signed).write_text("signed")
                    return RR(0)
                if args[:2] == ("user", "role-set"):
                    return RR(0)
                return RR(0)

            def capture_retry(cfg_arg, *args, **kwargs):
                stage = kwargs.get("stage", "")
                if "pre-create" in stage:
                    return RR(0, out='{"id": 1}')
                if "post-create" in stage:
                    return RR(0, out='{"id": 1}\n{"id": 5}')
                return RR(0, out='{"id": 5}')

            with mock.patch.object(u, "_runner", side_effect=runner), mock.patch.object(
                u, "_runner_capture_retry", side_effect=capture_retry
            ), mock.patch.object(u, "run", return_value=RR(0)), mock.patch.object(
                u, "_user_has_role", return_value=True
            ), mock.patch.object(u.sys, "platform", "linux"), mock.patch.object(
                u, "print_error"
            ) as pe:
                u.create_user(cfg, "ROLE_ADMIN")
            self.assertTrue(any("ROLE_SUPER_ADMIN" in str(c) for c in pe.call_args_list))

    def test_missing_signed_cert(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)

            def runner(cfg_arg, *args, **kwargs):
                if args[:2] == ("user", "list"):
                    return RR(0, out="ROLE_ADMIN")
                if args[:2] == ("user", "create"):
                    return RR(0)
                return RR(0)

            with mock.patch.object(u, "_runner", side_effect=runner), mock.patch.object(
                u, "_runner_capture_retry", return_value=RR(0, out="")
            ), mock.patch.object(u, "run", return_value=RR(0)), mock.patch.object(
                u.sys, "platform", "linux"
            ):
                with self.assertRaises(RuntimeError) as ctx:
                    u.create_user(cfg, "ROLE_ADMIN")
                self.assertIn("signed certificate was not generated", str(ctx.exception))

    def test_windows_pfx_legacy_and_verify(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            signed = os.path.join(cfg.quartus_keys_dir, "admin_bkps_signed.crt")
            calls = {"n": 0}

            def runner(cfg_arg, *args, **kwargs):
                if args[:2] == ("user", "list"):
                    return RR(0, out="ROLE_SUPER_ADMIN")
                if args[:2] == ("user", "create"):
                    Path(signed).write_text("signed")
                    return RR(0)
                if args[:2] == ("user", "role-set"):
                    return RR(0)
                return RR(0)

            def capture_retry(cfg_arg, *args, **kwargs):
                stage = kwargs.get("stage", "")
                if "pre-create" in stage:
                    return RR(0, out='{"id": 1}')
                if "post-create" in stage:
                    return RR(0, out='{"id": 1}\n{"id": 9}')
                return RR(0, out='{"id": 9}')

            def run_side(cmd, **kwargs):
                calls["n"] += 1
                # first openssl req, then pkcs12 -legacy success, then verify success
                return RR(0)

            with mock.patch.object(u, "_runner", side_effect=runner), mock.patch.object(
                u, "_runner_capture_retry", side_effect=capture_retry
            ), mock.patch.object(u, "run", side_effect=run_side), mock.patch.object(
                u, "_user_has_role", return_value=True
            ), mock.patch.object(u.sys, "platform", "win32"):
                u.create_user(cfg, "ROLE_ADMIN")
            self.assertGreaterEqual(calls["n"], 3)

    def test_windows_pfx_fallback_and_verify_fail(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            signed = os.path.join(cfg.quartus_keys_dir, "admin_bkps_signed.crt")

            def runner(cfg_arg, *args, **kwargs):
                if args[:2] == ("user", "list"):
                    return RR(0, out="ROLE_ADMIN")
                if args[:2] == ("user", "create"):
                    Path(signed).write_text("signed")
                    return RR(0)
                return RR(0)

            def capture_retry(cfg_arg, *args, **kwargs):
                stage = kwargs.get("stage", "")
                if "pre-create" in stage:
                    return RR(0, out='{"id": 1}')
                return RR(0, out='{"id": 1}\n{"id": 2}')

            def run_side(cmd, **kwargs):
                cmd_s = " ".join(str(c) for c in cmd)
                if "pkcs12" in cmd_s and "-export" in cmd_s and "-legacy" in cmd_s:
                    return RR(1, err="no legacy")
                if "pkcs12" in cmd_s and "-export" in cmd_s:
                    return RR(0)
                if "pkcs12" in cmd_s and "-noout" in cmd_s:
                    return RR(1, err="bad pass")
                return RR(0)

            with mock.patch.object(u, "_runner", side_effect=runner), mock.patch.object(
                u, "_runner_capture_retry", side_effect=capture_retry
            ), mock.patch.object(u, "run", side_effect=run_side), mock.patch.object(
                u.sys, "platform", "win32"
            ):
                with self.assertRaises(RuntimeError) as ctx:
                    u.create_user(cfg, "ROLE_ADMIN")
                self.assertIn("cannot be read back", str(ctx.exception))

    def test_role_set_failure(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            signed = os.path.join(cfg.quartus_keys_dir, "admin_bkps_signed.crt")

            def runner(cfg_arg, *args, **kwargs):
                if args[:2] == ("user", "list"):
                    return RR(0, out="ROLE_ADMIN")
                if args[:2] == ("user", "create"):
                    Path(signed).write_text("signed")
                    return RR(0)
                if args[:2] == ("user", "role-set"):
                    return RR(1, out="denied", err="no")
                return RR(0)

            def capture_retry(cfg_arg, *args, **kwargs):
                stage = kwargs.get("stage", "")
                if "pre-create" in stage:
                    return RR(0, out='{"id": 1}')
                return RR(0, out='{"id": 1}\n{"id": 3}')

            with mock.patch.object(u, "_runner", side_effect=runner), mock.patch.object(
                u, "_runner_capture_retry", side_effect=capture_retry
            ), mock.patch.object(u, "run", return_value=RR(0)), mock.patch.object(
                u.sys, "platform", "linux"
            ):
                with self.assertRaises(RuntimeError) as ctx:
                    u.create_user(cfg, "ROLE_ADMIN")
                self.assertIn("Failed to assign", str(ctx.exception))

    def test_role_missing_after_set(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            p1, p2, p3, _ = self._patch_common(cfg)
            with p1, p2, p3, mock.patch.object(
                u, "_user_has_role", return_value=False
            ), mock.patch.object(u.sys, "platform", "linux"):
                with self.assertRaises(RuntimeError) as ctx:
                    u.create_user(cfg, "ROLE_ADMIN")
                self.assertIn("not present after role-set", str(ctx.exception))

    def test_cannot_detect_user_id(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            signed = os.path.join(cfg.quartus_keys_dir, "admin_bkps_signed.crt")

            def runner(cfg_arg, *args, **kwargs):
                if args[:2] == ("user", "list"):
                    return RR(0, out="ROLE_ADMIN")
                if args[:2] == ("user", "create"):
                    Path(signed).write_text("signed")
                    return RR(0)
                return RR(0)

            # Same ids before/after → new_ids empty → UnboundLocalError on user_id
            # (else branch at 232-236 is unreachable without a prior falsy assignment)
            def capture_retry(cfg_arg, *args, **kwargs):
                return RR(0, out='{"id": 1}')

            with mock.patch.object(u, "_runner", side_effect=runner), mock.patch.object(
                u, "_runner_capture_retry", side_effect=capture_retry
            ), mock.patch.object(u, "run", return_value=RR(0)), mock.patch.object(
                u.sys, "platform", "linux"
            ):
                with self.assertRaises(UnboundLocalError):
                    u.create_user(cfg, "ROLE_ADMIN")


class UnsetUserRoleTests(unittest.TestCase):
    def test_missing_args(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with mock.patch.object(u, "audit_log"):
                with self.assertRaises(ValueError):
                    u.unset_user_role(cfg, "", "ROLE_ADMIN")
                with self.assertRaises(ValueError):
                    u.unset_user_role(cfg, "1", "")

    def test_non_numeric(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with mock.patch.object(u, "audit_log"):
                with self.assertRaises(ValueError):
                    u.unset_user_role(cfg, "x", "ROLE_ADMIN")

    def test_success(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with mock.patch.object(u, "audit_log"), mock.patch.object(
                u, "_runner", return_value=RR(0)
            ):
                u.unset_user_role(cfg, "3", "ROLE_ADMIN")

    def test_failure(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with mock.patch.object(u, "audit_log"), mock.patch.object(
                u, "_runner", return_value=RR(2, err="fail\n")
            ):
                with self.assertRaises(RuntimeError):
                    u.unset_user_role(cfg, "3", "ROLE_ADMIN")


if __name__ == "__main__":
    unittest.main()

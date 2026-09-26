#!/usr/bin/env python3
"""Unit tests for bkps_windows_runtime.py."""

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

import bkps_windows_runtime as wr  # noqa: E402


class WindowsSofthsmRootTests(unittest.TestCase):
    def test_explicit_install_root(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"BKPS_SOFTHSM_INSTALL_ROOT": td}, clear=False):
                self.assertEqual(wr.windows_softhsm_root(), os.path.abspath(td))

    def test_expands_user_and_vars(self):
        with tempfile.TemporaryDirectory() as td:
            nested = os.path.join(td, "soft")
            os.makedirs(nested)
            with mock.patch.dict(
                os.environ,
                {"BKPS_SOFTHSM_INSTALL_ROOT": nested, "HOME": td},
                clear=False,
            ):
                self.assertEqual(wr.windows_softhsm_root(), os.path.abspath(nested))

    def test_localappdata_path(self):
        with tempfile.TemporaryDirectory() as td:
            env = {"LOCALAPPDATA": td}
            env.pop("BKPS_SOFTHSM_INSTALL_ROOT", None)
            with mock.patch.dict(os.environ, env, clear=False):
                os.environ.pop("BKPS_SOFTHSM_INSTALL_ROOT", None)
                expected = os.path.abspath(
                    os.path.join(
                        td,
                        "BKPS",
                        "SoftHSM2",
                        f"runtime-{wr.WINDOWS_SOFTHSM_VERSION}",
                    )
                )
                self.assertEqual(wr.windows_softhsm_root(), expected)

    def test_empty_without_localappdata(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(wr.windows_softhsm_root(), "")


class WindowsSofthsmConfigPathTests(unittest.TestCase):
    def test_explicit_config_root(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"BKPS_SOFTHSM_CONFIG_ROOT": td}, clear=False):
                self.assertEqual(
                    wr.windows_softhsm_config_path(),
                    os.path.join(os.path.abspath(td), "softhsm2.conf"),
                )

    def test_localappdata_config(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"LOCALAPPDATA": td}, clear=False):
                os.environ.pop("BKPS_SOFTHSM_CONFIG_ROOT", None)
                expected = os.path.join(
                    os.path.abspath(os.path.join(td, "BKPS", "SoftHSM2")),
                    "softhsm2.conf",
                )
                self.assertEqual(wr.windows_softhsm_config_path(), expected)

    def test_empty_without_localappdata(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(wr.windows_softhsm_config_path(), "")


class ConfigureWindowsSofthsmDefaultsTests(unittest.TestCase):
    def test_noop_on_non_windows(self):
        cfg = SimpleNamespace()
        with mock.patch.object(os, "name", "posix"):
            wr.configure_windows_softhsm_defaults(cfg)
        self.assertEqual(vars(cfg), {})

    def test_populates_managed_paths_and_pkcs11_which(self):
        with tempfile.TemporaryDirectory() as td:
            root = os.path.join(td, "runtime")
            lib = os.path.join(root, "lib", "softhsm2-x64.dll")
            util = os.path.join(root, "bin", "softhsm2-util.exe")
            conf = os.path.join(td, "softhsm2.conf")
            os.makedirs(os.path.dirname(lib))
            os.makedirs(os.path.dirname(util))
            Path(lib).write_text("dll")
            Path(util).write_text("exe")
            Path(conf).write_text("conf")
            p11 = os.path.join(td, "pkcs11-tool.exe")
            Path(p11).write_text("p11")

            cfg = SimpleNamespace(
                softhsm_lib_path="",
                softhsm_util_path="missing.dll",
                softhsm_conf_path="",
                pkcs11_tool_path="",
            )
            with mock.patch.object(os, "name", "nt"), mock.patch.object(
                wr, "windows_softhsm_root", return_value=root
            ), mock.patch.object(
                wr, "windows_softhsm_config_path", return_value=conf
            ), mock.patch.object(wr.shutil, "which", return_value=p11):
                wr.configure_windows_softhsm_defaults(cfg)

            self.assertEqual(cfg.softhsm_lib_path, lib)
            self.assertEqual(cfg.softhsm_util_path, util)
            self.assertEqual(cfg.softhsm_conf_path, conf)
            self.assertEqual(cfg.pkcs11_tool_path, p11)

    def test_keeps_existing_valid_pkcs11(self):
        with tempfile.TemporaryDirectory() as td:
            root = os.path.join(td, "runtime")
            os.makedirs(root)
            conf = os.path.join(td, "softhsm2.conf")
            Path(conf).write_text("c")
            existing = os.path.join(td, "existing-pkcs11.exe")
            Path(existing).write_text("x")
            cfg = SimpleNamespace(
                softhsm_lib_path="",
                softhsm_util_path="",
                softhsm_conf_path="",
                pkcs11_tool_path=existing,
            )
            with mock.patch.object(os, "name", "nt"), mock.patch.object(
                wr, "windows_softhsm_root", return_value=root
            ), mock.patch.object(
                wr, "windows_softhsm_config_path", return_value=conf
            ), mock.patch.object(wr.shutil, "which") as which_mock:
                wr.configure_windows_softhsm_defaults(cfg)
                which_mock.assert_not_called()
            self.assertEqual(cfg.pkcs11_tool_path, existing)

    def test_scans_program_files_for_pkcs11(self):
        with tempfile.TemporaryDirectory() as td:
            root = os.path.join(td, "runtime")
            os.makedirs(root)
            conf = os.path.join(td, "softhsm2.conf")
            Path(conf).write_text("c")
            prog = os.path.join(td, "Prog64")
            candidate = os.path.join(
                prog, "OpenSC Project", "OpenSC", "tools", "pkcs11-tool.exe"
            )
            os.makedirs(os.path.dirname(candidate))
            Path(candidate).write_text("tool")

            cfg = SimpleNamespace(
                softhsm_lib_path="",
                softhsm_util_path="",
                softhsm_conf_path="",
                pkcs11_tool_path="",
            )
            env = {
                "ProgramW6432": prog,
                "ProgramFiles": prog,
                "ProgramFiles(x86)": "",
            }
            with mock.patch.object(os, "name", "nt"), mock.patch.object(
                wr, "windows_softhsm_root", return_value=root
            ), mock.patch.object(
                wr, "windows_softhsm_config_path", return_value=conf
            ), mock.patch.object(wr.shutil, "which", return_value=None), mock.patch.dict(
                os.environ, env, clear=False
            ):
                wr.configure_windows_softhsm_defaults(cfg)
            self.assertEqual(cfg.pkcs11_tool_path, candidate)

    def test_skips_managed_when_configured_exists(self):
        with tempfile.TemporaryDirectory() as td:
            root = os.path.join(td, "runtime")
            os.makedirs(root)
            existing_lib = os.path.join(td, "custom.dll")
            Path(existing_lib).write_text("x")
            conf = os.path.join(td, "softhsm2.conf")
            Path(conf).write_text("c")
            cfg = SimpleNamespace(
                softhsm_lib_path=existing_lib,
                softhsm_util_path="",
                softhsm_conf_path="",
                pkcs11_tool_path="",
            )
            with mock.patch.object(os, "name", "nt"), mock.patch.object(
                wr, "windows_softhsm_root", return_value=root
            ), mock.patch.object(
                wr, "windows_softhsm_config_path", return_value=conf
            ), mock.patch.object(wr.shutil, "which", return_value=None), mock.patch.dict(
                os.environ,
                {"ProgramW6432": "", "ProgramFiles": "", "ProgramFiles(x86)": ""},
                clear=False,
            ):
                wr.configure_windows_softhsm_defaults(cfg)
            self.assertEqual(cfg.softhsm_lib_path, existing_lib)


class InstallWindowsSofthsmTests(unittest.TestCase):
    def test_missing_installer(self):
        installer = Path(wr.__file__).resolve().with_name("install_softhsm_windows.ps1")
        real_is_file = Path.is_file

        def _is_file(self):
            if Path(self) == installer:
                return False
            return real_is_file(self)

        with mock.patch.object(Path, "is_file", _is_file):
            with self.assertRaises(RuntimeError) as ctx:
                wr.install_windows_softhsm()
            self.assertIn("installer is missing", str(ctx.exception))

    def test_missing_powershell(self):
        with mock.patch.object(wr.shutil, "which", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                wr.install_windows_softhsm()
            self.assertIn("PowerShell", str(ctx.exception))

    def test_nonzero_exit(self):
        with mock.patch.object(wr.shutil, "which", return_value="/bin/pwsh"), mock.patch.object(
            wr.subprocess, "run", return_value=SimpleNamespace(returncode=1)
        ):
            with self.assertRaises(RuntimeError) as ctx:
                wr.install_windows_softhsm()
            self.assertIn("failed installation", str(ctx.exception))

    def test_missing_runtime_files_after_success(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(
                wr.shutil, "which", return_value="/bin/pwsh"
            ), mock.patch.object(
                wr.subprocess, "run", return_value=SimpleNamespace(returncode=0)
            ), mock.patch.object(wr, "windows_softhsm_root", return_value=td):
                with self.assertRaises(RuntimeError) as ctx:
                    wr.install_windows_softhsm()
                self.assertIn("runtime files are missing", str(ctx.exception))

    def test_success_sets_env(self):
        with tempfile.TemporaryDirectory() as td:
            util = os.path.join(td, "bin", "softhsm2-util.exe")
            provider = os.path.join(td, "lib", "softhsm2-x64.dll")
            os.makedirs(os.path.dirname(util))
            os.makedirs(os.path.dirname(provider))
            Path(util).write_text("u")
            Path(provider).write_text("p")
            with mock.patch.object(
                wr.shutil, "which", side_effect=lambda name: "/bin/powershell" if name == "powershell" else None
            ), mock.patch.object(
                wr.subprocess, "run", return_value=SimpleNamespace(returncode=0)
            ) as run_mock, mock.patch.object(wr, "windows_softhsm_root", return_value=td):
                root = wr.install_windows_softhsm()
            self.assertEqual(root, td)
            self.assertEqual(os.environ.get("BKPS_SOFTHSM_ROOT"), td)
            args = run_mock.call_args[0][0]
            self.assertEqual(args[0], "/bin/powershell")
            self.assertIn("-File", args)


if __name__ == "__main__":
    unittest.main()

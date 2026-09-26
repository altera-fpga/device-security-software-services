#!/usr/bin/env python3
"""Regression tests for using the cloned repository's Windows build flow."""

from __future__ import annotations

import tempfile
import unittest
import os
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


TOOL_DIR = Path(__file__).resolve().parents[1]
import sys

if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

import bkps_deps


class WindowsRepositoryBuildTests(unittest.TestCase):
    UPSTREAM_SCRIPT = (
        "@echo off\r\n"
        "for /f \"tokens=1,2 delims=.\" %%X in (\"14.44\") do (\r\n"
        "        set \"BOOST_TOOLSET=vc%%Y%%X\"\r\n"
        "        set \"BOOST_B2_TOOLSET=msvc-%%Y.%%X\"\r\n"
        "        set \"CMAKE_VS_TOOLSET=v%%Y%%X\"\r\n"
        ")\r\n"
        "echo ===================================================\r\n"
        "cmd /c .\\bootstrap.bat %BOOST_TOOLSET%\r\n"
        "cmd /c .\\b2.exe --toolset=%BOOST_B2_TOOLSET% install\r\n"
        "call gradlew.bat  clean build -Pversion=%BUILD_VERSION% -Dversion=%BUILD_VERSION%\r\n"
        "call gradlew.bat -Pprod -Paws -Pversion=%BUILD_VERSION% -Dversion=%BUILD_VERSION% :bkps:liquibaseGenerateSql\r\n"
    ).encode("utf-8")

    def test_native_build_uses_repository_script_unchanged(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            checkout = Path(temp_dir)
            build_script = checkout / "build-dependencies.bat"
            upstream_contents = self.UPSTREAM_SCRIPT
            build_script.write_bytes(upstream_contents)
            cfg = SimpleNamespace(
                bkps_repo_dir=str(checkout),
                bkps_version="1.2.3",
                bkps_build_mode="full",
                include_bkp_programmer=True,
            )
            vs_build_dir = str(checkout / "Visual Studio" / "VC" / "Auxiliary" / "Build")
            cmd_exe = r"C:\Windows\System32\cmd.exe"

            with (
                mock.patch.object(bkps_deps, "_detect_distro", return_value="windows"),
                mock.patch.object(
                    bkps_deps,
                    "_windows_visual_studio_build_dir",
                    return_value=vs_build_dir,
                ),
                mock.patch.object(
                    bkps_deps,
                    "_windows_executable",
                    return_value=cmd_exe,
                ),
                mock.patch.object(
                    bkps_deps,
                    "_windows_reg_query_works",
                    return_value=True,
                ),
                mock.patch.object(bkps_deps, "stream", return_value=0) as stream_mock,
            ):
                self.assertTrue(
                    bkps_deps.build_native_dependencies(
                        cfg, repo_dir=str(checkout), force=True
                    )
                )

            self.assertEqual(upstream_contents, build_script.read_bytes())
            stream_mock.assert_called_once_with(
                [
                    cmd_exe, "/d", "/s", "/c", "call", str(build_script),
                    vs_build_dir, "1.2.3", "--full",
                ],
                cwd=str(checkout),
                env=None,
            )

    def test_registry_shim_builds_valid_power_shell_provider_paths(self):
        shim = (TOOL_DIR / "windows_cmd_shims" / "reg_query.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "'Registry::HKEY_LOCAL_MACHINE\\' + $Matches[1]", shim
        )
        self.assertIn(
            "'Registry::HKEY_CURRENT_USER\\' + $Matches[1]", shim
        )

    def test_native_build_uses_read_only_registry_shim_when_reg_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            checkout = Path(temp_dir)
            (checkout / "build-dependencies.bat").write_bytes(self.UPSTREAM_SCRIPT)
            cfg = SimpleNamespace(bkps_repo_dir=temp_dir, bkps_version="")
            vs_build_dir = str(checkout / "VC" / "Auxiliary" / "Build")
            cmd_exe = r"C:\Windows\System32\cmd.exe"
            shim_dir = str(TOOL_DIR / "windows_cmd_shims")

            with (
                mock.patch.object(bkps_deps, "_detect_distro", return_value="windows"),
                mock.patch.object(
                    bkps_deps,
                    "_windows_visual_studio_build_dir",
                    return_value=vs_build_dir,
                ),
                mock.patch.object(
                    bkps_deps,
                    "_windows_executable",
                    return_value=cmd_exe,
                ),
                mock.patch.object(
                    bkps_deps,
                    "_windows_reg_query_works",
                    return_value=False,
                ),
                mock.patch.object(
                    bkps_deps,
                    "_windows_registry_query_shim_dir",
                    return_value=shim_dir,
                ),
                mock.patch.object(bkps_deps, "stream", return_value=0) as stream_mock,
            ):
                self.assertTrue(
                    bkps_deps.build_native_dependencies(
                        cfg, repo_dir=temp_dir, force=True
                    )
                )

            call = stream_mock.call_args
            self.assertEqual(call.kwargs["cwd"], temp_dir)
            self.assertEqual(
                call.kwargs["env"]["PATH"].split(os.pathsep)[0],
                shim_dir,
            )

    def test_native_build_requires_repository_script(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cfg = SimpleNamespace(bkps_repo_dir=temp_dir, bkps_version="")
            with (
                mock.patch.object(bkps_deps, "_detect_distro", return_value="windows"),
                mock.patch.object(bkps_deps, "stream") as stream_mock,
            ):
                self.assertFalse(
                    bkps_deps.build_native_dependencies(
                        cfg, repo_dir=temp_dir, force=True
                    )
                )
            stream_mock.assert_not_called()

    def test_native_build_fails_cleanly_without_visual_studio(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            checkout = Path(temp_dir)
            (checkout / "build-dependencies.bat").write_text(
                "@echo off\r\n", encoding="utf-8"
            )
            cfg = SimpleNamespace(bkps_repo_dir=temp_dir, bkps_version="")
            with (
                mock.patch.object(bkps_deps, "_detect_distro", return_value="windows"),
                mock.patch.object(
                    bkps_deps,
                    "_windows_visual_studio_build_dir",
                    return_value="",
                ),
                mock.patch.object(bkps_deps, "stream") as stream_mock,
            ):
                self.assertFalse(
                    bkps_deps.build_native_dependencies(
                        cfg, repo_dir=temp_dir, force=True
                    )
                )
            stream_mock.assert_not_called()

    def test_native_build_runs_unknown_upstream_script_without_rewriting_it(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            checkout = Path(temp_dir)
            build_script = checkout / "build-dependencies.bat"
            original = b"@echo off\r\necho future upstream layout\r\n"
            build_script.write_bytes(original)
            vs_build_dir = str(checkout / "VC" / "Auxiliary" / "Build")
            cmd_exe = r"C:\Windows\System32\cmd.exe"
            cfg = SimpleNamespace(
                bkps_repo_dir=temp_dir,
                bkps_version="",
                bkps_build_mode="bkp_only",
                include_bkp_programmer=False,
            )
            with (
                mock.patch.object(bkps_deps, "_detect_distro", return_value="windows"),
                mock.patch.object(
                    bkps_deps,
                    "_windows_visual_studio_build_dir",
                    return_value=vs_build_dir,
                ),
                mock.patch.object(
                    bkps_deps,
                    "_windows_executable",
                    return_value=cmd_exe,
                ),
                mock.patch.object(
                    bkps_deps,
                    "_windows_reg_query_works",
                    return_value=True,
                ),
                mock.patch.object(bkps_deps, "stream", return_value=0) as stream_mock,
            ):
                self.assertTrue(
                    bkps_deps.build_native_dependencies(
                        cfg, repo_dir=temp_dir, force=True
                    )
                )
            self.assertEqual(build_script.read_bytes(), original)
            stream_mock.assert_called_once_with(
                [
                    cmd_exe, "/d", "/s", "/c", "call", str(build_script),
                    vs_build_dir, "1.0.0", "--bkp-only",
                ],
                cwd=temp_dir,
                env=None,
            )


if __name__ == "__main__":
    unittest.main()

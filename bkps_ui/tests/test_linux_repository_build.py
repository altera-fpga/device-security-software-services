#!/usr/bin/env python3
"""Regression tests for using the cloned repository's Linux build flow."""

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

import bkps_deps


class LinuxRepositoryBuildTests(unittest.TestCase):
    def test_native_build_uses_repository_script_unchanged(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            checkout = Path(temp_dir)
            build_script = checkout / "build_ubuntu.sh"
            upstream_contents = "#!/bin/bash\necho repository-owned\n"
            build_script.write_text(upstream_contents, encoding="utf-8")
            cfg = SimpleNamespace(
                bkps_repo_dir=str(checkout),
                bkps_version="1.2.3",
                bkps_build_mode="full",
                include_bkp_programmer=True,
            )
            missing = {
                "openssl": False,
                "boost": False,
                "libcurl": False,
                "gtest": False,
                "libspdm": False,
            }

            with (
                mock.patch.object(bkps_deps, "_detect_distro", return_value="debian"),
                mock.patch.object(
                    bkps_deps,
                    "check_native_dependencies",
                    return_value=missing,
                ),
                mock.patch.object(bkps_deps, "stream", return_value=0) as stream_mock,
                mock.patch.object(
                    bkps_deps, "_linux_docker_prerequisite", return_value="ready"
                ),
                mock.patch.dict(os.environ, {"GRADLE_OPTS": "-Xmx1g"}),
            ):
                self.assertTrue(
                    bkps_deps.build_native_dependencies(
                        cfg, repo_dir=str(checkout), force=True
                    )
                )

            self.assertEqual(
                upstream_contents,
                build_script.read_text(encoding="utf-8"),
            )
            stream_mock.assert_called_once_with(
                ["bash", str(build_script), "--full"],
                env={
                    "BUILD_VERSION": "1.2.3",
                    "GRADLE_OPTS": (
                        "-Xmx1g -Dorg.gradle.daemon=false "
                        "-Dorg.gradle.console=plain"
                    ),
                },
                input_text="y\n",
            )

    def test_native_build_requires_repository_script(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            checkout = Path(temp_dir)
            cfg = SimpleNamespace(bkps_repo_dir=str(checkout), bkps_version="")
            missing = {
                "openssl": False,
                "boost": False,
                "libcurl": False,
                "gtest": False,
                "libspdm": False,
            }

            with (
                mock.patch.object(bkps_deps, "_detect_distro", return_value="debian"),
                mock.patch.object(
                    bkps_deps,
                    "check_native_dependencies",
                    return_value=missing,
                ),
                mock.patch.object(bkps_deps, "stream") as stream_mock,
            ):
                self.assertFalse(
                    bkps_deps.build_native_dependencies(
                        cfg, repo_dir=str(checkout), force=True
                    )
                )

            stream_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()

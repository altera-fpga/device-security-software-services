#!/usr/bin/env python3
"""Regression tests for selectable BKPS repository artifact builds."""

from __future__ import annotations

import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path


TOOL_DIR = Path(__file__).resolve().parents[1]
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

import bkps_build
import bkps_config
import bkps_deps


class BuildSelectionTests(unittest.TestCase):
    def test_default_is_bkp_only_without_programmer(self):
        cfg = bkps_config.Config()
        self.assertEqual(cfg.bkps_build_mode, "bkp_only")
        self.assertFalse(cfg.include_bkp_programmer)

    def test_config_round_trip_preserves_build_selection(self):
        with tempfile.TemporaryDirectory(dir=TOOL_DIR) as root:
            path = Path(root) / "build-selection.conf"
            cfg = bkps_config.Config(
                config_file=str(path),
                bkps_build_mode="full",
                include_bkp_programmer=True,
            )
            bkps_config.create_config(cfg)
            loaded = bkps_config.Config(config_file=str(path))
            bkps_config.load_config(loaded)
            self.assertEqual(loaded.bkps_build_mode, "full")
            self.assertTrue(loaded.include_bkp_programmer)

    def _windows_script_arguments(
        self, mode: str, include_programmer: bool
    ) -> list[str]:
        """Run the Windows flow against a stub script and return its arguments."""
        with tempfile.TemporaryDirectory(dir=TOOL_DIR) as root:
            batch_path = Path(root) / "build-dependencies.bat"
            batch_path.write_text("@echo off\n", encoding="utf-8")
            cfg = bkps_config.Config(
                bkps_repo_dir=root,
                bkps_version="1.2.3",
                bkps_build_mode=mode,
                include_bkp_programmer=include_programmer,
            )
            with unittest.mock.patch.multiple(
                bkps_deps,
                _windows_visual_studio_build_dir=unittest.mock.DEFAULT,
                _windows_executable=unittest.mock.DEFAULT,
                _windows_reg_query_works=unittest.mock.DEFAULT,
                stream=unittest.mock.DEFAULT,
            ) as patched:
                patched["_windows_visual_studio_build_dir"].return_value = (
                    r"C:\VS\VC\Auxiliary\Build"
                )
                patched["_windows_executable"].return_value = r"C:\cmd.exe"
                patched["_windows_reg_query_works"].return_value = True
                patched["stream"].return_value = 0
                self.assertTrue(
                    bkps_deps.build_windows_repository(cfg, repo_dir=root)
                )
                command = patched["stream"].call_args[0][0]

        self.assertEqual(str(batch_path), command[5])
        # The script takes the VS build directory and version first, then the
        # selection flags.
        return command[6:]

    def test_windows_selection_is_passed_to_the_repository_script(self):
        """The repository .bat is run unchanged; selection travels as flags."""
        self.assertEqual(
            [
                r"C:\VS\VC\Auxiliary\Build",
                "1.2.3",
                "--bkp-only",
            ],
            self._windows_script_arguments("bkp_only", False),
        )
        self.assertEqual(
            [
                r"C:\VS\VC\Auxiliary\Build",
                "1.2.3",
                "--bkp-with-bkpprogrammer",
            ],
            self._windows_script_arguments("bkp_only", True),
        )
        self.assertEqual(
            [
                r"C:\VS\VC\Auxiliary\Build",
                "1.2.3",
                "--full",
            ],
            self._windows_script_arguments("full", True),
        )

    def _linux_script_invocation(
        self, mode: str, include_programmer: bool
    ) -> list[str]:
        """Run the Linux flow against a stub script and return its invocation."""
        with tempfile.TemporaryDirectory(dir=TOOL_DIR) as root:
            script = Path(root) / "build_ubuntu.sh"
            script.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            cfg = bkps_config.Config(
                bkps_repo_dir=root,
                bkps_version="1.2.3",
                bkps_build_mode=mode,
                include_bkp_programmer=include_programmer,
            )
            with unittest.mock.patch.multiple(
                bkps_deps,
                _detect_distro=unittest.mock.DEFAULT,
                check_native_dependencies=unittest.mock.DEFAULT,
                _linux_docker_prerequisite=unittest.mock.DEFAULT,
                stream=unittest.mock.DEFAULT,
            ) as patched:
                patched["_detect_distro"].return_value = "debian"
                patched["check_native_dependencies"].return_value = {
                    "openssl": False
                }
                patched["_linux_docker_prerequisite"].return_value = "ready"
                patched["stream"].return_value = 0
                self.assertTrue(
                    bkps_deps.build_native_dependencies(cfg, repo_dir=root)
                )
                return patched["stream"].call_args[0][0][1:]

    def test_linux_selection_is_passed_to_the_repository_script(self):
        """build_ubuntu.sh is run unchanged; selection travels as flags."""
        self.assertEqual(
            ["--bkp-only"],
            self._linux_script_invocation("bkp_only", False)[1:],
        )
        self.assertEqual(
            ["--bkp-with-bkpprogrammer"],
            self._linux_script_invocation("bkp_only", True)[1:],
        )
        self.assertEqual(
            ["--full"],
            self._linux_script_invocation("full", True)[1:],
        )

    def test_each_selection_reports_its_own_container_components(self):
        """Full builds FCSServer; the programmer is independent of the mode."""
        self.assertEqual(
            ["FCSServer"], bkps_deps._container_build_components("full", False)
        )
        self.assertEqual(
            ["BKP Programmer"],
            bkps_deps._container_build_components("bkp_only", True),
        )
        self.assertEqual(
            ["FCSServer", "BKP Programmer"],
            bkps_deps._container_build_components("full", True),
        )
        self.assertEqual(
            [], bkps_deps._container_build_components("bkp_only", False)
        )

    def test_a_selection_without_containers_needs_no_engine(self):
        cfg = bkps_config.Config()
        with unittest.mock.patch.object(bkps_deps, "_docker_build_status") as status:
            state = bkps_deps._linux_docker_prerequisite(cfg, "bkp_only", False)
        self.assertEqual("ready", state)
        status.assert_not_called()

    def test_an_unusable_engine_is_provisioned_before_the_build(self):
        cfg = bkps_config.Config()
        with unittest.mock.patch.object(
            bkps_deps, "_docker_build_status",
            side_effect=[("unusable", "no daemon"), ("ready", "")],
        ):
            with unittest.mock.patch.object(
                bkps_deps, "_ensure_container_engine", return_value=True
            ) as provision:
                state = bkps_deps._linux_docker_prerequisite(cfg, "full", True)

        self.assertEqual("ready", state)
        provision.assert_called_once()

    def test_a_failed_provisioning_stops_the_build(self):
        cfg = bkps_config.Config()
        with unittest.mock.patch.object(
            bkps_deps, "_docker_build_status", return_value=("unusable", "no daemon")
        ):
            with unittest.mock.patch.object(
                bkps_deps, "_ensure_container_engine", return_value=False
            ):
                state = bkps_deps._linux_docker_prerequisite(cfg, "full", True)

        self.assertEqual("unusable", state)

    def test_the_docker_prompt_follows_the_build_selection(self):
        """Answering the repository prompt 'no' silently drops both artifacts."""
        self.assertEqual(
            "y\n",
            bkps_deps._docker_prompt_answer(["FCSServer", "BKP Programmer"]),
        )
        self.assertEqual("y\n", bkps_deps._docker_prompt_answer(["BKP Programmer"]))
        self.assertEqual("n\n", bkps_deps._docker_prompt_answer([]))

    def test_config_maps_to_build_ubuntu_script_flags(self):
        self.assertEqual(
            ["--full"],
            bkps_deps._linux_build_selection_args("full", True),
        )
        self.assertEqual(
            ["--bkp-with-bkpprogrammer"],
            bkps_deps._linux_build_selection_args("bkp_only", True),
        )
        self.assertEqual(
            ["--bkp-only"],
            bkps_deps._linux_build_selection_args("bkp_only", False),
        )
        self.assertEqual(
            bkps_deps._linux_build_selection_args("full", True),
            bkps_deps._repository_build_selection_args("full", True),
        )

    def test_a_fresh_group_membership_runs_the_build_through_sg(self):
        """A new docker group member must not have to log out and back in."""
        self.assertEqual(
            ["sg", "docker", "-c", "bash '/tmp/build me.sh'"],
            bkps_deps._linux_build_invocation("/tmp/build me.sh", "group-shim"),
        )
        self.assertEqual(
            ["bash", "/tmp/build.sh"],
            bkps_deps._linux_build_invocation("/tmp/build.sh", "ready"),
        )
        self.assertEqual(
            [
                "bash",
                "/tmp/build.sh",
                "--bkp-only",
            ],
            bkps_deps._linux_build_invocation(
                "/tmp/build.sh",
                "ready",
                ["--bkp-only"],
            ),
        )
        self.assertEqual(
            [
                "sg",
                "docker",
                "-c",
                "bash /tmp/build.sh --full",
            ],
            bkps_deps._linux_build_invocation(
                "/tmp/build.sh",
                "group-shim",
                ["--full"],
            ),
        )
        self.assertEqual(
            [
                "bash",
                "/tmp/build.sh",
                "--bkp-only",
            ],
            bkps_deps._linux_build_invocation(
                "/tmp/build.sh",
                "ready",
                ["--bkp-only"],
            ),
        )
        self.assertEqual(
            [
                "sg",
                "docker",
                "-c",
                "bash /tmp/build.sh --full",
            ],
            bkps_deps._linux_build_invocation(
                "/tmp/build.sh",
                "group-shim",
                ["--full"],
            ),
        )

    def test_engine_provisioning_installs_starts_and_grants_access(self):
        cfg = bkps_config.Config()
        with unittest.mock.patch.object(
            bkps_deps, "_docker_build_status",
            side_effect=[("unusable", "not installed"), ("group-shim", "denied")],
        ):
            with unittest.mock.patch.object(
                bkps_deps, "command_exists", return_value=False
            ):
                with unittest.mock.patch.object(
                    bkps_deps, "_install_system_packages"
                ) as install:
                    with unittest.mock.patch.object(bkps_deps, "run") as privileged:
                        # command_exists stays False, so the client is reported
                        # as missing even after the package install.
                        self.assertFalse(
                            bkps_deps._ensure_container_engine(cfg, "debian")
                        )

        install.assert_called_once_with(["docker.io"], "debian")
        privileged.assert_not_called()

    def test_engine_provisioning_reports_a_ready_engine_without_changes(self):
        cfg = bkps_config.Config()
        with unittest.mock.patch.object(
            bkps_deps, "_docker_build_status", return_value=("ready", "")
        ):
            with unittest.mock.patch.object(
                bkps_deps, "_install_system_packages"
            ) as install:
                self.assertTrue(bkps_deps._ensure_container_engine(cfg, "debian"))

        install.assert_not_called()

    def test_schema_generation_is_skipped_when_the_build_produced_one(self):
        with tempfile.TemporaryDirectory(dir=TOOL_DIR) as root:
            repo = Path(root)
            (repo / "bkps").mkdir()
            (repo / "bkps" / "bkps-1.0.0.sql").write_text(
                "CREATE TABLE service_configuration (id bigint);\n",
                encoding="utf-8",
            )
            cfg = bkps_config.Config(bkps_repo_dir=str(repo))
            with unittest.mock.patch.object(bkps_build, "stream") as gradle:
                bkps_build._ensure_bkps_sql_schema(cfg)
            gradle.assert_not_called()

    def test_schema_generation_runs_liquibase_with_the_prod_properties(self):
        with tempfile.TemporaryDirectory(dir=TOOL_DIR) as root:
            repo = Path(root)
            (repo / "bkps").mkdir()
            wrapper = repo / ("gradlew.bat" if sys.platform.startswith("win") else "gradlew")
            wrapper.write_text("", encoding="utf-8")
            cfg = bkps_config.Config(bkps_repo_dir=str(repo), bkps_version="1.2.3")
            with unittest.mock.patch.object(
                bkps_build, "stream", return_value=0
            ) as gradle:
                bkps_build._ensure_bkps_sql_schema(cfg)

            command, kwargs = gradle.call_args[0][0], gradle.call_args[1]
            self.assertEqual(str(wrapper), command[0])
            self.assertIn("-Pprod", command)
            self.assertIn("-Paws", command)
            self.assertIn("liquibaseGenerateSql", command)
            self.assertIn("-Pversion=1.2.3", command)
            self.assertEqual(str(repo / "bkps"), kwargs["cwd"])
            self.assertEqual("dummy", kwargs["env"]["KEYSTORE_DUMMY_ALIAS"])

    def test_schema_generation_failure_stops_the_build(self):
        with tempfile.TemporaryDirectory(dir=TOOL_DIR) as root:
            repo = Path(root)
            (repo / "bkps").mkdir()
            wrapper = repo / ("gradlew.bat" if sys.platform.startswith("win") else "gradlew")
            wrapper.write_text("", encoding="utf-8")
            cfg = bkps_config.Config(bkps_repo_dir=str(repo))
            with unittest.mock.patch.object(bkps_build, "stream", return_value=1):
                with self.assertRaises(RuntimeError) as raised:
                    bkps_build._ensure_bkps_sql_schema(cfg)

            self.assertIn("Liquibase SQL generation failed", str(raised.exception))

    def _wrapper_cmake(
        self, root: Path, gnu_libraries: str, leading_mingw_branch: bool
    ) -> Path:
        """Write a wrapper CMake file in one of the two upstream layouts."""
        path = root / "spdm_wrapper" / "wrapper" / "CMakeLists.txt"
        path.parent.mkdir(parents=True)
        mingw = (
            "if(MINGW)\n"
            "    target_link_libraries(libspdm_wrapper PRIVATE\n"
            "            ${LIBSPDM_LIB_DIR}/libmemlib.a\n"
            "            ${LIBSPDM_LIB_DIR}/libmalloclib.a)\n"
            if leading_mingw_branch else ""
        )
        gnu_keyword = "elseif" if leading_mingw_branch else "if"
        path.write_text(
            "add_library(libspdm_wrapper SHARED ${SOURCES})\n"
            f"{mingw}"
            f"{gnu_keyword}(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)\n"
            "    target_link_libraries(libspdm_wrapper PRIVATE\n"
            f"{gnu_libraries}"
            "else()\n"
            "    target_link_libraries(libspdm_wrapper PRIVATE\n"
            "            malloclib.lib)\n"
            "endif()\n",
            encoding="utf-8",
        )
        return path

    def _gnu_branch(self, text: str) -> str:
        branch = bkps_build._GNU_LINK_BRANCH.search(text)
        self.assertIsNotNone(branch)
        return branch.group(0)

    @unittest.mock.patch.object(bkps_build.sys, "platform", "linux")
    def test_gnu_wrapper_branch_gains_the_libspdm_malloc_stub(self):
        """free_pool is undefined without it, so the .so cannot be loaded."""
        for leading_mingw_branch in (True, False):
            with self.subTest(leading_mingw_branch=leading_mingw_branch):
                with tempfile.TemporaryDirectory(dir=TOOL_DIR) as root:
                    path = self._wrapper_cmake(
                        Path(root),
                        "            ${LIBSPDM_LIB_DIR}/libspdm_requester_lib.a\n"
                        "            ${LIBSPDM_LIB_DIR}/libmemlib.a)\n",
                        leading_mingw_branch,
                    )
                    bkps_build._apply_linux_spdm_wrapper_malloc_link(root)
                    gnu_branch = self._gnu_branch(
                        path.read_text(encoding="utf-8")
                    )

                self.assertIn("${LIBSPDM_LIB_DIR}/libmalloclib.a", gnu_branch)
                # The stub must follow the archives that reference it.
                self.assertLess(
                    gnu_branch.index("libmemlib.a"),
                    gnu_branch.index("libmalloclib.a"),
                )

    @unittest.mock.patch.object(bkps_build.sys, "platform", "linux")
    def test_an_already_linked_wrapper_is_left_alone(self):
        for leading_mingw_branch in (True, False):
            with self.subTest(leading_mingw_branch=leading_mingw_branch):
                with tempfile.TemporaryDirectory(dir=TOOL_DIR) as root:
                    path = self._wrapper_cmake(
                        Path(root),
                        "            ${LIBSPDM_LIB_DIR}/libmemlib.a\n"
                        "            ${LIBSPDM_LIB_DIR}/libmalloclib.a)\n",
                        leading_mingw_branch,
                    )
                    original = path.read_text(encoding="utf-8")
                    bkps_build._apply_linux_spdm_wrapper_malloc_link(root)

                    self.assertEqual(
                        original, path.read_text(encoding="utf-8")
                    )

    @unittest.mock.patch.object(bkps_build.sys, "platform", "linux")
    def test_a_missing_gnu_branch_is_reported(self):
        with tempfile.TemporaryDirectory(dir=TOOL_DIR) as root:
            path = Path(root) / "spdm_wrapper" / "wrapper" / "CMakeLists.txt"
            path.parent.mkdir(parents=True)
            path.write_text(
                "add_library(libspdm_wrapper SHARED ${SOURCES})\n", encoding="utf-8"
            )
            with self.assertRaises(RuntimeError) as raised:
                bkps_build._apply_linux_spdm_wrapper_malloc_link(root)

        self.assertIn("GNU compiler branch", str(raised.exception))

    def test_executable_jar_selection_excludes_plain_jar(self):
        with tempfile.TemporaryDirectory(dir=TOOL_DIR) as root:
            output = Path(root)
            plain = output / "bkps-1.0.0-plain.jar"
            executable = output / "bkps-1.0.0.jar"
            plain.write_bytes(b"plain")
            executable.write_bytes(b"executable")
            selected = bkps_build._require_bkps_executable_jar(
                [str(output / "bkps*.jar")]
            )
            self.assertEqual(Path(selected), executable)


if __name__ == "__main__":
    unittest.main()

"""Regression checks for the standalone Visual Studio Build Tools setup flow."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


TOOL_ROOT = Path(__file__).resolve().parents[1]
SETUP_BAT = TOOL_ROOT / "setup.bat"


class WindowsBuildToolsSetupTests(unittest.TestCase):
    def _create_complete_build_tools_tree(self, temp_dir: str) -> Path:
        install_root = Path(temp_dir) / "BuildTools"
        build_dir = install_root / "VC" / "Auxiliary" / "Build"
        cmake = (
            install_root
            / "Common7"
            / "IDE"
            / "CommonExtensions"
            / "Microsoft"
            / "CMake"
            / "CMake"
            / "bin"
            / "cmake.exe"
        )
        native_bin = (
            install_root
            / "VC"
            / "Tools"
            / "MSVC"
            / "14.44.35207"
            / "bin"
            / "Hostx64"
            / "x64"
        )

        for path in (
            build_dir / "vcvarsall.bat",
            build_dir / "vcvarsamd64_x86.bat",
            cmake,
            native_bin / "cl.exe",
            native_bin / "nmake.exe",
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()

        version_file = (
            install_root
            / "VC"
            / "Auxiliary"
            / "Build"
            / "Microsoft.VCToolsVersion.default.txt"
        )
        version_file.write_text("14.44.35207\n", encoding="utf-8")

        return build_dir

    def test_setup_declares_only_the_required_build_tools_components(self):
        setup_text = SETUP_BAT.read_text(encoding="utf-8")

        for component in (
            "Microsoft.VisualStudio.Workload.VCTools",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "Microsoft.VisualStudio.Component.VC.CMake.Project",
            "Microsoft.VisualStudio.Component.Windows11SDK.26100",
        ):
            self.assertIn(component, setup_text)

        self.assertIn("Microsoft.VisualStudio.2022.BuildTools", setup_text)
        self.assertIn(":ensure_visual_studio_build_tools", setup_text)
        self.assertIn("--quiet --norestart", setup_text)
        self.assertNotIn("Microsoft.VisualStudio.2022.Community", setup_text)
        self.assertIn("StrawberryPerl.StrawberryPerl", setup_text)
        self.assertIn(r"C:\Strawberry\perl\bin\perl.exe", setup_text)

    @unittest.skipUnless(os.name == "nt", "Windows batch validation")
    def test_check_msvc_accepts_a_complete_external_build_tools_tree(self):
        with tempfile.TemporaryDirectory(
            prefix="bkps vs build tools ", dir=TOOL_ROOT
        ) as temp_dir:
            build_dir = self._create_complete_build_tools_tree(temp_dir)

            environment = os.environ.copy()
            environment["BKPS_VS_BUILD_DIR"] = str(build_dir)
            command = f"{SETUP_BAT} --check-msvc"
            result = subprocess.run(
                [environment.get("COMSPEC", "cmd.exe"), "/d", "/c", command],
                cwd=TOOL_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(
                result.returncode,
                0,
                msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
            )
            self.assertIn("Visual Studio C++ Build Tools check passed", result.stdout)
            self.assertIn(str(build_dir), result.stdout)
            self.assertIn("MSVC compiler version - 14.44.35207", result.stdout)
            self.assertIn("BKPS Boost bootstrap mapping - vc143", result.stdout)
            self.assertIn("BKPS Boost.Build mapping - msvc-14.3", result.stdout)
            self.assertIn("BKPS CMake platform toolset - v143", result.stdout)

    @unittest.skipUnless(os.name == "nt", "Windows batch validation")
    def test_ensure_msvc_returns_to_its_own_mode_handler(self):
        with tempfile.TemporaryDirectory(
            prefix="bkps vs ensure ", dir=TOOL_ROOT
        ) as temp_dir:
            build_dir = self._create_complete_build_tools_tree(temp_dir)
            environment = os.environ.copy()
            environment["BKPS_VS_BUILD_DIR"] = str(build_dir)
            command = f"{SETUP_BAT} --ensure-msvc"
            result = subprocess.run(
                [environment.get("COMSPEC", "cmd.exe"), "/d", "/c", command],
                cwd=TOOL_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(
                result.returncode,
                0,
                msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
            )
            self.assertIn(str(build_dir), result.stdout)
            self.assertIn("Visual Studio C++ Build Tools setup passed", result.stdout)
            self.assertNotIn("Tool path discovery", result.stdout)

    @unittest.skipUnless(os.name == "nt", "Windows batch validation")
    def test_check_java_reads_the_version_from_stderr(self):
        with tempfile.TemporaryDirectory(
            prefix="bkps java ", dir=TOOL_ROOT
        ) as temp_dir:
            fake_bin = Path(temp_dir) / "fake bin"
            fake_bin.mkdir(parents=True)
            fake_java = fake_bin / "java.cmd"
            fake_java.write_text(
                "@echo off\n"
                "if /I \"%~1\"==\"-version\" (\n"
                "  1>&2 echo openjdk version \"17.0.20.1\" 2026-08-18 LTS\n"
                "  exit /b 0\n"
                ")\n"
                "exit /b 0\n",
                encoding="utf-8",
            )

            environment = os.environ.copy()
            environment["PATH"] = str(fake_bin) + os.pathsep + environment["PATH"]
            command = f"{SETUP_BAT} --check-java"
            result = subprocess.run(
                [environment.get("COMSPEC", "cmd.exe"), "/d", "/c", command],
                cwd=TOOL_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(
                result.returncode,
                0,
                msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
            )
            self.assertIn("Java 17+ check passed", result.stdout)
            self.assertIn("17.0.20.1", result.stdout)


if __name__ == "__main__":
    unittest.main()

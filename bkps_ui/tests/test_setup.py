#!/usr/bin/env python3
"""Unit tests for setup.py first-time dependency bootstrap."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOL_DIR = Path(__file__).resolve().parents[1]
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

import setup as setup_mod  # noqa: E402


def setUpModule():
    # Progress messages contain Unicode glyphs; a narrow console codec (cp1252)
    # would turn an incidental print into a UnicodeEncodeError.
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(errors="replace")


class SetupHelperTests(unittest.TestCase):
    def test_print_helpers(self):
        with mock.patch("builtins.print") as printed:
            setup_mod.print_ok("ok")
            setup_mod.print_fail("fail")
            setup_mod.print_warn("warn")
        self.assertEqual(printed.call_count, 3)

    def test_check_python_version_ok(self):
        with mock.patch.object(sys, "version_info", (3, 10, 0)):
            self.assertTrue(setup_mod.check_python_version())

    def test_check_python_version_too_old(self):
        with mock.patch.object(sys, "version_info", (3, 7, 0)):
            self.assertFalse(setup_mod.check_python_version())

    def test_check_system_tools_reports_missing(self):
        def which(name):
            return "/bin/java" if name == "java" else None

        with mock.patch.object(setup_mod.shutil, "which", side_effect=which):
            missing = setup_mod.check_system_tools()
        self.assertTrue(any(item[0] == "psql" for item in missing))
        self.assertFalse(any(item[0] == "java" for item in missing))

    def test_check_system_tools_optional_present(self):
        def which(name):
            return f"/bin/{name}" if name in ("java", "nc") else None

        with mock.patch.object(setup_mod.shutil, "which", side_effect=which):
            missing = setup_mod.check_system_tools()
        self.assertTrue(any(item[0] == "psql" for item in missing))

    def test_install_python_packages_missing_requirements(self):
        with mock.patch.object(setup_mod.os.path, "exists", return_value=False):
            self.assertFalse(setup_mod.install_python_packages())

    def test_install_python_packages_success(self):
        with mock.patch.object(setup_mod.os.path, "exists", return_value=True), \
             mock.patch.object(setup_mod.subprocess, "check_call") as check:
            self.assertTrue(setup_mod.install_python_packages())
            check.assert_called_once()

    def test_install_python_packages_pip_failure(self):
        with mock.patch.object(setup_mod.os.path, "exists", return_value=True), \
             mock.patch.object(
                 setup_mod.subprocess,
                 "check_call",
                 side_effect=subprocess.CalledProcessError(1, "pip"),
             ):
            self.assertFalse(setup_mod.install_python_packages())

    def test_check_python_packages_mixed(self):
        real_import = __import__

        def fake_import(name, *args, **kwargs):
            if name in ("PySide6", "cryptography", "OpenSSL", "Crypto",
                        "docopt", "requests", "packaging", "psycopg2"):
                if name == "docopt":
                    raise ImportError("missing")
                return mock.Mock()
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=fake_import):
            self.assertFalse(setup_mod.check_python_packages())

    def test_print_missing_tools_help(self):
        with mock.patch("builtins.print") as printed:
            setup_mod.print_missing_tools_help([])
            setup_mod.print_missing_tools_help([("java", "Java", "hint")])
        self.assertGreater(printed.call_count, 0)

    def test_main_check_only_ready(self):
        with mock.patch.object(setup_mod, "check_python_version", return_value=True), \
             mock.patch.object(setup_mod, "check_system_tools", return_value=[]), \
             mock.patch.object(setup_mod, "check_python_packages", return_value=True), \
             mock.patch.object(sys, "argv", ["setup.py", "--check-only"]), \
             self.assertRaises(SystemExit) as raised:
            setup_mod.main()
        self.assertEqual(raised.exception.code, 0)

    def test_main_python_too_old(self):
        with mock.patch.object(setup_mod, "check_python_version", return_value=False), \
             mock.patch.object(sys, "argv", ["setup.py"]), \
             self.assertRaises(SystemExit) as raised:
            setup_mod.main()
        self.assertEqual(raised.exception.code, 1)

    def test_main_missing_tools(self):
        with mock.patch.object(setup_mod, "check_python_version", return_value=True), \
             mock.patch.object(
                 setup_mod, "check_system_tools",
                 return_value=[("java", "Java", "hint")],
             ), \
             mock.patch.object(setup_mod, "install_python_packages", return_value=True), \
             mock.patch.object(setup_mod, "check_python_packages", return_value=True), \
             mock.patch.object(sys, "argv", ["setup.py", "--install"]), \
             self.assertRaises(SystemExit) as raised:
            setup_mod.main()
        self.assertEqual(raised.exception.code, 1)

    def test_main_packages_missing_after_install(self):
        with mock.patch.object(setup_mod, "check_python_version", return_value=True), \
             mock.patch.object(setup_mod, "check_system_tools", return_value=[]), \
             mock.patch.object(setup_mod, "install_python_packages", return_value=False), \
             mock.patch.object(sys, "argv", ["setup.py"]), \
             self.assertRaises(SystemExit) as raised:
            setup_mod.main()
        self.assertEqual(raised.exception.code, 1)

    def test_main_install_then_verify(self):
        with mock.patch.object(setup_mod, "check_python_version", return_value=True), \
             mock.patch.object(setup_mod, "check_system_tools", return_value=[]), \
             mock.patch.object(setup_mod, "install_python_packages", return_value=True), \
             mock.patch.object(setup_mod, "check_python_packages", return_value=True), \
             mock.patch.object(sys, "argv", ["setup.py"]), \
             self.assertRaises(SystemExit) as raised:
            setup_mod.main()
        self.assertEqual(raised.exception.code, 0)


if __name__ == "__main__":
    unittest.main()

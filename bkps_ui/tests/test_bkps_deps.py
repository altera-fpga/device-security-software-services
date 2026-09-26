#!/usr/bin/env python3
"""Unit tests for bkps_deps.py (heavy mocks; no real package installs)."""

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

import bkps_deps as d  # noqa: E402
from bkps_config import Config  # noqa: E402


def setUpModule():
    # Progress messages contain Unicode glyphs; a narrow console codec (cp1252)
    # would turn an incidental print into a UnicodeEncodeError.
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(errors="replace")


def RR(code=0, out="", err=""):
    return SimpleNamespace(returncode=code, stdout=out, stderr=err)


def _cfg(root: str) -> Config:
    cfg = Config()
    cfg.bkps_dir = root
    cfg.bkps_repo_dir = os.path.join(root, "repo")
    cfg.profile_name = "agilex5"
    cfg.build_selection = "bkp_only"
    cfg.include_bkp_programmer = False
    cfg.yes = True
    cfg.softhsm_lib_path = ""
    cfg.softhsm_util_path = ""
    cfg.pkcs11_tool_path = ""
    cfg.softhsm_token_label = "tok"
    cfg.softhsm_user_pin = "1234"
    cfg.softhsm_key_label = "key"
    cfg.softhsm_conf_path = ""
    cfg.softhsm_tokens_dir = ""
    os.makedirs(cfg.bkps_repo_dir, exist_ok=True)
    return cfg


class HelperTests(unittest.TestCase):
    def test_small_helpers(self):
        with mock.patch.object(d.subprocess, "run", return_value=RR(0, out="v1\n")):
            self.assertEqual(d._tool_version("git"), "v1")
        with mock.patch.object(d.subprocess, "run", side_effect=OSError()):
            self.assertEqual(d._tool_version("git"), "")
        with mock.patch.object(d.subprocess, "run", return_value=RR(0, out="")):
            self.assertEqual(d._tool_version("git"), "")
        with mock.patch.object(d.subprocess, "run", return_value=RR(0)):
            self.assertTrue(d._python_import_ok("sys"))
        with mock.patch.object(d.subprocess, "run", return_value=RR(1)):
            self.assertFalse(d._python_import_ok("sys"))
        with mock.patch.object(d.subprocess, "run", side_effect=OSError()):
            self.assertFalse(d._python_import_ok("sys"))

        with mock.patch.object(d.subprocess, "run", return_value=RR(0, err='java version "17.0.1"')):
            self.assertTrue(d._check_java_version()[0])
        with mock.patch.object(d.subprocess, "run", return_value=RR(0, err='java version "1.8.0_292"')):
            self.assertFalse(d._check_java_version()[0])
        with mock.patch.object(d.subprocess, "run", return_value=RR(0, err="nope")):
            self.assertEqual(d._check_java_version()[1], "unknown")
        with mock.patch.object(d.subprocess, "run", return_value=RR(0, err='java version "bad"')):
            self.assertFalse(d._check_java_version()[0])
        with mock.patch.object(d.subprocess, "run", side_effect=OSError()):
            self.assertEqual(d._check_java_version()[1], "not found")

        with mock.patch.object(d, "command_exists", return_value=False):
            self.assertFalse(d._create_dummy_truststore())
        with mock.patch.object(d, "command_exists", return_value=True), \
             mock.patch.object(d.os.path, "isfile", return_value=True), \
             mock.patch.object(d.subprocess, "run", return_value=RR(0)):
            self.assertTrue(d._create_dummy_truststore())
        with mock.patch.object(d, "command_exists", return_value=True), \
             mock.patch.object(d.os.path, "isfile", return_value=False), \
             mock.patch.object(d.subprocess, "run", return_value=RR(0)):
            self.assertTrue(d._create_dummy_truststore())
        with mock.patch.object(d, "command_exists", return_value=True), \
             mock.patch.object(d.os.path, "isfile", return_value=False), \
             mock.patch.object(d.subprocess, "run", return_value=RR(1, err=b"fail")):
            self.assertFalse(d._create_dummy_truststore())
        with mock.patch.object(d, "command_exists", return_value=True), \
             mock.patch.object(d.os.path, "isfile", return_value=True), \
             mock.patch.object(d.subprocess, "run", side_effect=[RR(1), RR(0)]):
            self.assertTrue(d._create_dummy_truststore())

        with mock.patch("builtins.open", mock.mock_open(read_data="ID=ubuntu\n")), \
             mock.patch.object(d.os, "name", "posix"):
            self.assertEqual(d._detect_distro(), "debian")
        with mock.patch("builtins.open", mock.mock_open(read_data="ID=fedora\n")), \
             mock.patch.object(d.os, "name", "posix"):
            self.assertEqual(d._detect_distro(), "rhel")
        with mock.patch.object(d.os, "name", "nt"):
            self.assertEqual(d._detect_distro(), "windows")
        with mock.patch("builtins.open", side_effect=OSError()), \
             mock.patch.object(d.os, "name", "posix"), \
             mock.patch.object(d.shutil, "which", return_value=None):
            self.assertEqual(d._detect_distro(), "unknown")
        with mock.patch("builtins.open", side_effect=OSError()), \
             mock.patch.object(d.os, "name", "posix"), \
             mock.patch.object(d.shutil, "which", side_effect=lambda x: "/bin/dnf" if x == "dnf" else None):
            self.assertEqual(d._detect_distro(), "rhel")

        with mock.patch.object(d, "run", return_value=RR(0)), \
             mock.patch.object(d, "stream", return_value=0):
            d._install_system_packages(["curl"], "debian")
            d._install_system_packages(["curl"], "rhel")
            d._install_system_packages(["curl"], "unknown")

        with mock.patch.object(d.os.path, "isdir", return_value=True), \
             mock.patch.object(d.os, "listdir", return_value=["PG_VERSION"]):
            d._ensure_postgresql_rhel()
        with mock.patch.object(d.os.path, "isdir", return_value=False), \
             mock.patch.object(d.subprocess, "run", return_value=RR(0)):
            d._ensure_postgresql_rhel()
        with mock.patch.object(d.os.path, "isdir", return_value=False), \
             mock.patch.object(d.subprocess, "run", side_effect=[RR(1, err="e"), RR(0), RR(0), RR(0)]):
            d._ensure_postgresql_rhel()
        with mock.patch.object(d.os.path, "isdir", return_value=False), \
             mock.patch.object(d.subprocess, "run", side_effect=[RR(1, err="e"), RR(1, err="e")]):
            d._ensure_postgresql_rhel()
        with mock.patch.object(d.os.path, "isdir", return_value=False), \
             mock.patch.object(
                 d.subprocess, "run",
                 side_effect=[RR(0), RR(0), RR(1, err="start fail")],
             ):
            d._ensure_postgresql_rhel()

        self.assertEqual(d._docker_prompt_answer(["x"]), "y\n")
        self.assertEqual(d._docker_prompt_answer([]), "n\n")
        self.assertEqual(d._linux_build_invocation("/s", "group-shim")[0], "sg")
        self.assertEqual(d._linux_build_invocation("/s", "ready")[0], "bash")
        self.assertTrue(any(t[0] == "aria2c" for t in d.REQUIRED_TOOLS))

        with mock.patch.object(d, "run", return_value=RR(0)):
            self.assertTrue(d._docker_ps(["docker", "ps"])[0])
        with mock.patch.object(d, "run", return_value=RR(1, err="permission denied")):
            self.assertFalse(d._docker_ps(["docker", "ps"])[0])

        with mock.patch.object(d, "command_exists", return_value=False):
            self.assertEqual(d._docker_build_status()[0], "unusable")
        with mock.patch.object(d, "command_exists", return_value=True), \
             mock.patch.object(d, "_docker_ps", return_value=(True, "")):
            self.assertEqual(d._docker_build_status()[0], "ready")
        with mock.patch.object(d, "command_exists", side_effect=lambda t: t in ("docker", "sg")), \
             mock.patch.object(d, "_docker_ps", side_effect=[(False, "perm"), (True, "")]):
            self.assertEqual(d._docker_build_status()[0], "group-shim")
        with mock.patch.object(d, "command_exists", side_effect=lambda t: t == "docker"), \
             mock.patch.object(d, "_docker_ps", return_value=(False, "x")):
            self.assertEqual(d._docker_build_status()[0], "unusable")

        # grp is Unix-only, so stand in for it rather than importing it.
        grp_stub = SimpleNamespace(getgrnam=lambda _name: SimpleNamespace(gr_mem=["u"]))
        with mock.patch.dict(sys.modules, {"grp": grp_stub}):
            self.assertTrue(d._in_docker_group("u"))
            with mock.patch.object(grp_stub, "getgrnam", side_effect=KeyError()):
                self.assertFalse(d._in_docker_group("u"))

        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("same")
            name = f.name
        self.assertTrue(d._linux_build_script_unchanged(name, "same"))
        self.assertFalse(d._linux_build_script_unchanged(name, "diff"))
        os.unlink(name)
        self.assertFalse(d._linux_build_script_unchanged(name, "x"))


class CheckInstallEnsureTests(unittest.TestCase):
    def test_check_install_ensure(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            lib = Path(td, "libsofthsm2.so")
            lib.write_bytes(b"x")
            util = Path(td, "softhsm2-util")
            util.write_text("#!/bin/sh\n")
            p11 = Path(td, "pkcs11-tool")
            p11.write_text("#!/bin/sh\n")
            conf = Path(td, "softhsm2.conf")
            conf.write_text("directories.tokendir = /tmp/tokens\n")
            cfg.softhsm_lib_path = str(lib)
            cfg.softhsm_util_path = str(util)
            cfg.pkcs11_tool_path = str(p11)
            cfg.softhsm_conf_path = str(conf)

            with mock.patch.object(d, "command_exists", return_value=True), \
                 mock.patch.object(d, "_tool_version", return_value="1"), \
                 mock.patch.object(d, "_check_java_version", return_value=(True, "17")), \
                 mock.patch.object(d, "_python_import_ok", return_value=True), \
                 mock.patch.object(d, "_selected_container_components", return_value=[]), \
                 mock.patch.object(d, "is_windows", False), \
                 mock.patch.object(d, "configure_windows_softhsm_defaults"):
                missing, *_ = d.check_dependencies(cfg)
                self.assertEqual(missing, 0)

            # java bad + missing tools + containers + soft tools + softHSM gaps
            cfg2 = _cfg(td)
            cfg2.softhsm_lib_path = "/no/lib.so"
            cfg2.softhsm_util_path = ""
            cfg2.pkcs11_tool_path = ""
            cfg2.softhsm_token_label = ""
            cfg2.softhsm_user_pin = ""
            cfg2.softhsm_key_label = ""
            with mock.patch.object(d, "command_exists", return_value=False), \
                 mock.patch.object(d, "_tool_version", return_value=""), \
                 mock.patch.object(d, "_check_java_version", return_value=(False, "8")), \
                 mock.patch.object(d, "_python_import_ok", return_value=False), \
                 mock.patch.object(d, "_selected_container_components", return_value=["FCS"]), \
                 mock.patch.object(d, "_docker_build_status", return_value=("unusable", "x")), \
                 mock.patch.object(d, "detect_system_softhsm_library", return_value=""), \
                 mock.patch.object(d.shutil, "which", return_value=None), \
                 mock.patch.object(d, "is_windows", False), \
                 mock.patch.object(d, "configure_windows_softhsm_defaults"):
                missing, *_ = d.check_dependencies(cfg2, last_check=True)
                self.assertGreater(missing, 0)

            # java present but bad version when command_exists True
            with mock.patch.object(d, "command_exists", return_value=True), \
                 mock.patch.object(d, "_tool_version", return_value="1"), \
                 mock.patch.object(d, "_check_java_version", return_value=(False, "8")), \
                 mock.patch.object(d, "_python_import_ok", return_value=True), \
                 mock.patch.object(d, "_selected_container_components", return_value=["FCS"]), \
                 mock.patch.object(d, "_docker_build_status", return_value=("ready", "")), \
                 mock.patch.object(d, "is_windows", False), \
                 mock.patch.object(d, "configure_windows_softhsm_defaults"):
                cfg.softhsm_lib_path = str(lib)
                cfg.softhsm_util_path = str(util)
                cfg.pkcs11_tool_path = str(p11)
                missing, tools, *_ = d.check_dependencies(cfg)
                self.assertIn("java", tools)

            # group-shim container path + which softHSM tools
            with mock.patch.object(d, "command_exists", return_value=True), \
                 mock.patch.object(d, "_tool_version", return_value="1"), \
                 mock.patch.object(d, "_check_java_version", return_value=(True, "17")), \
                 mock.patch.object(d, "_python_import_ok", return_value=True), \
                 mock.patch.object(d, "_selected_container_components", return_value=["FCS"]), \
                 mock.patch.object(d, "_docker_build_status", return_value=("group-shim", "x")), \
                 mock.patch.object(d.shutil, "which", return_value="/bin/x"), \
                 mock.patch.object(d, "is_windows", False), \
                 mock.patch.object(d, "configure_windows_softhsm_defaults"):
                cfg3 = _cfg(td)
                cfg3.softhsm_lib_path = str(lib)
                cfg3.softhsm_conf_path = str(conf)
                cfg3.softhsm_util_path = ""
                cfg3.pkcs11_tool_path = ""
                missing, *_ = d.check_dependencies(cfg3)
                self.assertEqual(missing, 0)

            # empty lib path with detect
            with mock.patch.object(d, "command_exists", return_value=True), \
                 mock.patch.object(d, "_tool_version", return_value="1"), \
                 mock.patch.object(d, "_check_java_version", return_value=(True, "17")), \
                 mock.patch.object(d, "_python_import_ok", return_value=True), \
                 mock.patch.object(d, "_selected_container_components", return_value=[]), \
                 mock.patch.object(d, "detect_system_softhsm_library", return_value=str(lib)), \
                 mock.patch.object(d, "is_windows", False), \
                 mock.patch.object(d, "configure_windows_softhsm_defaults"):
                cfg4 = _cfg(td)
                cfg4.softhsm_lib_path = ""
                cfg4.softhsm_conf_path = str(conf)
                cfg4.softhsm_util_path = str(util)
                cfg4.pkcs11_tool_path = str(p11)
                missing, *_ = d.check_dependencies(cfg4)
                self.assertEqual(missing, 0)

            # windows skip tools path
            with mock.patch.object(d, "is_windows", True), \
                 mock.patch.object(d, "_refresh_windows_path"), \
                 mock.patch.object(d, "configure_windows_softhsm_defaults"), \
                 mock.patch.object(d, "command_exists", return_value=True), \
                 mock.patch.object(d, "_tool_version", return_value="1"), \
                 mock.patch.object(d, "_check_java_version", return_value=(True, "17")), \
                 mock.patch.object(d, "_python_import_ok", return_value=True):
                cfg5 = _cfg(td)
                cfg5.profile_name = "other"
                missing, *_ = d.check_dependencies(cfg5)
                self.assertEqual(missing, 0)

            with mock.patch.object(d, "check_dependencies", return_value=(0, [], [], [], [])):
                self.assertTrue(d.ensure_dependencies(cfg))
            with mock.patch.object(
                d, "check_dependencies",
                side_effect=[(1, ["a"], [], [], []), (0, [], [], [], [])],
            ), mock.patch.object(d, "install_dependencies"):
                self.assertTrue(d.ensure_dependencies(cfg))
            with mock.patch.object(
                d, "check_dependencies", return_value=(1, ["a"], [], [], [])
            ), mock.patch.object(d, "install_dependencies"):
                self.assertFalse(d.ensure_dependencies(cfg))

            with mock.patch.object(d, "check_dependencies", return_value=(0, [], [], [], [])):
                d.install_dependencies(cfg)

            with mock.patch.object(
                d, "check_dependencies",
                return_value=(1, ["curl", "java"], ["requests"], ["softhsm2-util"], []),
            ), mock.patch.object(d.os, "name", "posix"), \
               mock.patch.object(d, "_detect_distro", return_value="debian"), \
               mock.patch("bkps_database.authenticate_sudo"), \
               mock.patch.object(d, "_install_system_packages"), \
               mock.patch.object(d, "_install_softhsm"), \
               mock.patch.object(d, "_create_dummy_truststore", return_value=True), \
               mock.patch.object(d, "_selected_container_components", return_value=["FCS"]), \
               mock.patch.object(d, "_ensure_container_engine", return_value=True), \
               mock.patch.object(d, "stream", return_value=0):
                d.install_dependencies(cfg)

            with mock.patch.object(
                d, "check_dependencies",
                return_value=(1, ["psql"], [], [], []),
            ), mock.patch.object(d.os, "name", "posix"), \
               mock.patch.object(d, "_detect_distro", return_value="rhel"), \
               mock.patch("bkps_database.authenticate_sudo"), \
               mock.patch.object(d, "_install_system_packages"), \
               mock.patch.object(d, "_ensure_postgresql_rhel"), \
               mock.patch.object(d, "_selected_container_components", return_value=[]), \
               mock.patch.object(d, "_create_dummy_truststore", return_value=True), \
               mock.patch.object(d, "stream", return_value=0):
                d.install_dependencies(cfg)

            with mock.patch.object(
                d, "check_dependencies", return_value=(1, ["curl"], [], [], [])
            ), mock.patch.object(d, "_detect_distro", return_value="windows"), \
               mock.patch.object(d, "_install_dependencies_windows"):
                d.install_dependencies(cfg)


class SoftHsmWindowsContainerBuildTests(unittest.TestCase):
    def test_softhsm_windows_container_build(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with mock.patch.object(d.shutil, "which", return_value=None), \
                 mock.patch.object(d, "_install_system_packages") as inst:
                cfg_soft = _cfg(td)
                cfg_soft.softhsm_conf_path = ""
                cfg_soft.softhsm_tokens_dir = os.path.join(td, "tok2")
                d._install_softhsm(cfg_soft, "debian")
                self.assertTrue(inst.called)
                self.assertTrue(os.path.isfile(cfg_soft.softhsm_conf_path))
            # already installed + existing conf
            conf = Path(td, "softhsm2.conf")
            conf.write_text("x")
            cfg.softhsm_conf_path = str(conf)
            cfg.softhsm_tokens_dir = os.path.join(td, "tokens")
            with mock.patch.object(d.shutil, "which", return_value="/bin/x"):
                d._install_softhsm(cfg, "rhel")

            with mock.patch.object(d.shutil, "which", return_value="winget"), \
                 mock.patch.object(d, "_refresh_windows_path"), \
                 mock.patch.object(d, "_check_java_version", return_value=(False, "")), \
                 mock.patch.object(d.subprocess, "run", return_value=RR(0)), \
                 mock.patch.object(d, "_create_dummy_truststore", return_value=True):
                d._install_dependencies_windows(cfg)
            # postgres install + service start loop
            def which_pg(name):
                if name == "winget":
                    return "winget"
                if name == "psql":
                    return None
                return f"/bin/{name}"
            with mock.patch.object(d.shutil, "which", side_effect=which_pg), \
                 mock.patch.object(d, "_refresh_windows_path"), \
                 mock.patch.object(d, "_check_java_version", return_value=(True, "17")), \
                 mock.patch.object(
                     d.subprocess, "run",
                     side_effect=[RR(0), RR(1), RR(0)],  # winget ok, net start fail, net start ok
                 ), \
                 mock.patch.object(d, "_create_dummy_truststore", return_value=True):
                d._install_dependencies_windows(cfg)
            with mock.patch.object(d.shutil, "which", return_value=None), \
                 mock.patch.object(d, "_refresh_windows_path"):
                d._install_dependencies_windows(cfg)
            # winget present, tools already on PATH
            with mock.patch.object(d.shutil, "which", return_value="/bin/x"), \
                 mock.patch.object(d, "_refresh_windows_path"), \
                 mock.patch.object(d, "_check_java_version", return_value=(True, "17")), \
                 mock.patch.object(d, "_create_dummy_truststore", return_value=True):
                d._install_dependencies_windows(cfg)
            # winget install failures
            with mock.patch.object(d.shutil, "which", side_effect=lambda n: "winget" if n == "winget" else None), \
                 mock.patch.object(d, "_refresh_windows_path"), \
                 mock.patch.object(d, "_check_java_version", return_value=(False, "")), \
                 mock.patch.object(d.subprocess, "run", return_value=RR(1)), \
                 mock.patch.object(d, "_create_dummy_truststore", return_value=False):
                d._install_dependencies_windows(cfg)

            # refresh windows path — mock filesystem probes
            with mock.patch.object(d.os, "name", "nt"), \
                 mock.patch.dict(
                     os.environ,
                     {
                         "ProgramFiles": r"C:\Program Files",
                         "ProgramFiles(x86)": r"C:\Program Files (x86)",
                         "LOCALAPPDATA": r"C:\Users\u\AppData\Local",
                         "PATH": r"C:\Windows",
                         "ProgramW6432": r"C:\Program Files",
                     },
                     clear=False,
                 ), \
                 mock.patch.object(d.os.path, "isdir", return_value=True), \
                 mock.patch.object(d.os, "listdir", return_value=["Python312"]), \
                 mock.patch.object(
                     d.subprocess, "run",
                     return_value=RR(0, out=r"C:\Java\bin" + "\n"),
                 ):
                d._refresh_windows_path()
            with mock.patch.object(d.os, "name", "posix"):
                d._refresh_windows_path()

            with mock.patch.object(d, "_docker_build_status", return_value=("ready", "")):
                self.assertTrue(d._ensure_container_engine(cfg, "debian"))
            with mock.patch.object(d, "_docker_build_status", return_value=("group-shim", "x")):
                self.assertTrue(d._ensure_container_engine(cfg, "debian"))
            with mock.patch.object(d, "_docker_build_status", return_value=("unusable", "x")):
                self.assertFalse(d._ensure_container_engine(cfg, "unknown"))

            with mock.patch.object(d, "_docker_build_status", side_effect=[
                     ("unusable", "x"), ("ready", "")
                 ]), \
                 mock.patch("bkps_database.authenticate_sudo"), \
                 mock.patch.object(d, "command_exists", side_effect=[False, True]), \
                 mock.patch.object(d, "_install_system_packages"), \
                 mock.patch.object(d, "run", return_value=RR(0)), \
                 mock.patch.object(d, "_in_docker_group", return_value=True), \
                 mock.patch.object(d.getpass, "getuser", return_value="u"):
                self.assertTrue(d._ensure_container_engine(cfg, "debian"))

            with mock.patch.object(d, "_docker_build_status", side_effect=[
                     ("unusable", "x"), ("group-shim", "x")
                 ]), \
                 mock.patch("bkps_database.authenticate_sudo"), \
                 mock.patch.object(d, "command_exists", return_value=True), \
                 mock.patch.object(d, "run", return_value=RR(0)), \
                 mock.patch.object(d, "_in_docker_group", return_value=False), \
                 mock.patch.object(d.getpass, "getuser", return_value="u"):
                self.assertTrue(d._ensure_container_engine(cfg, "rhel"))

            with mock.patch.object(d, "_docker_build_status", return_value=("unusable", "x")), \
                 mock.patch("bkps_database.authenticate_sudo"), \
                 mock.patch.object(d, "command_exists", return_value=False), \
                 mock.patch.object(d, "_install_system_packages"), \
                 mock.patch.object(d.getpass, "getuser", return_value="u"):
                self.assertFalse(d._ensure_container_engine(cfg, "debian"))

            with mock.patch.object(d, "_docker_build_status", side_effect=[
                     ("unusable", "x"), ("unusable", "still")
                 ]), \
                 mock.patch("bkps_database.authenticate_sudo"), \
                 mock.patch.object(d, "command_exists", return_value=True), \
                 mock.patch.object(d, "run", return_value=RR(1)), \
                 mock.patch.object(d, "_in_docker_group", return_value=True), \
                 mock.patch.object(d.getpass, "getuser", return_value="u"):
                self.assertFalse(d._ensure_container_engine(cfg, "debian"))

            # build native linux
            script = Path(cfg.bkps_repo_dir, "build_ubuntu.sh")
            script.write_text("#!/bin/bash\necho hi\n")
            with mock.patch.object(d, "_detect_distro", return_value="debian"), \
                 mock.patch.object(d, "_selected_build_options", return_value=("full", True)), \
                 mock.patch.object(d, "check_native_dependencies", return_value={"openssl": False}), \
                 mock.patch.object(d, "_linux_docker_prerequisite", return_value="ready"), \
                 mock.patch.object(d, "_container_build_components", return_value=[]), \
                 mock.patch.object(d, "stream", return_value=0), \
                 mock.patch.object(d, "_linux_build_script_unchanged", return_value=True):
                self.assertTrue(d.build_native_dependencies(cfg, force=True))
            with mock.patch.object(d, "_detect_distro", return_value="debian"), \
                 mock.patch.object(d, "_selected_build_options", return_value=("bkp_only", False)), \
                 mock.patch.object(d, "check_native_dependencies", return_value={"openssl": False}), \
                 mock.patch.object(d, "_linux_docker_prerequisite", return_value="ready"), \
                 mock.patch.object(d, "_container_build_components", return_value=[]), \
                 mock.patch.object(d, "stream", return_value=0), \
                 mock.patch.object(d, "_linux_build_script_unchanged", return_value=True):
                self.assertTrue(d.build_native_dependencies(cfg, force=True))
            with mock.patch.object(d, "_detect_distro", return_value="debian"), \
                 mock.patch.object(d, "_selected_build_options", return_value=("full", True)), \
                 mock.patch.object(d, "check_native_dependencies", return_value={"openssl": True}):
                self.assertTrue(d.build_native_dependencies(cfg))
            with mock.patch.object(d, "_detect_distro", return_value="debian"), \
                 mock.patch.object(d, "_selected_build_options", return_value=("full", True)), \
                 mock.patch.object(d, "check_native_dependencies", return_value={"openssl": False}), \
                 mock.patch.object(d, "_linux_docker_prerequisite", return_value="unusable"):
                self.assertFalse(d.build_native_dependencies(cfg, force=True))
            with mock.patch.object(d, "_detect_distro", return_value="debian"), \
                 mock.patch.object(d, "_selected_build_options", return_value=("full", True)), \
                 mock.patch.object(d, "check_native_dependencies", return_value={"openssl": False}), \
                 mock.patch.object(d, "_linux_docker_prerequisite", return_value="ready"), \
                 mock.patch.object(d, "_container_build_components", return_value=[]), \
                 mock.patch.object(d, "stream", return_value=1), \
                 mock.patch.object(d, "_linux_build_script_unchanged", return_value=True):
                self.assertFalse(d.build_native_dependencies(cfg, force=True))
            with mock.patch.object(d, "_detect_distro", return_value="debian"), \
                 mock.patch.object(d, "_selected_build_options", return_value=("full", True)), \
                 mock.patch.object(d, "check_native_dependencies", return_value={"openssl": False}), \
                 mock.patch.object(d, "_linux_docker_prerequisite", return_value="ready"), \
                 mock.patch.object(d, "_container_build_components", return_value=[]), \
                 mock.patch.object(d, "stream", return_value=0), \
                 mock.patch.object(d, "_linux_build_script_unchanged", return_value=False):
                self.assertFalse(d.build_native_dependencies(cfg, force=True))
            script.unlink()
            with mock.patch.object(d, "_detect_distro", return_value="debian"), \
                 mock.patch.object(d, "_selected_build_options", return_value=("full", True)), \
                 mock.patch.object(d, "check_native_dependencies", return_value={"openssl": False}):
                self.assertFalse(d.build_native_dependencies(cfg, force=True))
            with mock.patch.object(d, "_detect_distro", return_value="windows"), \
                 mock.patch.object(d, "build_windows_repository", return_value=True):
                self.assertTrue(d.build_native_dependencies(cfg))

            # check_native_dependencies
            deps = Path(cfg.bkps_repo_dir, "dependencies")
            for name in ("openssl", "boost", "libcurl", "gtest", "libspdm"):
                p = deps / name
                p.mkdir(parents=True, exist_ok=True)
                (p / "f").write_text("x")
            with mock.patch.object(d, "_detect_distro", return_value="debian"):
                st = d.check_native_dependencies(cfg.bkps_repo_dir, include_programmer=True)
                self.assertTrue(all(st.values()))
                st2 = d.check_native_dependencies(cfg.bkps_repo_dir, include_programmer=False)
                self.assertNotIn("boost", st2)
            with mock.patch.object(d, "_detect_distro", return_value="windows"), \
                 mock.patch.object(d.os.path, "isfile", return_value=True):
                st3 = d.check_native_dependencies(cfg.bkps_repo_dir)
                self.assertTrue(st3)

            # windows helpers
            with mock.patch.dict(os.environ, {"BKPS_VS_BUILD_DIR": r"C:\VS\Build"}, clear=False), \
                 mock.patch.object(d.os.path, "isfile", return_value=True):
                self.assertTrue(d._windows_visual_studio_build_dir())
            with mock.patch.dict(os.environ, {
                "BKPS_VS_BUILD_DIR": "",
                "VSINSTALLDIR": r"C:\VS",
                "ProgramFiles(x86)": r"C:\PF86",
            }, clear=False), \
                 mock.patch.object(
                     d.os.path, "isfile",
                     side_effect=lambda p: ("vswhere" in str(p)) or ("vcvars" in str(p)),
                 ), \
                 mock.patch.object(
                     d.subprocess, "run",
                     return_value=RR(0, out=r"C:\VS\Community" + "\n"),
                 ):
                self.assertTrue(d._windows_visual_studio_build_dir())
            with mock.patch.object(d, "_windows_executable", return_value=""):
                self.assertFalse(d._windows_reg_query_works())
            with mock.patch.object(d, "_windows_executable", return_value=r"C:\reg.exe"), \
                 mock.patch.object(
                     d.subprocess, "run",
                     return_value=RR(0, out="KitsRoot10 REG_SZ x"),
                 ):
                self.assertTrue(d._windows_reg_query_works())
            with mock.patch.object(d, "_windows_executable", return_value=r"C:\reg.exe"), \
                 mock.patch.object(d.subprocess, "run", side_effect=OSError()):
                self.assertFalse(d._windows_reg_query_works())
            self.assertTrue(d._windows_registry_query_shim_dir())
            with mock.patch.object(d.shutil, "which", return_value="/bin/java"), \
                 mock.patch.object(d.os.path, "isfile", return_value=True):
                self.assertTrue(d._windows_executable("java", []))
            with mock.patch.object(d.shutil, "which", return_value=None), \
                 mock.patch.object(d.os.path, "isfile", return_value=True):
                self.assertTrue(d._windows_executable("java", [r"C:\java.exe"]))
            with mock.patch.object(d.shutil, "which", return_value=None), \
                 mock.patch.object(d.os.path, "isfile", return_value=False):
                self.assertEqual(d._windows_executable("java", [r"C:\java.exe"]), "")
            self.assertTrue(d._selected_build_options(cfg))
            self.assertIsInstance(d._selected_container_components(cfg), list)
            self.assertIsInstance(d._container_build_components("full", True), list)

            with mock.patch.object(d, "_docker_build_status", return_value=("group-shim", "x")):
                self.assertTrue(d._ensure_container_engine(cfg, "debian"))
            with mock.patch.object(d, "_docker_build_status", return_value=("unusable", "x")):
                self.assertFalse(d._ensure_container_engine(cfg, "alpine"))

            script.write_text("#!/bin/bash\n")
            with mock.patch.object(d, "_detect_distro", return_value="debian"), \
                 mock.patch.object(d, "_selected_build_options", return_value=("full", True)), \
                 mock.patch.object(d, "check_native_dependencies", return_value={"openssl": False}), \
                 mock.patch.object(d, "_linux_docker_prerequisite", return_value="ready"), \
                 mock.patch.object(d, "_container_build_components", return_value=[]), \
                 mock.patch.object(d, "stream", side_effect=RuntimeError("boom")):
                self.assertFalse(d.build_native_dependencies(cfg, force=True))

            with mock.patch.object(d, "_detect_distro", return_value="debian"), \
                 mock.patch.object(d, "_selected_build_options", return_value=("bkp_only", False)), \
                 mock.patch.object(
                     d, "check_native_dependencies",
                     return_value={"openssl": False, "libspdm": True},
                 ), \
                 mock.patch.object(d, "_linux_docker_prerequisite", return_value="ready"), \
                 mock.patch.object(d, "_container_build_components", return_value=[]), \
                 mock.patch.object(d, "stream", return_value=1), \
                 mock.patch.object(d, "_linux_build_script_unchanged", return_value=True):
                self.assertFalse(d.build_native_dependencies(cfg, force=True))

            with mock.patch.object(d, "_container_build_components", return_value=["FCS"]), \
                 mock.patch.object(d, "_docker_build_status", return_value=("unusable", "x")), \
                 mock.patch.object(d, "_ensure_container_engine", return_value=False), \
                 mock.patch.object(d, "_detect_distro", return_value="debian"):
                self.assertEqual(d._linux_docker_prerequisite(cfg, "full", True), "unusable")
            with mock.patch.object(d, "_container_build_components", return_value=["FCS"]), \
                 mock.patch.object(
                     d, "_docker_build_status",
                     side_effect=[("unusable", "x"), ("ready", "")],
                 ), \
                 mock.patch.object(d, "_ensure_container_engine", return_value=True), \
                 mock.patch.object(d, "_detect_distro", return_value="debian"):
                self.assertEqual(d._linux_docker_prerequisite(cfg, "full", True), "ready")

            with mock.patch.object(
                d, "check_dependencies",
                return_value=(1, [], [], ["softhsm2-util"], []),
            ), mock.patch.object(d.os, "name", "posix"), \
               mock.patch.object(d, "_detect_distro", return_value="debian"), \
               mock.patch("bkps_database.authenticate_sudo"), \
               mock.patch.object(d, "_selected_container_components", return_value=[]), \
               mock.patch.object(d, "_create_dummy_truststore", return_value=True), \
               mock.patch.object(d, "_install_softhsm"), \
               mock.patch.object(d, "stream", return_value=0):
                d.install_dependencies(cfg)


if __name__ == "__main__":
    unittest.main()

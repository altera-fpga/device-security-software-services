#!/usr/bin/env python3
"""Unit tests for bkps_build with mocked git/gradle/zip/network."""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

TOOL_DIR = Path(__file__).resolve().parents[1]
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

import bkps_build as build  # noqa: E402


def setUpModule():
    # Progress messages contain Unicode glyphs; a narrow console codec (cp1252)
    # would turn an incidental print into a UnicodeEncodeError.
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(errors="replace")


def _cfg(root: str, **kwargs):
    base = dict(
        bkps_dir=root,
        bkps_repo_dir=os.path.join(root, "repo"),
        bkps_release="auto",
        bkps_build_mode="bkp_only",
        include_bkp_programmer=False,
        bkps_version="",
        local_override_gradle_zip="",
        bkps_jar_path="",
        bkps_sql_path="",
        libspdm_wrapper_path="",
        bkps_admin_tools_dir="",
        bundle_zip="",
        bundle_zip_password="",
        config_file=os.path.join(root, "c.conf"),
    )
    base.update(kwargs)
    return SimpleNamespace(**base)


class HelperTests(unittest.TestCase):
    def test_gradle_zip_override(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            build._apply_local_gradle_zip_override(cfg)
            cfg.local_override_gradle_zip = "/missing.zip"
            with self.assertRaises(RuntimeError):
                build._apply_local_gradle_zip_override(cfg)

            z = Path(td, "g.zip")
            z.write_bytes(b"z")
            cfg.local_override_gradle_zip = str(z)
            cfg.bkps_repo_dir = os.path.join(td, "repo")
            build._apply_local_gradle_zip_override(cfg)  # no props

            props = Path(td, "repo", "gradle", "wrapper")
            props.mkdir(parents=True)
            pfile = props / "gradle-wrapper.properties"
            pfile.write_text("distributionUrl=https://example/gradle.zip\nother=1\n")
            build._apply_local_gradle_zip_override(cfg)
            build._apply_local_gradle_zip_override(cfg)  # unchanged

    def test_spdm_malloc_link(self):
        with mock.patch.object(build.sys, "platform", "win32"):
            build._apply_linux_spdm_wrapper_malloc_link("/x")
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(build.sys, "platform", "linux"):
            path = Path(td, "spdm_wrapper", "wrapper")
            path.mkdir(parents=True)
            cmake = path / "CMakeLists.txt"
            with self.assertRaises(RuntimeError):
                build._apply_linux_spdm_wrapper_malloc_link(td)
            cmake.write_text("no branch")
            with self.assertRaises(RuntimeError):
                build._apply_linux_spdm_wrapper_malloc_link(td)
            cmake.write_text(
                "if(CMAKE_COMPILER_IS_GNUCXX)\n"
                "  target_link_libraries(foo bar)\n"
                "endif()\n"
            )
            build._apply_linux_spdm_wrapper_malloc_link(td)
            build._apply_linux_spdm_wrapper_malloc_link(td)  # already linked
            cmake.write_text(
                "if(CMAKE_COMPILER_IS_GNUCXX)\n"
                "  something else\n"
                "endif()\n"
            )
            with self.assertRaises(RuntimeError):
                build._apply_linux_spdm_wrapper_malloc_link(td)
            cmake.write_text(
                "if(CMAKE_COMPILER_IS_GNUCXX)\n"
                "  target_link_libraries(foo bar\n"
            )
            with self.assertRaises(RuntimeError):
                build._apply_linux_spdm_wrapper_malloc_link(td)

    def test_extract_zip_and_gradle_opts(self):
        with tempfile.TemporaryDirectory() as td:
            zpath = os.path.join(td, "a.zip")
            dest = os.path.join(td, "out")
            with zipfile.ZipFile(zpath, "w") as zf:
                zf.writestr("f.txt", "hi")
            with mock.patch.object(build.shutil, "which", return_value="/bin/unzip"), \
                 mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0)):
                build._extract_zip(zpath, dest)
            with mock.patch.object(build.shutil, "which", return_value="/bin/unzip"), \
                 mock.patch(
                     "subprocess.run",
                     return_value=subprocess.CompletedProcess([], 2),
                 ):
                build._extract_zip(zpath, dest, password="pw")
            with mock.patch.object(build.shutil, "which", return_value=None):
                build._extract_zip(zpath, dest)
            with mock.patch.object(build.shutil, "which", return_value=None), \
                 mock.patch("zipfile.ZipFile.extractall", side_effect=RuntimeError("encrypted")):
                with self.assertRaises(RuntimeError):
                    build._extract_zip(zpath, dest, password="")

            repo = Path(td, "repo")
            repo.mkdir()
            (repo / "gradle.properties").write_text("org.gradle.jvmargs=-Xmx1g\n")
            self.assertIn("-Xmx1g", build._read_gradle_jvmargs(str(repo)))
            with mock.patch("builtins.open", side_effect=OSError()):
                self.assertEqual(build._read_gradle_jvmargs(str(repo)), "")

            with mock.patch.dict(
                os.environ,
                {
                    "http_proxy": "http://user:pass@proxy:8080",
                    "https_proxy": "https://proxy2:8443",
                },
            ):
                opts = build._proxy_java_opts()
                self.assertIn("proxyHost", opts)
            with mock.patch.dict(os.environ, {"http_proxy": ":::bad"}, clear=False):
                build._proxy_java_opts()
            self.assertIn("daemon=false", build._build_gradle_opts(str(repo)))

    def test_fetch_releases_and_artifacts(self):
        payload = b'[{"name":"release/1"},{"name":"master"},{"name":"x"}]'
        cm = mock.MagicMock()
        cm.__enter__.return_value.read.return_value = payload
        with mock.patch("urllib.request.urlopen", return_value=cm):
            rel = build.fetch_bkps_releases()
            self.assertEqual(rel[0], "master")
        with mock.patch("urllib.request.urlopen", side_effect=OSError()):
            self.assertEqual(build.fetch_bkps_releases(), [])

        with tempfile.TemporaryDirectory() as td:
            sql = Path(td, "s.sql")
            sql.write_text("CREATE TABLE t(i int);")
            self.assertTrue(build._sql_has_ddl(str(sql)))
            sql.write_text("-- none")
            self.assertFalse(build._sql_has_ddl(str(sql)))
            self.assertFalse(build._sql_has_ddl("/no"))

            jar = Path(td, "bkps.jar")
            jar.write_bytes(b"j")
            plain = Path(td, "bkps-plain.jar")
            plain.write_bytes(b"p")
            self.assertTrue(
                build._require_newest_artifact("JAR", [str(Path(td, "bkps*.jar"))]).endswith(".jar")
            )
            with self.assertRaises(RuntimeError):
                build._require_newest_artifact("X", [str(Path(td, "none*"))])
            self.assertTrue(
                build._require_bkps_executable_jar([str(Path(td, "bkps*.jar"))]).endswith("bkps.jar")
            )
            with self.assertRaises(RuntimeError):
                build._require_bkps_executable_jar([str(Path(td, "none*"))])

            sql.write_text("CREATE TABLE t(i int);")
            schema = build._find_sql_schema(td, td)
            self.assertTrue(schema)
            self.assertTrue(build._require_sql_schema(td, td))
            sql.unlink()
            with self.assertRaises(RuntimeError):
                build._require_sql_schema(td, td)

            with mock.patch.object(build.sys, "platform", "linux"):
                (Path(td, "gradlew")).write_text("#!/bin/sh")
                self.assertTrue(build._project_gradle_executable(td))
                Path(td, "gradlew").unlink()
                with mock.patch.object(build.shutil, "which", return_value="/usr/bin/gradle"):
                    self.assertTrue(build._project_gradle_executable(td))
                with mock.patch.object(build.shutil, "which", return_value=None):
                    self.assertEqual(build._project_gradle_executable(td), "")


class BuildFlowTests(unittest.TestCase):
    def test_build_jar_sql_and_ensure_schema(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            with self.assertRaises(RuntimeError):
                build._build_bkps_jar_and_sql(cfg)
            bkps = Path(td, "repo", "bkps")
            bkps.mkdir(parents=True)
            with mock.patch.object(build, "_project_gradle_executable", return_value=""), \
                 self.assertRaises(RuntimeError):
                build._build_bkps_jar_and_sql(cfg)

            # Both names, so the lookup succeeds whichever platform runs the suite.
            (Path(td, "repo", "gradlew")).write_text("x")
            (Path(td, "repo", "gradlew.bat")).write_text("x")
            cfg.bkps_version = "1.0"
            with mock.patch.object(build, "stream", return_value=1):
                with self.assertRaises(RuntimeError):
                    build._build_bkps_jar_and_sql(cfg)
            with mock.patch.object(build, "stream", return_value=0), \
                 mock.patch.object(build, "_require_bkps_executable_jar", return_value="j"), \
                 mock.patch.object(build, "_require_sql_schema", return_value="s"):
                build._build_bkps_jar_and_sql(cfg)

            with mock.patch.object(build, "_find_sql_schema", return_value="found"):
                build._ensure_bkps_sql_schema(cfg)
            with mock.patch.object(build, "_find_sql_schema", return_value=""), \
                 mock.patch.object(build, "_project_gradle_executable", return_value=""), \
                 self.assertRaises(RuntimeError):
                build._ensure_bkps_sql_schema(cfg)
            with mock.patch.object(build, "_find_sql_schema", return_value=""), \
                 mock.patch.object(build, "_project_gradle_executable", return_value="g"), \
                 mock.patch.object(build, "stream", return_value=1), \
                 self.assertRaises(RuntimeError):
                build._ensure_bkps_sql_schema(cfg)
            with mock.patch.object(build, "_find_sql_schema", return_value=""), \
                 mock.patch.object(build, "_project_gradle_executable", return_value="g"), \
                 mock.patch.object(build, "stream", return_value=0), \
                 mock.patch.object(build, "_build_gradle_opts", return_value=""):
                cfg.bkps_version = "2"
                build._ensure_bkps_sql_schema(cfg)

    def test_ensure_wrapper_and_validate(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            Path(td, "repo", "bkps").mkdir(parents=True)
            Path(td, "repo", "dependencies").mkdir()
            so = Path(td, "repo", "bkps", "libspdm_wrapper.so")
            so.write_bytes(b"x")
            with mock.patch.object(build.sys, "platform", "linux"), \
                 mock.patch.object(build, "build_native_dependencies", return_value=True), \
                 mock.patch.object(build, "_validate_spdm_wrapper"), \
                 mock.patch.object(build, "_ensure_bkps_sql_schema"), \
                 mock.patch.object(
                     build, "_find_libspdm_wrapper_candidates",
                     return_value=[str(so)],
                 ):
                build._ensure_agilex5_spdm_wrapper(cfg)

            with mock.patch.object(build.sys, "platform", "linux"), \
                 mock.patch.object(build, "build_native_dependencies", return_value=False):
                with self.assertRaises(RuntimeError):
                    build._ensure_agilex5_spdm_wrapper(cfg)

            with mock.patch.object(build.sys, "platform", "win32"), \
                 mock.patch.object(build, "build_native_dependencies", return_value=False):
                with self.assertRaises(RuntimeError):
                    build._ensure_agilex5_spdm_wrapper(cfg)

            dll = Path(td, "w.dll")
            dll.write_bytes(b"x")
            with mock.patch.object(build.sys, "platform", "win32"), \
                 mock.patch.object(build, "build_native_dependencies", return_value=True), \
                 mock.patch.object(
                     build, "_find_libspdm_wrapper_candidates", return_value=[str(dll)]
                 ), \
                 mock.patch.object(build, "_validate_spdm_wrapper"), \
                 mock.patch.object(build, "_ensure_bkps_sql_schema"):
                build._ensure_agilex5_spdm_wrapper(cfg)

            with mock.patch.object(build.sys, "platform", "win32"), \
                 mock.patch.object(build, "build_native_dependencies", return_value=True), \
                 mock.patch.object(
                     build, "_find_libspdm_wrapper_candidates", return_value=[]
                 ):
                with self.assertRaises(RuntimeError):
                    build._ensure_agilex5_spdm_wrapper(cfg)

            with mock.patch.object(build.sys, "platform", "linux"), \
                 mock.patch.object(build, "build_native_dependencies", return_value=True), \
                 mock.patch.object(
                     build, "_find_libspdm_wrapper_candidates", return_value=[]
                 ):
                with self.assertRaises(RuntimeError):
                    build._ensure_agilex5_spdm_wrapper(cfg)

            lib = mock.Mock()
            lib.libspdm_get_context_size_w = mock.Mock(return_value=16)
            for name in (
                "set_callbacks",
                "libspdm_get_context_size_w",
                "libspdm_prepare_context_w",
                "libspdm_send_receive_data_w",
            ):
                setattr(lib, name, mock.Mock(return_value=16) if "size" in name else mock.Mock())
            lib.libspdm_get_context_size_w.return_value = 16
            with mock.patch.object(build.sys, "platform", "linux"), \
                 mock.patch("ctypes.CDLL", return_value=lib):
                build._validate_spdm_wrapper(str(so))
            with mock.patch.object(build.sys, "platform", "linux"), \
                 mock.patch("ctypes.CDLL", side_effect=OSError("x")):
                with self.assertRaises(RuntimeError):
                    build._validate_spdm_wrapper(str(so))
            bad = mock.Mock(spec=[])
            with mock.patch.object(build.sys, "platform", "linux"), \
                 mock.patch("ctypes.CDLL", return_value=bad):
                with self.assertRaises(RuntimeError):
                    build._validate_spdm_wrapper(str(so))
            lib2 = mock.Mock()
            for name in (
                "set_callbacks",
                "libspdm_get_context_size_w",
                "libspdm_prepare_context_w",
                "libspdm_send_receive_data_w",
            ):
                setattr(lib2, name, mock.Mock())
            lib2.libspdm_get_context_size_w.return_value = 0
            with mock.patch.object(build.sys, "platform", "linux"), \
                 mock.patch("ctypes.CDLL", return_value=lib2):
                with self.assertRaises(RuntimeError):
                    build._validate_spdm_wrapper(str(so))

    def test_install_wrapper_files_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            cfg.libspdm_wrapper_path = os.path.join(td, "existing.so")
            Path(cfg.libspdm_wrapper_path).write_bytes(b"x")
            build._install_libspdm_wrapper(cfg, td)
            cfg.libspdm_wrapper_path = ""
            build._install_libspdm_wrapper(cfg, td)
            so = Path(td, "libspdm_wrapper.so")
            so.write_bytes(b"x")
            with mock.patch.object(
                build, "_find_libspdm_wrapper_candidates", return_value=[str(so)]
            ):
                build._install_libspdm_wrapper(cfg, td)
                build._install_libspdm_wrapper(cfg, td)

            jar = Path(td, "src", "bkps.jar")
            sql = Path(td, "src", "bkps.sql")
            wrap = Path(td, "src", "w.so")
            admin = Path(td, "src", "admin")
            jar.parent.mkdir(parents=True)
            jar.write_bytes(b"j")
            sql.write_text("CREATE TABLE t(i int);")
            wrap.write_bytes(b"w")
            admin.mkdir()
            (admin / "runner.py").write_text("x")
            dest_root = os.path.join(td, "dest")
            for kwargs in (
                dict(bkps_sql_path=str(sql), libspdm_wrapper_path=str(wrap),
                     bkps_admin_tools_dir=str(admin)),
                dict(bkps_jar_path=str(jar), libspdm_wrapper_path=str(wrap),
                     bkps_admin_tools_dir=str(admin)),
                dict(bkps_jar_path=str(jar), bkps_sql_path=str(sql),
                     bkps_admin_tools_dir=str(admin)),
                dict(bkps_jar_path=str(jar), bkps_sql_path=str(sql),
                     libspdm_wrapper_path=str(wrap)),
            ):
                with self.assertRaises(ValueError):
                    build.install_from_files(_cfg(dest_root, **kwargs))
            cfg2 = _cfg(
                dest_root,
                bkps_jar_path=str(jar),
                bkps_sql_path=str(sql),
                libspdm_wrapper_path=str(wrap),
                bkps_admin_tools_dir=str(admin),
            )
            build.install_from_files(cfg2, parent_step=1)
            with self.assertRaises(FileNotFoundError):
                build.install_from_files(
                    _cfg(dest_root, bkps_jar_path="/no.jar", bkps_sql_path=str(sql),
                         libspdm_wrapper_path=str(wrap),
                         bkps_admin_tools_dir=str(admin))
                )
            with self.assertRaises(FileNotFoundError):
                build.install_from_files(
                    _cfg(dest_root, bkps_jar_path=str(jar), bkps_sql_path="/no.sql",
                         libspdm_wrapper_path=str(wrap),
                         bkps_admin_tools_dir=str(admin))
                )
            with self.assertRaises(FileNotFoundError):
                build.install_from_files(
                    _cfg(dest_root, bkps_jar_path=str(jar), bkps_sql_path=str(sql),
                         libspdm_wrapper_path="/no.so",
                         bkps_admin_tools_dir=str(admin))
                )
            with self.assertRaises(FileNotFoundError):
                build.install_from_files(
                    _cfg(dest_root, bkps_jar_path=str(jar), bkps_sql_path=str(sql),
                         libspdm_wrapper_path=str(wrap),
                         bkps_admin_tools_dir="/noadmin")
                )

            zpath = os.path.join(td, "bundle.zip")
            with zipfile.ZipFile(zpath, "w") as zf:
                zf.writestr("nested/bkps.jar", b"j")
                zf.writestr("nested/bkps.sql", "CREATE TABLE t(i int);")
                zf.writestr("nested/admin-tools/runner.py", "r")
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w") as inner:
                    inner.writestr("inner.txt", "i")
                zf.writestr("nested/inner.zip", buf.getvalue())
            dest = os.path.join(td, "install")
            cfg3 = _cfg(dest, bundle_zip=zpath, bundle_zip_password="")
            with mock.patch.object(build.shutil, "which", return_value=None):
                build.install_bundle_zip(cfg3)
            with self.assertRaises(FileNotFoundError):
                build.install_bundle_zip(_cfg(td, bundle_zip="/no.zip"))

            # flatten wrapper + no jar/sql/admin warnings
            dest2 = os.path.join(td, "install2")
            z2 = os.path.join(td, "empty.zip")
            with zipfile.ZipFile(z2, "w") as zf:
                zf.writestr("onlydir/x.txt", "x")
            cfg4 = _cfg(dest2, bundle_zip=z2)
            with mock.patch.object(build.shutil, "which", return_value=None):
                build.install_bundle_zip(cfg4)

    @mock.patch.object(build.sys, "platform", "linux")
    def test_build_all(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td, bkps_dir="")
            with mock.patch.object(
                build, "normalize_project_paths",
                side_effect=ValueError("empty"),
            ):
                with self.assertRaises(RuntimeError):
                    build.build_all(cfg)

            repo = Path(td, "repo")
            cfg = _cfg(td, bkps_repo_dir=str(repo), bkps_release="",
                       bkps_build_mode="full", include_bkp_programmer=True)
            with mock.patch.object(
                build, "normalize_project_paths",
                return_value=(td, str(repo)),
            ), mock.patch.object(build, "run"), \
               mock.patch.object(
                   build, "get_output",
                   return_value="  origin/master\n",
               ), \
               mock.patch.object(build, "_apply_local_gradle_zip_override"), \
               mock.patch.object(build, "_apply_linux_spdm_wrapper_malloc_link"), \
               mock.patch.object(build, "_ensure_agilex5_spdm_wrapper"), \
               mock.patch.object(
                   build, "_require_bkps_executable_jar", return_value="/j.jar"
               ), \
               mock.patch.object(
                   build, "_require_sql_schema", return_value="/s.sql"
               ), \
               mock.patch.object(
                   build, "_find_libspdm_wrapper_candidates",
                   return_value=[os.path.join(td, "libspdm_wrapper.so")],
               ), \
               mock.patch.object(build, "install_from_files"):
                Path(td, "libspdm_wrapper.so").write_bytes(b"x")
                (repo / "admintools" / "bkps").mkdir(parents=True)
                build.build_all(cfg)

            # clone path with explicit release checkout
            new_repo = os.path.join(td, "clone_repo")
            cfg_clone = _cfg(td, bkps_repo_dir=new_repo, bkps_release="release/x")
            with mock.patch.object(
                build, "normalize_project_paths",
                return_value=(td, new_repo),
            ), mock.patch.object(build, "run"), \
               mock.patch.object(build, "get_output", return_value="origin/release/x\n"), \
               mock.patch.object(build, "_apply_local_gradle_zip_override"), \
               mock.patch.object(build, "_apply_linux_spdm_wrapper_malloc_link"), \
               mock.patch.object(build, "_ensure_agilex5_spdm_wrapper"), \
               mock.patch.object(
                   build, "_require_bkps_executable_jar", return_value="/j.jar"
               ), \
               mock.patch.object(
                   build, "_require_sql_schema", return_value="/s.sql"
               ), \
               mock.patch.object(
                   build, "_find_libspdm_wrapper_candidates",
                   return_value=[os.path.join(td, "libspdm_wrapper.so")],
               ), \
               mock.patch.object(build, "install_from_files"):
                Path(td, "libspdm_wrapper.so").write_bytes(b"x")
                # create admin after clone is skipped — install mocks handle it;
                # but build_all checks admin on disk under repo
                def run_and_mkdir(cmd, **kwargs):
                    Path(new_repo, "admintools", "bkps").mkdir(parents=True, exist_ok=True)
                    return subprocess.CompletedProcess(cmd, 0)
                with mock.patch.object(build, "run", side_effect=run_and_mkdir):
                    # still need repo to not exist initially — ensure absent
                    build.build_all(cfg_clone)

            # existing repo, no admin
            repo.mkdir(exist_ok=True)
            cfg.bkps_release = "release/x"
            with mock.patch.object(
                build, "normalize_project_paths",
                return_value=(td, str(repo)),
            ), mock.patch.object(build, "_apply_local_gradle_zip_override"), \
               mock.patch.object(build, "_apply_linux_spdm_wrapper_malloc_link"), \
               mock.patch.object(build, "_ensure_agilex5_spdm_wrapper"), \
               mock.patch.object(
                   build, "_require_bkps_executable_jar", return_value="/j.jar"
               ), \
               mock.patch.object(
                   build, "_require_sql_schema", return_value="/s.sql"
               ), \
               mock.patch.object(
                   build, "_find_libspdm_wrapper_candidates", return_value=[]
               ):
                with self.assertRaises(RuntimeError):
                    build.build_all(cfg)

            # existing repo, wrapper ok, admin missing
            so = Path(td, "libspdm_wrapper.so")
            so.write_bytes(b"x")
            shutil = __import__("shutil")
            admin_dir = repo / "admintools"
            if admin_dir.exists():
                shutil.rmtree(admin_dir)
            with mock.patch.object(
                build, "normalize_project_paths",
                return_value=(td, str(repo)),
            ), mock.patch.object(build, "_apply_local_gradle_zip_override"), \
               mock.patch.object(build, "_apply_linux_spdm_wrapper_malloc_link"), \
               mock.patch.object(build, "_ensure_agilex5_spdm_wrapper"), \
               mock.patch.object(
                   build, "_require_bkps_executable_jar", return_value="/j.jar"
               ), \
               mock.patch.object(
                   build, "_require_sql_schema", return_value="/s.sql"
               ), \
               mock.patch.object(
                   build, "_find_libspdm_wrapper_candidates",
                   return_value=[str(so)],
               ):
                with self.assertRaises(RuntimeError):
                    build.build_all(cfg)

            with mock.patch.object(
                build, "normalize_project_paths",
                return_value=(td, str(repo)),
            ), mock.patch.object(build, "run"), \
               mock.patch.object(build, "get_output", return_value=""), \
               mock.patch.object(build, "_apply_local_gradle_zip_override"), \
               mock.patch.object(build, "_apply_linux_spdm_wrapper_malloc_link"):
                cfg2 = _cfg(td, bkps_repo_dir=os.path.join(td, "newrepo"), bkps_release="")
                with self.assertRaises(RuntimeError):
                    build.build_all(cfg2)


if __name__ == "__main__":
    unittest.main()

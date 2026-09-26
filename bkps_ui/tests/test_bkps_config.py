#!/usr/bin/env python3
"""Unit tests for bkps_config path helpers and config I/O."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOL_DIR = Path(__file__).resolve().parents[1]
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

import bkps_config as cfg_mod  # noqa: E402
from bkps_config import Config  # noqa: E402


class RuntimeHelpersTests(unittest.TestCase):
    def test_runtime_home_and_default_project_root(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BKPS_PROJECT_ROOT", None)
            home = cfg_mod._runtime_home()
            self.assertTrue(home)
            root = cfg_mod._default_project_root()
            self.assertTrue(root.endswith("bkps") or "bkps" in root)

        with mock.patch.dict(os.environ, {"BKPS_PROJECT_ROOT": "~/proj"}):
            expanded = cfg_mod._default_project_root()
            self.assertTrue(os.path.isabs(expanded))

    def test_readable_file_handles_oserror(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "f.txt"
            p.write_text("x")
            self.assertTrue(cfg_mod._readable_file(p))
        bad = Path("/no/such/path/file")
        with mock.patch.object(Path, "is_file", side_effect=PermissionError("denied")):
            self.assertFalse(cfg_mod._readable_file(bad))

    def test_detect_system_softhsm_library_env(self):
        with mock.patch.dict(os.environ, {"SOFTHSM_LIB_PATH": "/tmp/libsofthsm2.so"}):
            self.assertEqual(
                cfg_mod.detect_system_softhsm_library(),
                os.path.abspath("/tmp/libsofthsm2.so"),
            )

    def test_detect_system_softhsm_library_windows_empty(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SOFTHSM_LIB_PATH", None)
            with mock.patch.object(cfg_mod.os, "name", "nt"):
                self.assertEqual(cfg_mod.detect_system_softhsm_library(), "")

    def test_detect_system_softhsm_library_search(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            libdir = root / "softhsm"
            libdir.mkdir()
            lib = libdir / "libsofthsm2.so"
            lib.write_bytes(b"x")
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("SOFTHSM_LIB_PATH", None)
                found = cfg_mod.detect_system_softhsm_library(search_roots=[root])
            self.assertEqual(found, str(lib.resolve()))

    def test_detect_system_softhsm_library_oserror_and_unreadable(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("SOFTHSM_LIB_PATH", None)
                with mock.patch.object(Path, "glob", side_effect=OSError("boom")):
                    self.assertEqual(
                        cfg_mod.detect_system_softhsm_library(search_roots=[root]),
                        "",
                    )

            lib = root / "libsofthsm2.so"
            lib.write_bytes(b"x")
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("SOFTHSM_LIB_PATH", None)
                with mock.patch.object(cfg_mod, "_readable_file", return_value=False):
                    self.assertEqual(
                        cfg_mod.detect_system_softhsm_library(search_roots=[root]),
                        "",
                    )

            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("SOFTHSM_LIB_PATH", None)
                with mock.patch.object(cfg_mod, "_readable_file", return_value=True), \
                     mock.patch.object(Path, "resolve", side_effect=OSError("no")):
                    found = cfg_mod.detect_system_softhsm_library(search_roots=[root])
                    self.assertEqual(found, str(lib))


class AesCcertHelpersTests(unittest.TestCase):
    def test_aes_ccert_types_and_lookup(self):
        types = cfg_mod.aes_ccert_types_for_profile("agilex5")
        self.assertIn("EFUSE_WRAPPED_AES_KEY", types)
        unknown = cfg_mod.aes_ccert_types_for_profile("nope")
        self.assertEqual(unknown, cfg_mod._DEFAULT_AES_CCERT_TYPES)

        puf, storage = cfg_mod.aes_ccert_lookup("agilex5", "EFUSE_WRAPPED_AES_KEY")
        self.assertEqual(puf, "INTERNAL")
        self.assertEqual(storage, "EFUSE")
        self.assertTrue(
            cfg_mod.aes_ccert_requires_iv("agilex5", "UDS_EFUSE_WRAPPED_AES_KEY")
        )
        with self.assertRaises(ValueError):
            cfg_mod.aes_ccert_lookup("agilex5", "NOT_A_TYPE")


class ConfigDataclassTests(unittest.TestCase):
    def test_post_init_and_properties(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BKPS_PROJECT_ROOT", None)
            os.environ.pop("BKPS_CONFIG_FILE", None)
            cfg = Config(bkps_dir="", quartus_keys_dir="", cm_provisioning_dir="",
                         bkps_repo_dir="", config_file="")
            self.assertTrue(cfg.bkps_dir)
            self.assertTrue(cfg.tool_root)
            self.assertIn("https://", cfg.bkps_url)
            self.assertTrue(cfg.ca_cert.endswith("bkps_ssl_cert.crt"))
            self.assertTrue(cfg.client_cert.endswith("programmer_bkps_signed.crt"))
            self.assertTrue(cfg.client_key.endswith("programmer_private.pem"))
            cfg.profile_name = "agilex5"
            self.assertIn("Agilex", cfg.device_family)
            self.assertTrue(cfg.build_from_source)
            cfg.profile_name = "unknown_profile"
            self.assertEqual(cfg.device_family, "")
            self.assertTrue(cfg.build_from_source)

        with mock.patch.dict(os.environ, {"BKPS_CONFIG_FILE": "/tmp/custom.conf"}):
            cfg2 = Config(bkps_dir="/p", quartus_keys_dir="/k",
                          cm_provisioning_dir="/c", bkps_repo_dir="/r",
                          config_file="")
            self.assertEqual(cfg2.config_file, os.path.abspath("/tmp/custom.conf"))


class ConfigIoTests(unittest.TestCase):
    def test_resolve_and_normalize_paths(self):
        with tempfile.TemporaryDirectory() as td:
            conf = os.path.join(td, "conf", "x.conf")
            os.makedirs(os.path.dirname(conf))
            cfg = Config()
            cfg.config_file = conf
            cfg.bkps_dir = "project"
            cfg.bkps_repo_dir = ""
            with mock.patch.object(cfg_mod, "detect_embedded_bkps_repo", return_value=""):
                project, repo = cfg_mod.normalize_project_paths(cfg)
            self.assertTrue(project.endswith("project"))
            self.assertTrue(repo.endswith("bkps_repo"))

            cfg.bkps_dir = ""
            with self.assertRaises(ValueError):
                cfg_mod.normalize_project_paths(cfg, require_project=True)
            self.assertEqual(
                cfg_mod.normalize_project_paths(cfg, require_project=False),
                ("", ""),
            )

            abs_path = cfg_mod._resolve_config_path("rel/path", td)
            self.assertTrue(os.path.isabs(abs_path))

    def test_load_and_create_config(self):
        with tempfile.TemporaryDirectory() as td:
            conf = os.path.join(td, "bkps_demo_config.conf")
            Path(conf).write_text(
                "\n".join([
                    "# comment",
                    "USERNAME=tester",
                    "BKPS_DIR=proj",
                    "INCLUDE_BKP_PROGRAMMER=true",
                    "INCLUDE_BKP_PROGRAMMER=maybe",  # invalid bool ignored later overwrite
                    "BADLINE",
                    "AES_CCERT_TYPE=NOT_VALID",
                    "SOFTHSM_LIB_PATH=",
                    "QUARTUS_KEYS_DIR=keys",
                    "",
                ]),
                encoding="utf-8",
            )
            # rewrite with valid bool then invalid separately via load logic
            Path(conf).write_text(
                "\n".join([
                    "# comment",
                    "USERNAME=tester",
                    "BKPS_DIR=proj",
                    "INCLUDE_BKP_PROGRAMMER=yes",
                    "BADLINE",
                    "AES_CCERT_TYPE=NOT_VALID",
                    "SOFTHSM_LIB_PATH=",
                    "QUARTUS_KEYS_DIR=keys",
                    "PROFILE_NAME=agilex5",
                ]),
                encoding="utf-8",
            )
            cfg = Config()
            cfg.config_file = conf
            cfg_mod.load_config(cfg)
            self.assertEqual(cfg.username, "tester")
            self.assertTrue(cfg.include_bkp_programmer)
            self.assertTrue(cfg.bkps_dir.endswith("proj"))

            cfg.aes_ccert_type = "EFUSE_WRAPPED_AES_KEY"
            out = os.path.join(td, "out", "new.conf")
            cfg.config_file = out
            cfg_mod.create_config(cfg)
            self.assertTrue(os.path.isfile(out))
            text = Path(out).read_text(encoding="utf-8")
            self.assertIn("USERNAME=tester", text)
            self.assertIn("INCLUDE_BKP_PROGRAMMER=true", text)

    def test_load_missing_config(self):
        cfg = Config()
        cfg.config_file = "/tmp/does-not-exist-bkps-config.conf"
        cfg_mod.load_config(cfg)

    def test_load_invalid_bool_warning(self):
        with tempfile.TemporaryDirectory() as td:
            conf = os.path.join(td, "c.conf")
            Path(conf).write_text(
                "BKPS_DIR=proj\nINCLUDE_BKP_PROGRAMMER=maybe\n",
                encoding="utf-8",
            )
            cfg = Config()
            cfg.config_file = conf
            cfg_mod.load_config(cfg)

    def test_load_derives_repo_when_empty(self):
        with tempfile.TemporaryDirectory() as td:
            conf = os.path.join(td, "c.conf")
            Path(conf).write_text("BKPS_DIR=proj\n", encoding="utf-8")
            cfg = Config()
            cfg.config_file = conf
            cfg.bkps_repo_dir = ""
            with mock.patch.object(cfg_mod, "detect_embedded_bkps_repo", return_value=""):
                cfg_mod.load_config(cfg)
            self.assertTrue(cfg.bkps_repo_dir.endswith("bkps_repo"))



class EmbeddedRepoDetectionTests(unittest.TestCase):
    def test_detect_embedded_bkps_repo(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tool = root / "bkps_ui"
            tool.mkdir()
            (root / "bkps").mkdir()
            (root / "bkps" / "build.gradle").write_text("// bkps\n", encoding="utf-8")
            self.assertTrue(cfg_mod.is_bkps_source_checkout(root))
            self.assertEqual(
                Path(cfg_mod.detect_embedded_bkps_repo(str(tool))),
                root.resolve(),
            )

            other = root / "tools"
            other.mkdir()
            self.assertEqual(cfg_mod.detect_embedded_bkps_repo(str(other)), "")

            shallow = Path(td, "shallow")
            shallow_tool = shallow / "bkps_ui"
            shallow_tool.mkdir(parents=True)
            (shallow / "bkps").mkdir()
            self.assertFalse(cfg_mod.is_bkps_source_checkout(shallow))
            self.assertEqual(cfg_mod.detect_embedded_bkps_repo(str(shallow_tool)), "")

    def test_normalize_prefers_embedded_when_repo_empty(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td, "dsss")
            (root / "bkps_ui").mkdir(parents=True)
            (root / "bkps").mkdir()
            (root / "build.gradle").write_text("// root\n", encoding="utf-8")
            cfg = Config()
            cfg.config_file = str(Path(td, "x.conf"))
            cfg.bkps_dir = str(Path(td, "project"))
            cfg.bkps_repo_dir = ""
            with mock.patch.object(
                cfg_mod, "detect_embedded_bkps_repo", return_value=str(root)
            ):
                _, repo = cfg_mod.normalize_project_paths(cfg)
            self.assertEqual(repo, str(root))

    def test_explicit_repo_dir_wins_over_embedded(self):
        with tempfile.TemporaryDirectory() as td:
            explicit = os.path.join(td, "custom_checkout")
            cfg = Config()
            cfg.config_file = os.path.join(td, "x.conf")
            cfg.bkps_dir = os.path.join(td, "project")
            cfg.bkps_repo_dir = explicit
            with mock.patch.object(
                cfg_mod, "detect_embedded_bkps_repo",
                return_value=os.path.join(td, "embedded"),
            ):
                _, repo = cfg_mod.normalize_project_paths(cfg)
            self.assertEqual(repo, os.path.abspath(explicit))

if __name__ == "__main__":
    unittest.main()

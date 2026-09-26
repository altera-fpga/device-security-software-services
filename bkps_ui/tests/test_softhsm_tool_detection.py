"""Regression tests for unified SoftHSM and PKCS#11 tool discovery."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
GUI = ROOT / "gui"
for entry in (str(GUI), str(ROOT)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from bkps_config import (  # noqa: E402
    Config,
    detect_system_softhsm_library,
    detect_softhsm_config_path,
    detect_softhsm_tokens_dir,
    load_config,
)
from utils.ui_helpers import find_softhsm_tools  # noqa: E402


class SoftHsmToolDetectionTests(unittest.TestCase):
    def test_linux_setup_checks_multiarch_provider_and_config(self):
        setup_script = (ROOT / "setup.sh").read_text(encoding="utf-8")

        self.assertIn(
            "/usr/lib/*/softhsm/libsofthsm2.so",
            setup_script,
        )
        self.assertIn(
            "SoftHSM PKCS#11 library found",
            setup_script,
        )
        self.assertIn(
            "$HOME/.config/softhsm2/softhsm2.conf",
            setup_script,
        )
        self.assertNotIn("FAILED+=(\"config:", setup_script)

    def test_system_discovery_finds_debian_multiarch_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = (
                root
                / "x86_64-linux-gnu"
                / "softhsm"
                / "libsofthsm2.so"
            )
            provider.parent.mkdir(parents=True)
            provider.write_bytes(b"provider")

            with patch.dict(os.environ, {}, clear=True):
                result = detect_system_softhsm_library([root])

            self.assertTrue(os.path.samefile(result, provider))

    def test_unreadable_candidate_does_not_raise_permission_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = root / "softhsm" / "libsofthsm2.so"
            provider.parent.mkdir(parents=True)
            provider.write_bytes(b"provider")

            with patch.dict(os.environ, {}, clear=True), patch.object(
                Path, "is_file", side_effect=PermissionError(13, "denied")
            ):
                result = detect_system_softhsm_library([root])

            self.assertEqual(result, "")

    def test_config_discovery_prefers_first_existing_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            user_config = root / "user" / "softhsm2.conf"
            system_config = root / "system" / "softhsm2.conf"
            user_config.parent.mkdir(parents=True)
            system_config.parent.mkdir(parents=True)
            user_config.write_text("directories.tokendir = user-tokens\n")
            system_config.write_text("directories.tokendir = system-tokens\n")

            with patch.dict(os.environ, {}, clear=True):
                result = detect_softhsm_config_path(
                    [user_config, system_config]
                )

            self.assertTrue(os.path.samefile(result, user_config))

    def test_token_directory_is_read_from_selected_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp, "softhsm2.conf")
            config.write_text(
                "directories.tokendir = token-store\n",
                encoding="utf-8",
            )

            result = detect_softhsm_tokens_dir(str(config))

            self.assertEqual(result, str(Path(tmp, "token-store")))

    def test_empty_saved_paths_preserve_detected_linux_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tokens = root / "tokens"
            softhsm_config = root / "softhsm2.conf"
            softhsm_config.write_text(
                f"directories.tokendir = {tokens}\n",
                encoding="utf-8",
            )
            project_config = root / "bkps_demo_config.conf"
            project_config.write_text(
                "SOFTHSM_CONF_PATH=\nSOFTHSM_TOKENS_DIR=\n",
                encoding="utf-8",
            )

            with patch.dict(
                os.environ,
                {
                    "SOFTHSM2_CONF": str(softhsm_config),
                    "USER": "test-user",
                },
                clear=True,
            ):
                cfg = Config(config_file=str(project_config))
                load_config(cfg)

            self.assertEqual(cfg.softhsm_conf_path, str(softhsm_config))
            self.assertEqual(cfg.softhsm_tokens_dir, str(tokens))

    def test_explicit_environment_provider_takes_precedence(self):
        with tempfile.TemporaryDirectory() as tmp:
            provider = Path(tmp, "custom", "libsofthsm2.so")
            provider.parent.mkdir(parents=True)
            provider.write_bytes(b"provider")

            with patch.dict(
                os.environ,
                {"SOFTHSM_LIB_PATH": str(provider)},
                clear=True,
            ):
                result = detect_system_softhsm_library()

            self.assertTrue(os.path.samefile(result, provider))

    def test_linux_gui_discovery_uses_system_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            provider = Path(tmp, "libsofthsm2.so")
            provider.write_bytes(b"provider")

            with patch(
                "utils.ui_helpers.sys.platform", "linux"
            ), patch(
                "utils.ui_helpers.detect_system_softhsm_library",
                return_value=str(provider),
            ):
                result = find_softhsm_tools(str(Path(tmp, "project")))

            self.assertTrue(os.path.samefile(result["library"], provider))

    def test_windows_discovery_finds_all_three_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            managed = root / "managed"
            provider = managed / "lib" / "softhsm2-x64.dll"
            utility = managed / "bin" / "softhsm2-util.exe"
            pkcs11 = (
                root
                / "programs"
                / "OpenSC Project"
                / "OpenSC"
                / "tools"
                / "pkcs11-tool.exe"
            )
            for path in (provider, utility, pkcs11):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()

            with patch("utils.ui_helpers.sys.platform", "win32"), patch(
                "utils.ui_helpers.windows_softhsm_root", return_value=str(managed)
            ), patch(
                "utils.ui_helpers.shutil.which", return_value=None
            ), patch.dict(
                os.environ,
                {"ProgramFiles": str(root / "programs")},
                clear=True,
            ):
                result = find_softhsm_tools(str(root / "project"))

            self.assertTrue(os.path.samefile(result["library"], provider))
            self.assertTrue(os.path.samefile(result["softhsm_util"], utility))
            self.assertTrue(os.path.samefile(result["pkcs11_tool"], pkcs11))


if __name__ == "__main__":
    unittest.main()

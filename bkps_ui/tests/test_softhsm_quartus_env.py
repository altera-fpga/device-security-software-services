import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace
from unittest.mock import patch


TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))

from bkps_keys import _qe  # noqa: E402
from bkps_softhsm import (  # noqa: E402
    _quartus_softhsm_env,
    _validate_softhsm_module_for_quartus,
)


class QuartusSoftHsmEnvironmentTests(unittest.TestCase):
    def test_quartus_environment_preserves_provider_settings(self):
        provider_env = {
            "SOFTHSM2_CONF": r"C:\managed\softhsm2.conf",
            "PATH": r"C:\managed\lib;C:\Windows\System32",
        }
        with patch("bkps_softhsm._softhsm_env", return_value=provider_env):
            env = _quartus_softhsm_env(SimpleNamespace())

        self.assertEqual(env["SOFTHSM2_CONF"], provider_env["SOFTHSM2_CONF"])
        self.assertEqual(env["PATH"], provider_env["PATH"])
        self.assertEqual(env["QT_QPA_PLATFORM"], "offscreen")
        self.assertEqual(env["DISPLAY"], "")

    def test_preflight_loads_provider_with_quartus_environment(self):
        with tempfile.TemporaryDirectory() as root:
            provider = Path(root, "softhsm2-x64.dll")
            config = Path(root, "softhsm2.conf")
            provider.write_bytes(b"provider")
            config.write_text("directories.tokendir = tokens\n", encoding="utf-8")
            cfg = SimpleNamespace(
                softhsm_lib_path=str(provider),
                softhsm_conf_path=str(config),
                pkcs11_tool_path="pkcs11-tool",
            )
            child_env = {"SOFTHSM2_CONF": str(config), "PATH": str(root)}
            success = CompletedProcess(["pkcs11-tool"], 0, "Library info", "")

            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch(
                "bkps_softhsm._quartus_softhsm_env", return_value=child_env
            ), patch(
                "bkps_softhsm.run", return_value=success
            ) as run_mock:
                selected = _validate_softhsm_module_for_quartus(cfg)

            self.assertEqual(selected, str(provider))
            self.assertEqual(run_mock.call_args.kwargs["env"], child_env)
            self.assertFalse(run_mock.call_args.kwargs["check"])

    def test_preflight_rejects_missing_softhsm_configuration(self):
        with tempfile.TemporaryDirectory() as root:
            provider = Path(root, "softhsm2-x64.dll")
            provider.write_bytes(b"provider")
            cfg = SimpleNamespace(
                softhsm_lib_path=str(provider),
                softhsm_conf_path="",
                pkcs11_tool_path="pkcs11-tool",
            )

            with patch(
                "bkps_softhsm.configure_windows_softhsm_defaults"
            ), patch(
                "bkps_softhsm._quartus_softhsm_env", return_value={}
            ):
                with self.assertRaisesRegex(RuntimeError, "configuration not found"):
                    _validate_softhsm_module_for_quartus(cfg)


class QuartusOutputRedactionTests(unittest.TestCase):
    def test_qe_redacts_pin_from_quartus_command_echo(self):
        pin = "test-only-sensitive-pin"
        result = CompletedProcess(
            ["quartus_encrypt"],
            1,
            f"Command: quartus_encrypt --module_args=--user_pin={pin}\n",
            f"loader diagnostic repeated {pin}\n",
        )
        cfg = SimpleNamespace(softhsm_user_pin=pin)
        captured = io.StringIO()

        with patch("bkps_keys.subprocess.run", return_value=result), redirect_stdout(
            captured
        ):
            _qe(cfg, ["--module=softHSM"], cwd=str(TOOL_ROOT))

        output = captured.getvalue()
        self.assertNotIn(pin, output)
        self.assertEqual(output.count("[REDACTED]"), 2)


if __name__ == "__main__":
    unittest.main()

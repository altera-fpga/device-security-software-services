"""Regression tests for project-aware GUI state restoration."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
GUI = ROOT / "gui"
for entry in (str(GUI), str(ROOT)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

try:
    from app_window import AppWindow  # noqa: E402
    from config_store import ConfigStore  # noqa: E402
    from pipeline import PIPELINE_STEPS, PipelineState, StepStatus  # noqa: E402

    HAS_QT = True
except ImportError:
    HAS_QT = False


class _FakeSettings:
    values = {}

    def __init__(self, *_args):
        pass

    def value(self, key, default=None):
        return self.values.get(key, default)

    def setValue(self, key, value):
        self.values[key] = value

    def sync(self):
        pass


@unittest.skipUnless(HAS_QT, "PySide6/Qt native libraries unavailable")
class RestartStateTests(unittest.TestCase):
    def setUp(self):
        ConfigStore._instance = None
        _FakeSettings.values = {}

    def test_last_successful_config_path_is_restored(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            config_path = Path(tmp) / "project.conf"
            config_path.write_text("test", encoding="utf-8")

            with patch("config_store.QSettings", _FakeSettings), patch(
                "config_store.load_config"
            ):
                first = ConfigStore()
                first.load(str(config_path))

                second = ConfigStore()
                restored = second.restore_last()

            expected = os.path.abspath(str(config_path))
            self.assertEqual(restored, expected)
            self.assertEqual(second.cfg.config_file, expected)

    def test_completed_setup_restores_installation_and_server(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            project = Path(tmp) / "project"
            keys = project / "keys"
            quartus_keys = project / "quartus_keys"
            cm_dir = project / "cm"
            keys.mkdir(parents=True)
            quartus_keys.mkdir()
            cm_dir.mkdir()
            (project / ".bkps_setup_complete").write_text("1", encoding="utf-8")
            (keys / "super_admin_bkps_signed.crt").write_text(
                "certificate", encoding="utf-8"
            )
            (quartus_keys / "bkps_import_pubkey.pem").write_text(
                "public key", encoding="utf-8"
            )

            cfg = SimpleNamespace(
                bkps_dir=str(project),
                quartus_keys_dir=str(quartus_keys),
                cm_provisioning_dir=str(cm_dir),
                profile_name="agilex5",
            )
            window = SimpleNamespace(
                _store=SimpleNamespace(cfg=cfg),
                pipeline=PipelineState(),
            )

            AppWindow._prime_pipeline_from_disk(window)

            self.assertTrue(window.pipeline.is_group_complete("installation"))
            self.assertTrue(window.pipeline.is_group_complete("server"))
            self.assertTrue(AppWindow._prior_apply_marker(window))

    def test_marker_without_final_artifacts_does_not_unlock_setup(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            project = Path(tmp) / "project"
            project.mkdir()
            (project / ".bkps_setup_complete").write_text("1", encoding="utf-8")
            cfg = SimpleNamespace(
                bkps_dir=str(project),
                quartus_keys_dir=str(project / "quartus_keys"),
                cm_provisioning_dir=str(project / "cm"),
                profile_name="agilex5",
            )
            window = SimpleNamespace(
                _store=SimpleNamespace(cfg=cfg),
                pipeline=PipelineState(),
            )

            AppWindow._prime_pipeline_from_disk(window)

            self.assertFalse(window.pipeline.is_group_complete("installation"))
            self.assertFalse(window.pipeline.is_group_complete("server"))
            self.assertFalse(AppWindow._prior_apply_marker(window))

    def test_completed_stage_three_restores_programmer_step_on_windows(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            project = Path(tmp) / "project"
            quartus_keys = project / "quartus_keys"
            cm_dir = project / "cm"
            quartus_keys.mkdir(parents=True)
            cm_dir.mkdir()

            (project / "config_id.txt").write_text("123", encoding="utf-8")
            (quartus_keys / "signed_aes_efuse.ccert").write_text(
                "certificate", encoding="utf-8"
            )
            for name in (
                "programmer_bkps_signed.crt",
                "programmer_private.pem",
                "programmer.pfx",
            ):
                (quartus_keys / name).write_text(name, encoding="utf-8")
            (cm_dir / "bkp_options.txt").write_text(
                "bkp_cfg_id = 123\n", encoding="utf-8"
            )

            cfg = SimpleNamespace(
                bkps_dir=str(project),
                quartus_keys_dir=str(quartus_keys),
                cm_provisioning_dir=str(cm_dir),
                profile_name="agilex5",
            )
            window = SimpleNamespace(
                _store=SimpleNamespace(cfg=cfg),
                pipeline=PipelineState(),
            )

            with patch("app_window.sys.platform", "win32"):
                AppWindow._prime_pipeline_from_disk(window)

            self.assertEqual(
                window.pipeline.status("configuration", "create_programmer"),
                StepStatus.SUCCESS,
            )
            self.assertTrue(window.pipeline.is_group_complete("configuration"))

    def test_missing_windows_programmer_pfx_keeps_step_pending(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            project = Path(tmp) / "project"
            quartus_keys = project / "quartus_keys"
            cm_dir = project / "cm"
            quartus_keys.mkdir(parents=True)
            cm_dir.mkdir()
            (quartus_keys / "programmer_bkps_signed.crt").write_text(
                "certificate", encoding="utf-8"
            )
            (quartus_keys / "programmer_private.pem").write_text(
                "private key", encoding="utf-8"
            )

            cfg = SimpleNamespace(
                bkps_dir=str(project),
                quartus_keys_dir=str(quartus_keys),
                cm_provisioning_dir=str(cm_dir),
                profile_name="agilex5",
            )
            window = SimpleNamespace(
                _store=SimpleNamespace(cfg=cfg),
                pipeline=PipelineState(),
            )

            with patch("app_window.sys.platform", "win32"):
                AppWindow._prime_pipeline_from_disk(window)

            self.assertEqual(
                window.pipeline.status("configuration", "create_programmer"),
                StepStatus.PENDING,
            )

    def test_partial_installation_greens_completed_steps_with_cascade(self):
        """Stopping after Security Provider must green steps 1–3 on reopen."""
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            project = Path(tmp) / "project"
            keys = project / "keys"
            config = project / "config"
            libs = project / "libs-ext"
            quartus_keys = project / "quartus_keys"
            cm_dir = project / "cm"
            for path in (keys, config, libs, quartus_keys, cm_dir):
                path.mkdir(parents=True)

            (project / "bkps-service.jar").write_bytes(b"jar")
            (config / "application-bouncycastle.yml").write_text(
                "application: {}\n", encoding="utf-8"
            )
            (libs / "bcprov-jdk18on-1.78.1.jar").write_bytes(b"bc")

            cfg = SimpleNamespace(
                bkps_dir=str(project),
                quartus_keys_dir=str(quartus_keys),
                cm_provisioning_dir=str(cm_dir),
                profile_name="agilex5",
                security_provider="bouncycastle",
            )
            window = SimpleNamespace(
                _store=SimpleNamespace(cfg=cfg),
                pipeline=PipelineState(),
            )

            AppWindow._prime_pipeline_from_disk(window)

            for sid in (
                "dependency_setup",
                "repo_setup",
                "security_provider",
            ):
                self.assertEqual(
                    window.pipeline.status("installation", sid),
                    StepStatus.SUCCESS,
                    sid,
                )
            for sid in ("ssl_certs", "bkps_keystore", "bkps_config"):
                self.assertEqual(
                    window.pipeline.status("installation", sid),
                    StepStatus.PENDING,
                    sid,
                )
            self.assertFalse(window.pipeline.is_group_complete("installation"))
            self.assertFalse(window.pipeline.is_group_complete("server"))

    def test_bkp_options_cascades_earlier_configuration_steps(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            project = Path(tmp) / "project"
            quartus_keys = project / "quartus_keys"
            cm_dir = project / "cm"
            quartus_keys.mkdir(parents=True)
            cm_dir.mkdir()
            (cm_dir / "bkp_options.txt").write_text(
                "bkp_cfg_id = 123\n", encoding="utf-8"
            )

            cfg = SimpleNamespace(
                bkps_dir=str(project),
                quartus_keys_dir=str(quartus_keys),
                cm_provisioning_dir=str(cm_dir),
                profile_name="agilex5",
            )
            window = SimpleNamespace(
                _store=SimpleNamespace(cfg=cfg),
                pipeline=PipelineState(),
            )

            AppWindow._prime_pipeline_from_disk(window)

            self.assertTrue(window.pipeline.is_group_complete("configuration"))

    def test_pipeline_reset_prevents_state_leaking_between_projects(self):
        pipeline = PipelineState()
        pipeline.mark_group_success("installation")
        pipeline.mark_group_success("server")

        pipeline.reset()

        for group in ("installation", "server"):
            for step_id, _label in PIPELINE_STEPS[group]:
                self.assertEqual(
                    pipeline.status(group, step_id), StepStatus.PENDING
                )


if __name__ == "__main__":
    unittest.main()

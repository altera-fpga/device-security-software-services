"""Regression tests for the split BKPS Setup installation steps."""

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

from utils.pipeline_spec import PIPELINE_STEPS  # noqa: E402

try:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication  # noqa: E402
    from log_panel import LogPanel  # noqa: E402
    from pipeline_widgets import (  # noqa: E402
        build_server_pipeline_box,
        _dispatch_bkps_repo_setup,
        _dispatch_dependency_setup,
    )

    HAS_QT = True
except ImportError:
    HAS_QT = False


class SetupPipelineSplitTests(unittest.TestCase):
    def test_installation_steps_have_separate_dependency_and_repo_actions(self):
        self.assertEqual(
            PIPELINE_STEPS["installation"][:2],
            [
                ("dependency_setup", "1. Check/Setup Dependencies"),
                ("repo_setup", "2. Setup BKPS Repository"),
            ],
        )

    def test_all_installation_labels_begin_with_an_action(self):
        self.assertEqual(
            [label for _step_id, label in PIPELINE_STEPS["installation"]],
            [
                "1. Check/Setup Dependencies",
                "2. Setup BKPS Repository",
                "3. Install Security Provider",
                "4. Create SSL Certificates",
                "5. Create BKPS Keystore",
                "6. Create BKPS Configuration",
            ],
        )

    def test_server_pipeline_has_no_visible_start_step(self):
        self.assertEqual(
            PIPELINE_STEPS["server"],
            [
                ("db_reset", "1. Initialize / Reset Database"),
                ("super_admin", "2. Create + Activate Super Admin"),
                ("auth_keys", "3. Create Authentication Keys"),
                ("bkps_keys", "4. Configure BKPS Keys"),
            ],
        )


@unittest.skipUnless(HAS_QT, "PySide6/Qt native libraries unavailable")
class SetupPipelineDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_dependency_setup_does_not_clean_or_build_project(self):
        cfg = SimpleNamespace()
        with patch("pipeline_widgets.ensure_dependencies", return_value=True) as deps, \
             patch("pipeline_widgets._clean_installation_all_outputs") as clean, \
             patch("pipeline_widgets.build_all") as build:
            _dispatch_dependency_setup(cfg)
        deps.assert_called_once_with(cfg)
        clean.assert_not_called()
        build.assert_not_called()

    def test_repo_setup_does_not_repeat_dependency_setup(self):
        cfg = SimpleNamespace(
            bkps_dir=os.path.join("X:", "bkps-project"),
            bkps_repo_dir=os.path.join("X:", "bkps-project", "bkps_repo"),
            profile_name="agilex5",
            build_from_source=True,
            bkps_jar_path="",
            bkps_sql_path="",
            libspdm_wrapper_path="",
            bkps_admin_tools_dir="",
        )
        with patch(
            "pipeline_widgets.normalize_project_paths",
            return_value=(cfg.bkps_dir, cfg.bkps_repo_dir),
        ), patch(
            "pipeline_widgets._clean_installation_all_outputs"
        ) as clean, patch(
            "pipeline_widgets.ensure_dependencies"
        ) as deps, patch(
            "pipeline_widgets.build_all"
        ) as build, patch(
            "pipeline_widgets.glob.glob",
            side_effect=[[], [], [os.path.join(cfg.bkps_dir, "bkps.jar")], []],
        ):
            _dispatch_bkps_repo_setup(cfg)
        clean.assert_called_once_with(cfg)
        build.assert_called_once_with(cfg)
        deps.assert_not_called()

    def test_setup_and_database_bootstrap_use_separate_log_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            panel = LogPanel("Setup", log_root=tmp)
            self.assertEqual(os.path.basename(panel._log_file), "setup.log")
            panel.set_title("Database Bootstrap")
            self.assertEqual(
                os.path.basename(panel._log_file),
                "database_bootstrap.log",
            )
            panel.close()

    def _build_server_dispatchers(self):
        cfg = SimpleNamespace(
            bkps_dir="",
            bkps_sql_path="",
            bkps_server_port="8082",
        )
        host = SimpleNamespace(
            cfg=cfg,
            _step_dispatch={},
            _pipe_buttons={},
            _manual_mode={},
            set_manual=lambda *_args: None,
            _run_pipeline_chain_from=lambda *_args: None,
        )
        box = build_server_pipeline_box(host)
        return host, box

    def test_database_reset_stops_server_internally(self):
        host, box = self._build_server_dispatchers()
        calls = unittest.mock.Mock()
        with patch("pipeline_widgets.stop_bkps_server") as stop, patch(
            "pipeline_widgets.reset_database"
        ) as reset:
            calls.attach_mock(stop, "stop")
            calls.attach_mock(reset, "reset")
            host._step_dispatch[("server", "db_reset")](host.cfg)
        self.assertEqual(
            calls.mock_calls,
            [unittest.mock.call.stop(host.cfg), unittest.mock.call.reset(host.cfg)],
        )
        box.close()

    def test_super_admin_starts_server_internally(self):
        host, box = self._build_server_dispatchers()
        calls = unittest.mock.Mock()
        with patch(
            "pipeline_widgets.start_bkps_server", return_value=True
        ) as start, patch(
            "pipeline_widgets.extract_token_from_logs", return_value="token"
        ) as token, patch(
            "pipeline_widgets.create_super_admin"
        ) as create, patch(
            "pipeline_widgets._wait_for_authenticated_ready", return_value=True
        ) as ready:
            calls.attach_mock(start, "start")
            calls.attach_mock(token, "token")
            calls.attach_mock(create, "create")
            calls.attach_mock(ready, "ready")
            host._step_dispatch[("server", "super_admin")](host.cfg)
        self.assertEqual(calls.mock_calls[0], unittest.mock.call.start(host.cfg, ""))
        self.assertEqual(calls.mock_calls[1], unittest.mock.call.token(host.cfg))
        create.assert_called_once_with(host.cfg, "token")
        ready.assert_called_once_with(host.cfg)
        box.close()

    def test_configure_keys_writes_marker_without_restarting_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            host, box = self._build_server_dispatchers()
            host.cfg.bkps_dir = tmp
            marker = os.path.join(tmp, ".bkps_setup_complete")
            with patch("pipeline_widgets.configure_bkps_keys") as configure, patch(
                "pipeline_widgets.stop_bkps_server"
            ) as stop, patch(
                "pipeline_widgets.start_bkps_server", return_value=True
            ) as start:
                host._step_dispatch[("server", "bkps_keys")](host.cfg)
            configure.assert_called_once_with(host.cfg)
            stop.assert_not_called()
            start.assert_not_called()
            self.assertTrue(os.path.isfile(marker))
            box.close()


if __name__ == "__main__":
    unittest.main()

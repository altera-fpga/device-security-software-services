"""Regression tests for the dedicated BKPS server-operations page."""

import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
GUI = ROOT / "gui"
for entry in (str(GUI), str(ROOT)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

try:
    from PySide6.QtWidgets import QApplication, QGroupBox, QPushButton  # noqa: E402
    from app_window import AppWindow  # noqa: E402
    from tabs.tab_debug import DebugTab  # noqa: E402
    from tabs.tab_server_operations import (  # noqa: E402
        ServerOperationsTab,
        start_server_if_needed,
    )

    HAS_QT = True
except ImportError:
    HAS_QT = False


class _Capture:
    def register_thread(self, _callback):
        pass

    def unregister_thread(self):
        pass


@unittest.skipUnless(HAS_QT, "PySide6/Qt native libraries unavailable")
class ServerOperationsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_server_control_panel_is_unnumbered_under_utilities(self):
        labels = [entry[0] for entry in AppWindow._NAV_ENTRIES]
        server_index = labels.index("Server Control Panel")
        utilities_index = next(
            index
            for index, entry in enumerate(AppWindow._NAV_ENTRIES)
            if entry[0] == "__header__" and "Utilities" in entry[1]
        )
        self.assertGreater(server_index, utilities_index)
        self.assertEqual(AppWindow._NAV_ENTRIES[server_index][-1], "utility")
        self.assertNotIn("manual, optional", AppWindow._NAV_ENTRIES[utilities_index][1])
        self.assertFalse(any(
            entry[0] == "__header__" and "Guided Setup" in entry[1]
            for entry in AppWindow._NAV_ENTRIES
        ))

    def test_debug_has_no_duplicate_server_controls(self):
        cfg = SimpleNamespace()
        tab = DebugTab(SimpleNamespace(cfg=cfg), _Capture())
        group_names = {group.title() for group in tab.findChildren(QGroupBox)}
        button_names = {button.text() for button in tab.findChildren(QPushButton)}
        self.assertNotIn("Server Controls", group_names)
        for moved_button in (
            "Stop Server",
            "Check Health",
            "Diagnose JAR",
            "Open Log File",
            "Clear Logs",
        ):
            self.assertNotIn(moved_button, button_names)
        self.assertIn("Setup Validation", group_names)
        self.assertIn("Device Status  (JTAG diagnostics)", group_names)
        self.assertIn("Maintenance", group_names)
        tab.close()

    def test_start_does_not_restart_an_already_running_server(self):
        cfg = SimpleNamespace(bkps_server_port="8082")
        with patch(
            "tabs.tab_server_operations.is_bkps_server_running",
            return_value=True,
        ), patch("tabs.tab_server_operations.start_bkps_server") as start:
            self.assertTrue(start_server_if_needed(cfg))
        start.assert_not_called()

    def test_start_invokes_existing_server_launcher_when_stopped(self):
        cfg = SimpleNamespace(bkps_server_port="8082")
        with patch(
            "tabs.tab_server_operations.is_bkps_server_running",
            return_value=False,
        ), patch(
            "tabs.tab_server_operations.start_bkps_server",
            return_value=True,
        ) as start, patch(
            "tabs.tab_server_operations.apply_server_env_vars"
        ) as apply_env:
            self.assertTrue(start_server_if_needed(cfg, "-Xmx2g", "FOO=1\n"))
        apply_env.assert_called_once_with("FOO=1\n")
        start.assert_called_once_with(cfg, "-Xmx2g")

    def test_start_server_reads_setup_pipeline_launch_settings(self):
        cfg = SimpleNamespace(
            bkps_dir="",
            bkps_server_port="8082",
        )
        tab = ServerOperationsTab(SimpleNamespace(cfg=cfg), _Capture())
        flags = SimpleNamespace(text=lambda: " -Xmx4g ")
        env = SimpleNamespace(toPlainText=lambda: "A=1\n#c\nB=2\n")
        setup = SimpleNamespace(
            _server_extra_flags_edit=flags,
            _server_env_vars_edit=env,
        )
        window = SimpleNamespace(_tab_setup=setup)
        with patch.object(tab, "window", return_value=window), patch.object(
            tab, "run_worker"
        ) as run_worker, patch.object(tab, "_track_operation_worker"), patch.object(
            tab, "_set_operation_buttons_enabled"
        ):
            tab._start_server()
        run_worker.assert_called_once_with(
            start_server_if_needed, cfg, "-Xmx4g", "A=1\n#c\nB=2\n"
        )
        tab.shutdown()
        tab.close()

    def test_controls_unlock_after_config_is_applied(self):
        cfg = SimpleNamespace(
            bkps_dir="",
            bkps_server_port="8082",
        )
        tab = ServerOperationsTab(SimpleNamespace(cfg=cfg), _Capture())
        self.assertFalse(tab._btn_start.isEnabled())
        with patch(
            "tabs.tab_server_operations.is_bkps_server_running",
            return_value=False,
        ):
            tab.on_config_applied()
        self.assertTrue(tab._btn_start.isEnabled())
        self.assertTrue(tab._btn_stop.isEnabled())
        self.assertTrue(tab._btn_health.isEnabled())
        self.assertTrue(tab._btn_diagnose_jar.isEnabled())
        self.assertTrue(tab._btn_clear_logs.isEnabled())
        self.assertEqual(tab._btn_health.text(), "Detailed Health")
        self.assertIn("#55acee", tab._btn_health.styleSheet())
        self.assertIn(str(Path("logs") / "bkps.log"), tab._terminal_path.text())
        tab.shutdown()
        tab.close()

    def test_diagnose_jar_runs_in_server_control_panel(self):
        cfg = SimpleNamespace(
            bkps_dir="",
            bkps_server_port="8082",
        )
        tab = ServerOperationsTab(SimpleNamespace(cfg=cfg), _Capture())
        with patch(
            "tabs.tab_server_operations.diagnose_bkps_jar"
        ) as diagnose, patch.object(tab, "run_worker") as run_worker:
            tab._diagnose_jar()
        run_worker.assert_called_once_with(
            diagnose,
            cfg,
            _buttons=[tab._btn_diagnose_jar],
        )
        tab.shutdown()
        tab.close()

    def test_detailed_health_uses_existing_detailed_health_request(self):
        cfg = SimpleNamespace(
            bkps_dir="",
            bkps_server_port="8082",
        )
        tab = ServerOperationsTab(SimpleNamespace(cfg=cfg), _Capture())
        with patch(
            "tabs.tab_server_operations.check_bkps_health"
        ) as detailed_health, patch.object(tab, "run_worker") as run_worker:
            tab._check_health()
        run_worker.assert_called_once_with(
            detailed_health,
            cfg,
            _buttons=[tab._btn_health],
        )
        tab.shutdown()
        tab.close()


if __name__ == "__main__":
    unittest.main()

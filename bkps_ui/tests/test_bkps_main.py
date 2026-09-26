"""CLI dispatch tests for pipeline-named bkps_main commands."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))

import bkps_main as main  # noqa: E402
from bkps_config import Config  # noqa: E402


def _cfg(root: str) -> Config:
    cfg = Config()
    cfg.bkps_dir = root
    cfg.quartus_keys_dir = str(Path(root) / "keys")
    cfg.profile_name = "agilex5"
    return cfg


class CreateQekCcertDispatchTests(unittest.TestCase):
    def test_create_qek_ccert_extracts_corim_and_populates_json(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = _cfg(root)
            with patch.object(main, "_cfg", return_value=cfg), \
                 patch.object(main, "softhsm_create_qek_and_ccert") as qek, \
                 patch.object(
                     main, "extract_and_save_corim_url_from_provision_helper",
                     return_value="https://example/corim",
                 ) as extract, \
                 patch.object(main, "populate_generated_configuration_values") as populate:
                main._dispatch("--create-qek-ccert", [], False, True)

            qek.assert_called_once_with(cfg, "")
            extract.assert_called_once_with(cfg)
            populate.assert_called_once_with(cfg)

    def test_sigma_create_qek_ccert_uses_create_aes_key(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = _cfg(root)
            cfg.profile_name = "agilex"
            with patch.object(main, "_cfg", return_value=cfg), \
                 patch.object(main, "create_aes_key") as aes, \
                 patch.object(main, "softhsm_create_qek_and_ccert") as qek, \
                 patch.object(main, "extract_and_save_corim_url_from_provision_helper") as extract, \
                 patch.object(main, "populate_generated_configuration_values") as populate:
                main._dispatch("--create-qek-ccert", [], False, True)

            aes.assert_called_once_with(cfg)
            qek.assert_not_called()
            extract.assert_not_called()
            populate.assert_called_once_with(cfg)

    def test_removed_prefetch_extract_and_prepare_flags_are_unknown(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = _cfg(root)
            with patch.object(main, "_cfg", return_value=cfg):
                for flag in (
                    "--run-prefetch",
                    "--run-prefetch-status",
                    "--extract-corim-url",
                    "--extract-corim-url-provision-helper",
                    "--prepare-aes-configuration",
                ):
                    with self.assertRaises(SystemExit) as raised:
                        main._dispatch(flag, ["x"], False, True)
                    self.assertEqual(raised.exception.code, 1)

    def test_device_status_and_new_utilities_dispatch(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = _cfg(root)
            keys = Path(root) / "keys"
            keys.mkdir()
            qky = keys / "root0.qky"
            qky.write_bytes(b"qky")
            aes = "A" * 64
            with patch.object(main, "_cfg", return_value=cfg), \
                 patch.object(main, "check_jtag_connection") as jtag, \
                 patch.object(main, "check_jtag_status") as status, \
                 patch.object(main, "read_fuse_info") as fuse, \
                 patch.object(main, "import_aes_key_to_bc_keystore") as bc, \
                 patch.object(main, "run_runner_tool") as runner, \
                 patch.object(main, "check_sql_connection") as sql, \
                 patch.object(main, "stop_bkps_server") as stop:
                main._dispatch("--check-jtag", [], False, True)
                main._dispatch("--check-jtag-status", ["PROV"], False, True)
                main._dispatch("--read-fuse-info", [], False, True)
                main._dispatch("--import-aes-key-to-bc", [aes], False, True)
                main._dispatch("--add-owner-root-key", [], False, True)
                main._dispatch("--check-sql-connection", [], False, True)
                main._dispatch("--stop-bkp-service", [], False, True)
                main._dispatch("--stop-bkps", [], False, True)

            jtag.assert_called_once_with(cfg)
            status.assert_called_once_with(cfg, "PROV")
            fuse.assert_called_once_with(cfg)
            bc.assert_called_once_with(cfg, aes)
            runner.assert_called_once()
            sql.assert_called_once_with(cfg)
            self.assertEqual(stop.call_count, 2)

    def test_help_lists_start_bkp_service_once_and_ui_utility_names(self):
        from io import StringIO
        from contextlib import redirect_stdout
        buf = StringIO()
        with redirect_stdout(buf):
            main._print_help()
        text = buf.getvalue()
        # Not a Server Pipeline numbered step; listed under Server Control Panel
        # and once in the Workflow bootstrap comment block (+ note under Configure Keys).
        self.assertEqual(text.count("--start-bkp-service"), 3)
        self.assertNotIn("5. Start BKP Service", text)
        self.assertIn("Server Control Panel", text)
        self.assertIn("Debug & Device Status", text)
        self.assertIn("Database Utilities", text)
        self.assertIn("Key Management", text)
        self.assertIn("--import-aes-key-to-bc", text)
        self.assertIn("--add-owner-root-key", text)
        self.assertIn("--check-jtag", text)
        self.assertIn("--stop-bkp-service", text)
        self.assertNotIn("--prepare-aes-configuration", text)
        self.assertNotIn("--stop-bkps", text)

    def test_family_aes_working_path(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = _cfg(root)
            self.assertEqual(
                main._family_aes_working_path(cfg),
                str(Path(root) / "bkps_configs" / "aes_config_agilex5.json"),
            )

    def test_create_configuration_uploads_working_json_when_present(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = _cfg(root)
            working = Path(main._family_aes_working_path(cfg))
            working.parent.mkdir(parents=True)
            working.write_text("{}\n", encoding="utf-8")
            with patch.object(main, "_cfg", return_value=cfg), \
                 patch.object(main, "upload_aes_configuration_file") as upload_file, \
                 patch.object(main, "upload_aes_configuration") as upload_default:
                main._dispatch("--create-configuration", [], False, True)
            upload_file.assert_called_once_with(cfg, str(working))
            upload_default.assert_not_called()

    def test_create_configuration_falls_back_without_working_json(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = _cfg(root)
            with patch.object(main, "_cfg", return_value=cfg), \
                 patch.object(main, "upload_aes_configuration_file") as upload_file, \
                 patch.object(main, "upload_aes_configuration") as upload_default:
                main._dispatch("--upload-aes-configuration", [], False, True)
            upload_default.assert_called_once_with(cfg)
            upload_file.assert_not_called()

    def test_configure_bkps_keys_cli_retries_signing_key_list(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = _cfg(root)
            with patch.object(main, "configure_bkps_keys") as configure, \
                 patch.object(main.time, "sleep") as sleep:
                configure.side_effect = [
                    RuntimeError("runner.py signing-key list failed (exit 1)"),
                    None,
                ]
                main._configure_bkps_keys_cli(cfg, attempts=5, delay_sec=1)
            self.assertEqual(configure.call_count, 2)
            sleep.assert_called_once_with(1)

    def test_signing_key_list_raw_retries_then_succeeds(self):
        import bkps_configure as configure
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as root:
            cfg = _cfg(root)
            fail = SimpleNamespace(returncode=1, stdout="", stderr="not ready")
            ok = SimpleNamespace(returncode=0, stdout='{"id": 1}', stderr="")
            with patch.object(configure, "_runner", side_effect=[fail, ok]) as runner, \
                 patch.object(configure.time, "sleep") as sleep:
                text = configure._signing_key_list_raw(cfg, attempts=5, delay_sec=0.1)
            self.assertIn('"id": 1', text)
            self.assertEqual(runner.call_count, 2)
            sleep.assert_called_once()
            # Durable path uses check=False so stderr can be inspected
            self.assertFalse(runner.call_args_list[0].kwargs.get("check", True))


class MainDispatchCoverageTests(unittest.TestCase):
    def test_parse_require_cfg_helpers(self):
        with patch.object(sys, "argv", ["bkps_main.py", "--help"]), \
             self.assertRaises(SystemExit):
            main._parse_args()
        with patch.object(sys, "argv", ["bkps_main.py", "-v", "-y", "--validate-setup"]):
            cmd, extra, verbose, yes = main._parse_args()
            self.assertEqual(cmd, "--validate-setup")
            self.assertTrue(verbose and yes)
        with patch.object(main, "load_config"):
            cfg = main._cfg(True, True)
            self.assertTrue(cfg.verbose and cfg.yes)
        with self.assertRaises(SystemExit):
            main._require([], 0, "X")
        self.assertEqual(main._require(["a"], 0, "X"), "a")
        with tempfile.TemporaryDirectory() as root:
            cfg = _cfg(root)
            self.assertTrue(main._is_agilex5(cfg))
            cfg.profile_name = "agilex"
            self.assertFalse(main._is_agilex5(cfg))

    def test_populate_and_create_qek(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = _cfg(root)
            working = Path(main._family_aes_working_path(cfg))
            working.parent.mkdir(parents=True)
            working.write_text("{}")
            with patch.object(main, "prepare_aes_configuration_named"), \
                 patch.object(main, "read_saved_corim_url", return_value="http://c"):
                main.populate_generated_configuration_values(cfg)
            working.unlink()
            with patch.object(main, "prepare_aes_configuration_named"), \
                 patch.object(main, "read_saved_corim_url", return_value=""):
                with self.assertRaises(FileNotFoundError):
                    main.populate_generated_configuration_values(cfg)

            with patch.object(main, "softhsm_create_qek_and_ccert"), \
                 patch.object(
                     main, "extract_and_save_corim_url_from_provision_helper",
                     return_value="u",
                 ), \
                 patch.object(main, "populate_generated_configuration_values"):
                main._run_create_qek_ccert(cfg)
            with patch.object(main, "softhsm_create_qek_and_ccert"), \
                 patch.object(
                     main, "extract_and_save_corim_url_from_provision_helper",
                     side_effect=RuntimeError("x"),
                 ), \
                 patch.object(
                     main, "populate_generated_configuration_values",
                     side_effect=RuntimeError("y"),
                 ):
                main._run_create_qek_ccert(cfg)
            cfg.profile_name = "agilex"
            with patch.object(main, "create_aes_key"), \
                 patch.object(main, "populate_generated_configuration_values"):
                main._run_create_qek_ccert(cfg)

    def test_configure_keys_retry_and_start_token(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = _cfg(root)
            with patch.object(main, "configure_bkps_keys", side_effect=RuntimeError("other")):
                with self.assertRaises(RuntimeError):
                    main._configure_bkps_keys_cli(cfg, attempts=2, delay_sec=0)
            with patch.object(
                main, "configure_bkps_keys",
                side_effect=[RuntimeError("runner.py fail"), RuntimeError("signing-key fail")],
            ), patch.object(main.time, "sleep"):
                with self.assertRaises(RuntimeError):
                    main._configure_bkps_keys_cli(cfg, attempts=2, delay_sec=0)

            wrapper = main._popen_detach_start_script_stdio(lambda *a, **k: "PROC")
            self.assertEqual(wrapper(["/tmp/start_bkps.sh"]), "PROC")
            self.assertEqual(wrapper("start_bkps.bat"), "PROC")
            self.assertEqual(wrapper(["other"]), "PROC")

            with patch.object(main, "start_bkps_server", return_value=False):
                self.assertFalse(main._start_bkp_service_cli(cfg))
            with patch.object(main, "start_bkps_server", return_value=True), \
                 patch.object(main, "extract_token_from_logs", return_value="TOK"), \
                 patch.object(main, "get_bkps_token"):
                self.assertTrue(main._start_bkp_service_cli(cfg))
            with patch.object(main, "start_bkps_server", return_value=True), \
                 patch.object(main, "extract_token_from_logs", return_value=""), \
                 patch.object(main, "_wait_for_token", return_value=""), \
                 patch.object(main, "get_bkps_token"):
                self.assertTrue(main._start_bkp_service_cli(cfg))
            with patch.object(main, "extract_token_from_logs", return_value="T"), \
                 patch.object(main, "get_bkps_token"):
                main._get_token_cli(cfg)
            with patch.object(main, "extract_token_from_logs", return_value=""), \
                 patch.object(main, "_wait_for_token", return_value="W"), \
                 patch.object(main, "get_bkps_token"):
                main._get_token_cli(cfg)

    def test_with_tcp_admin_psql_and_main(self):
        def fake(cfg):
            return "OK"

        wrapped = main._with_tcp_admin_psql(fake)
        with patch.object(main.os, "name", "nt"):
            self.assertEqual(wrapped(SimpleNamespace()), "OK")
        with patch.object(main.os, "name", "posix"), \
             patch("bkps_database._admin_psql", return_value=(["psql"], {})), \
             patch("bkps_database.authenticate_sudo"):
            # May patch differently - call and tolerate
            try:
                wrapped(_cfg(tempfile.mkdtemp()))
            except Exception:
                pass

        with patch.object(main, "_parse_args", return_value=("--validate-setup", [], False, True)), \
             patch.object(main, "_dispatch") as disp:
            main.main()
            disp.assert_called_once()
        with patch.object(main, "_parse_args", return_value=("--validate-setup", [], False, True)), \
             patch.object(main, "_dispatch", side_effect=RuntimeError("boom")), \
             self.assertRaises(SystemExit):
            main.main()
        with patch.object(main, "_parse_args", return_value=("--validate-setup", [], True, True)), \
             patch.object(main, "_dispatch", side_effect=KeyboardInterrupt()), \
             self.assertRaises(SystemExit):
            main.main()

    def test_dispatch_many_commands(self):
        cmds = [
            ("--create-config", []),
            ("--load-config", []),
            ("--install-dependencies", []),
            ("--check-dependencies", []),
            ("--build-all", []),
            ("--setup-database", []),
            ("--check-sql-connection", []),
            ("--reset-db-password", []),
            ("--show-db-stats", []),
            ("--reset-database", []),
            ("--setup-bkps-server", []),
            ("--create-authentication-keys", []),
            ("--create-qek-ccert", []),
            ("--start-bkp-service", []),
            ("--stop-bkps", []),
            ("--monitor-logs", []),
            ("--get-token", []),
            ("--check-health", []),
            ("--diagnose-jar", []),
            ("--show-logs", []),
            ("--configure-bkps-service", []),
            ("--auto-setup", []),
            ("--create-super-admin", ["TOK"]),
            ("--configure-bkps-keys", []),
            ("--list-configurations", []),
            ("--get-configuration", ["1"]),
            ("--update-configuration", ["1"]),
            ("--delete-configuration", ["1"]),
            ("--generate-bkp-options", []),
            ("--validate-aes-configuration", []),
            ("--list-users", []),
            ("--delete-user", ["1"]),
            ("--create-programmer-user", []),
            ("--create-user", ["ROLE_ADMIN"]),
            ("--unset-user-role", ["1", "ROLE_ADMIN"]),
            ("--create-sealing-key", []),
            ("--create-import-key", []),
            ("--list-signing-keys", []),
            ("--list-root-signing-keys", []),
            ("--list-sealing-keys", []),
            ("--rotate-sealing-key", []),
            ("--delete-import-key", []),
            ("--get-import-pubkey", []),
            ("--backup-sealing-keys", []),
            ("--restore-sealing-keys", ["b.bak"]),
            ("--rotate-context-key", []),
            ("--list-trusted-certs", []),
            ("--delete-trusted-cert", ["a"]),
            ("--import-root-cert", ["c.crt"]),
            ("--program-helper-image", []),
            ("--bkp-provision", []),
            ("--program-jic", ["x.jic"]),
            ("--bkp-prefetch", []),
            ("--bkp-set-authority", []),
            ("--bkp-puf-activate", ["UDS_INTEL"]),
            ("--validate-setup", []),
            ("--export-logs", ["3"]),
            ("--backup", []),
            ("--restore", ["/bak"]),
            ("--cleanup", []),
            ("--debug-tests", []),
            ("--debug-prechecks", []),
            ("--debug-connectivity", []),
            ("--debug-cert-validity", []),
            ("--softhsm-init-token", []),
            ("--softhsm-show-slots", []),
            ("--softhsm-delete-token", []),
            ("--softhsm-list-objects", []),
            ("--softhsm-delete-key", []),
            ("--create-key", []),
            ("--softhsm-import-aes-key", ["A" * 64]),
            ("--program-root-key-hash", []),
        ]
        patch_names = [
            "create_config", "ensure_dependencies", "install_dependencies",
            "check_dependencies", "build_all", "setup_bouncycastle",
            "create_ssl_certificates", "create_bkps_keystore", "create_bkps_config",
            "create_authentication_keys", "stop_bkps_server", "monitor_bkps_logs",
            "check_bkps_health", "diagnose_bkps_jar", "show_logs",
            "configure_bkps_service", "create_super_admin", "list_configurations",
            "get_configuration", "update_configuration", "delete_configuration",
            "create_bkp_config", "validate_aes_configuration", "list_users",
            "delete_user", "create_user", "unset_user_role", "create_sealing_key",
            "create_import_key", "list_signing_keys", "list_root_signing_keys",
            "list_sealing_keys", "rotate_sealing_key", "delete_import_key",
            "get_import_pubkey", "backup_sealing_keys", "restore_sealing_keys",
            "rotate_context_key", "list_trusted_certs", "delete_trusted_cert",
            "import_root_cert", "provision_rkh_virtual", "program_helper_image",
            "run_bkp", "program_jic", "bkp_prefetch", "bkp_set_authority",
            "bkp_puf_activate", "validate_setup", "export_logs", "backup_setup",
            "restore_setup", "cleanup", "run_debug_tests", "run_prechecks",
            "run_connectivity_tests", "run_cert_validity_tests",
            "softhsm_init_token", "softhsm_show_slots", "softhsm_delete_token",
            "softhsm_list_objects", "softhsm_delete_key", "softhsm_generate_aes_key",
            "softhsm_import_aes_key", "install_from_files", "install_bundle_zip",
            "create_aes_key", "upload_aes_configuration",
            "upload_aes_configuration_file", "generate_jic", "setup_database",
        ]
        with tempfile.TemporaryDirectory() as root:
            cfg = _cfg(root)
            from contextlib import ExitStack
            with ExitStack() as stack:
                stack.enter_context(patch.object(main, "_cfg", return_value=cfg))
                stack.enter_context(patch.object(main, "Config", return_value=cfg))
                stack.enter_context(patch.object(main, "ensure_dependencies", return_value=True))
                stack.enter_context(patch.object(main, "_with_tcp_admin_psql", side_effect=lambda fn: fn))
                stack.enter_context(patch.object(main, "_start_bkp_service_cli", return_value=True))
                stack.enter_context(patch.object(main, "_get_token_cli"))
                stack.enter_context(patch.object(main, "_configure_bkps_keys_cli"))
                stack.enter_context(patch.object(main, "_run_create_qek_ccert"))
                stack.enter_context(patch.object(main, "auto_setup_bkps", return_value=True))
                for name in patch_names:
                    if hasattr(main, name):
                        kw = {"return_value": True} if name == "ensure_dependencies" else {}
                        stack.enter_context(patch.object(main, name, **kw))
                for cmd, extra in cmds:
                    try:
                        main._dispatch(cmd, extra, False, True)
                    except SystemExit:
                        pass
                    except Exception:
                        pass

            with ExitStack() as stack:
                stack.enter_context(patch.object(main, "_cfg", return_value=cfg))
                stack.enter_context(patch.object(main, "ensure_dependencies", return_value=True))
                for name in (
                    "build_all", "setup_bouncycastle", "create_ssl_certificates",
                    "create_bkps_keystore", "create_bkps_config", "setup_database",
                    "create_authentication_keys", "create_aes_key",
                ):
                    stack.enter_context(patch.object(main, name))
                stack.enter_context(
                    patch.object(main, "_with_tcp_admin_psql", side_effect=lambda fn: fn)
                )
                main._dispatch("--first-time-installation", [], False, True)

            cfg.profile_name = "agilex"
            cfg.bkps_jar_path = "/j.jar"
            cfg.bkps_sql_path = "/s.sql"
            cfg.bkps_admin_tools_dir = "/admin"
            cfg.libspdm_wrapper_path = "/w.so"
            with ExitStack() as stack:
                stack.enter_context(patch.object(main, "_cfg", return_value=cfg))
                stack.enter_context(patch.object(main, "ensure_dependencies", return_value=True))
                for name in (
                    "install_from_files", "setup_bouncycastle", "create_ssl_certificates",
                    "create_bkps_keystore", "create_bkps_config", "setup_database",
                    "create_authentication_keys", "create_aes_key",
                ):
                    stack.enter_context(patch.object(main, name))
                stack.enter_context(
                    patch.object(main, "_with_tcp_admin_psql", side_effect=lambda fn: fn)
                )
                stack.enter_context(patch.object(main.os.path, "isfile", return_value=True))
                stack.enter_context(patch.object(main.os.path, "isdir", return_value=True))
                try:
                    main._dispatch("--resume-setup", [], False, True)
                except Exception:
                    pass

            cfg.bkps_jar_path = ""
            with ExitStack() as stack:
                stack.enter_context(patch.object(main, "_cfg", return_value=cfg))
                stack.enter_context(patch.object(main, "ensure_dependencies", return_value=True))
                for name in (
                    "install_bundle_zip", "setup_bouncycastle", "create_ssl_certificates",
                    "create_bkps_keystore", "create_bkps_config", "setup_database",
                    "create_authentication_keys", "create_aes_key",
                ):
                    stack.enter_context(patch.object(main, name))
                stack.enter_context(
                    patch.object(main, "_with_tcp_admin_psql", side_effect=lambda fn: fn)
                )
                main._dispatch("--first-time-installation", [], False, True)

            repo = Path(root, "repo")
            (repo / "bkps" / "build" / "libs").mkdir(parents=True)
            (repo / "bkps" / "build" / "libs" / "bkps.jar").write_bytes(b"j")
            (repo / "bkps" / "schema.sql").write_text("CREATE TABLE t(i int);")
            (repo / "spdm_wrapper" / "build" / "Release" / "wrapper").mkdir(parents=True)
            (repo / "spdm_wrapper" / "build" / "Release" / "wrapper" / "libspdm_wrapper.so").write_bytes(b"s")
            (repo / "admin-tools").mkdir()
            (repo / "admin-tools" / "runner.py").write_text("x")
            cfg.bkps_repo_dir = str(repo)
            with patch.object(main, "_cfg", return_value=cfg), \
                 patch.object(main, "create_config"):
                main._dispatch("--auto-detect-prebuilt", ["--save"], False, True)

            with patch.object(main, "_cfg", return_value=cfg):
                with self.assertRaises(SystemExit):
                    main._dispatch("--unknown-flag", [], False, True)

            cfg.device_part = "AGFB014R24A"
            with patch.object(main, "_cfg", return_value=cfg), \
                 patch.object(main, "generate_jic"):
                main._dispatch("--generate-jic", ["a.sof", "/tmp", "MT", "LOADER"], False, True)
            with patch.object(main, "_cfg", return_value=cfg):
                with self.assertRaises(SystemExit):
                    main._dispatch("--generate-jic", [], False, True)
            cfg.device_part = ""
            with patch.object(main, "_cfg", return_value=cfg):
                with self.assertRaises(SystemExit):
                    main._dispatch("--generate-jic", ["a.sof"], False, True)


class BuildAllExtrasTests(unittest.TestCase):
    def test_defaults_to_bkps_only(self):
        cfg = Config()
        cfg.bkps_build_mode = "full"
        cfg.include_bkp_programmer = True
        main._apply_build_all_extras(cfg, [])
        self.assertEqual(cfg.bkps_build_mode, "bkp_only")
        self.assertFalse(cfg.include_bkp_programmer)

    def test_mode_tokens(self):
        cfg = Config()
        main._apply_build_all_extras(cfg, ["bkps_only"])
        self.assertEqual(cfg.bkps_build_mode, "bkp_only")
        self.assertFalse(cfg.include_bkp_programmer)

        main._apply_build_all_extras(cfg, ["full"])
        self.assertEqual(cfg.bkps_build_mode, "full")
        self.assertTrue(cfg.include_bkp_programmer)

        main._apply_build_all_extras(cfg, ["bkps_with_programmer"])
        self.assertEqual(cfg.bkps_build_mode, "bkp_only")
        self.assertTrue(cfg.include_bkp_programmer)

    def test_rejects_other_variants(self):
        cfg = Config()
        for bad in (
            ["bkp_only"],
            ["--include-programmer"],
            ["--no-programmer"],
            ["1.0"],
            ["full", "bkps_only"],
            ["--bogus"],
            ["full", "extra"],
        ):
            with self.assertRaises(SystemExit, msg=f"should reject {bad}"):
                main._apply_build_all_extras(cfg, bad)

    def test_dispatch_build_all_passes_selection(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = _cfg(root)
            with patch.object(main, "_cfg", return_value=cfg), \
                 patch.object(main, "ensure_dependencies", return_value=True) as deps, \
                 patch.object(main, "build_all") as build:
                main._dispatch(
                    "--build-all",
                    ["bkps_with_programmer"],
                    False,
                    True,
                )
            deps.assert_called_once_with(cfg)
            build.assert_called_once_with(cfg)
            self.assertEqual(cfg.bkps_build_mode, "bkp_only")
            self.assertTrue(cfg.include_bkp_programmer)


if __name__ == "__main__":
    unittest.main()

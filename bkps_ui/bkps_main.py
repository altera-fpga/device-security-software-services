#!/usr/bin/env python3
"""CLI entry point: parse arguments and dispatch BKPS demo commands."""

import sys
import os
import subprocess
import time
import traceback

# Ensure the package directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bkps_config import Config, DEVICE_FAMILIES, load_config, create_config
from bkps_printer import print_error, print_info, print_success, print_header, print_warning
from bkps_runner import AlreadyExistsError, run_runner_tool
from bkps_deps import (
    check_dependencies,
    ensure_dependencies,
    install_dependencies,
)
from bkps_build import build_all, install_bundle_zip, install_from_files
from bkps_database import (
    check_sql_connection,
    reset_database,
    reset_database_password,
    setup_database,
    show_db_stats,
)
from bkps_server_setup import (
    create_bkps_config,
    create_bkps_keystore,
    create_ssl_certificates,
    import_aes_key_to_bc_keystore,
    setup_bouncycastle,
)
from bkps_keys import create_aes_key, create_authentication_keys
from bkps_server import (
    check_bkps_health,
    diagnose_bkps_jar,
    get_bkps_token,
    monitor_bkps_logs,
    start_bkps_server,
    stop_bkps_server,
)
from bkps_monitoring import (
    export_logs,
    show_logs,
)
from bkps_autosetup import auto_setup_bkps, extract_token_from_logs, _wait_for_token
# Prefer prepare_aes_configuration_named for post-AES JSON fill (same as legacy CLI
# prepare path); UI materialize uses the same on-disk artifacts.
from bkps_configure import (
    configure_bkps_keys,
    configure_bkps_service,
    create_bkp_config,
    create_super_admin,
    delete_configuration,
    get_configuration,
    list_configurations,
    prepare_aes_configuration_named,
    update_configuration,
    upload_aes_configuration,
    upload_aes_configuration_file,
    validate_aes_configuration,
)
import bkps_configure as _bkps_configure

# prepare_aes_configuration_named references DEVICE_FAMILIES but bkps_configure
# does not import it (NameError → AES JSON auto-fill fails). Inject for CLI use
# without editing bkps_configure.py.
_bkps_configure.DEVICE_FAMILIES = DEVICE_FAMILIES

from bkps_softhsm import (
    softhsm_create_qek_and_ccert,
    softhsm_delete_key,
    softhsm_delete_token,
    softhsm_generate_aes_key,
    softhsm_import_aes_key,
    softhsm_init_token,
    softhsm_list_objects,
    softhsm_show_slots,
)
from bkps_users import (
    delete_user,
    list_users,
    create_user,
    unset_user_role,
)
from bkps_key_mgmt import (
    backup_sealing_keys,
    create_import_key,
    create_sealing_key,
    delete_import_key,
    get_import_pubkey,
    list_root_signing_keys,
    list_sealing_keys,
    list_signing_keys,
    restore_sealing_keys,
    rotate_context_key,
    rotate_sealing_key,
)
from bkps_certs import (
    delete_trusted_cert,
    import_root_cert,
    list_trusted_certs,
)
from bkps_device import (
    bkp_prefetch,
    bkp_puf_activate,
    bkp_set_authority,
    check_jtag_connection,
    check_jtag_status,
    extract_and_save_corim_url_from_provision_helper,
    generate_jic,
    program_helper_image,
    program_jic,
    provision_rkh_virtual,
    read_fuse_info,
    read_saved_corim_url,
    run_bkp,
)
from bkps_status import (
    backup_setup,
    cleanup,
    restore_setup,
    run_cert_validity_tests,
    run_connectivity_tests,
    run_debug_tests,
    run_prechecks,
    validate_setup,
)


# ---------------------------------------------------------------------------
# Argument parsing (manual - preserves --option style interface from bash)
# ---------------------------------------------------------------------------

def _parse_args():
    """Parse sys.argv into (command, extra, verbose, yes)."""
    argv = sys.argv[1:]

    verbose = False
    yes = False
    filtered = []
    for a in argv:
        if a in ("--verbose", "-v"):
            verbose = True
        elif a in ("--yes", "-y"):
            yes = True
        else:
            filtered.append(a)

    if not filtered or filtered[0] in ("--help", "-h"):
        _print_help()
        sys.exit(0)

    command = filtered[0]
    extra   = filtered[1:]
    return command, extra, verbose, yes


def _cfg(verbose: bool = False, yes: bool = False) -> Config:
    """Build a Config from defaults and the on-disk config file."""
    cfg = Config()
    cfg.verbose = verbose
    cfg.yes = yes
    load_config(cfg)
    return cfg


def _require(extra: list, index: int, name: str) -> str:
    """Return ``extra[index]`` or exit if that argument is missing."""
    if index >= len(extra) or not extra[index]:
        print_error(f"Argument required: <{name}>")
        print_info(f"Usage: bkps_main.py {_current_cmd} <{name}>")
        sys.exit(1)
    return extra[index]


# CLI mode token ``bkps_only`` maps to Config ``bkps_build_mode=bkp_only``.
_BUILD_ALL_CLI_MODES = {
    "full": "full",
    "bkps_only": "bkp_only",
}


def _apply_build_all_extras(cfg: Config, extra: list) -> None:
    """
    Defaults for this command (override conf): ``full``, programmer off.
    """
    cfg.bkps_build_mode = "full"
    cfg.include_bkp_programmer = False

    mode_set = False
    include_set = False
    for tok in extra:
        raw = (tok or "").strip()
        if not raw:
            continue
        low = raw.lower()
        if low in _BUILD_ALL_CLI_MODES:
            if mode_set:
                print_error(
                    "Duplicate build mode for --build-all. "
                    "Use exactly one of: full | bkps_only."
                )
                sys.exit(1)
            cfg.bkps_build_mode = _BUILD_ALL_CLI_MODES[low]
            mode_set = True
            continue
        if raw == "--include-programmer":
            if include_set:
                print_error("Duplicate --include-programmer for --build-all.")
                sys.exit(1)
            cfg.include_bkp_programmer = True
            include_set = True
            continue
        print_error(
            f"Invalid --build-all argument: {raw!r}. "
            "Usage: --build-all [full|bkps_only] [--include-programmer]"
        )
        sys.exit(1)


_current_cmd = ""   # module-level mutable: set in main() so _require() can reference it


def _is_agilex5(cfg: Config) -> bool:
    """Return True when the configured profile is Agilex 5 (SoftHSM / SPDM)."""
    return (getattr(cfg, "profile_name", "") or "").strip().lower() == "agilex5"


def _family_aes_working_path(cfg: Config) -> str:
    """Working AES JSON path (``bkps_configs/aes_config_<profile>.json``).

    Same location ``prepare_aes_configuration_named`` / the Configuration UI use.
    """
    profile = (getattr(cfg, "profile_name", "") or "").strip().lower() or "unknown"
    return os.path.join(cfg.bkps_dir, "bkps_configs", f"aes_config_{profile}.json")


def populate_generated_configuration_values(cfg: Config) -> None:
    """Write ``bkps_configs/aes_config_<profile>.json`` after AES create-qek.

    Reuses ``prepare_aes_configuration_named`` (same binary ccert/QEK overlay the
    classic CLI prepare path uses) plus the saved CoRIM URL. Relies on
    ``DEVICE_FAMILIES`` injected into ``bkps_configure`` at import time.
    """
    # Ensure symbol is present even if another import path cleared it.
    _bkps_configure.DEVICE_FAMILIES = DEVICE_FAMILIES
    profile = (getattr(cfg, "profile_name", "") or "").strip().lower() or "unknown"
    corim_url = (read_saved_corim_url(cfg) or "").strip() or None
    prepare_aes_configuration_named(
        cfg,
        f"aes_config_{profile}",
        corim_url=corim_url,
    )
    working = _family_aes_working_path(cfg)
    if not os.path.isfile(working):
        raise FileNotFoundError(f"Working AES JSON was not created: {working}")
    print_success(f"Working AES JSON ready: {working}")


def _run_create_qek_ccert(cfg: Config, aes_hex: str = "") -> None:
    """AES pipeline step 3: Create QEK + ccert + Sign, then fill working AES JSON.

    Mirrors the UI AES pipeline: SoftHSM create-qek (or SIGMA ``create_aes_key``),
    optional CoRIM extract, then prepare the family working JSON. SoftHSM reloads
    BKPS when needed for ``qek_encryption_key``.
    """
    if _is_agilex5(cfg):
        softhsm_create_qek_and_ccert(cfg, aes_hex)
        try:
            url = extract_and_save_corim_url_from_provision_helper(cfg)
            print_info(f"Configuration corimUrl will be auto-filled: {url}")
        except Exception as exc:
            print_warning(
                f"CoRIM URL auto-extract failed (corimUrl not updated): {exc}"
            )
    else:
        create_aes_key(cfg)
    try:
        populate_generated_configuration_values(cfg)
    except Exception as exc:
        print_warning(f"Working AES JSON auto-fill failed: {exc}")


def _configure_bkps_keys_cli(cfg: Config, attempts: int = 5, delay_sec: int = 5) -> None:
    """Run ``configure_bkps_keys`` with short retries for transient runner failures.

    Robot often hits ``signing-key list`` exit 1 right after Super Admin /
    auth-key creation even though the server is up; a few seconds later the
    same call succeeds. Durable hardening belongs in ``bkps_configure`` /
    ``bkps_runner`` — this is a ``bkps_main``-only bridge.
    """
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            configure_bkps_keys(cfg)
            return
        except RuntimeError as exc:
            last_error = exc
            text = str(exc)
            if "signing-key" not in text and "runner.py" not in text:
                raise
            if attempt >= attempts:
                break
            print_warning(
                f"configure-bkps-keys attempt {attempt}/{attempts} failed "
                f"({exc}); retrying in {delay_sec}s…"
            )
            time.sleep(delay_sec)
    assert last_error is not None
    raise last_error


def _popen_detach_start_script_stdio(original_popen):
    """Return a Popen wrapper that detaches ``start_bkps`` script stdio.

    Robot often runs ``python bkps_main.py --start-bkp-service | tee log``.
    ``bkps_server._launch_in_terminal`` starts ``start_bkps.sh`` without
    redirecting fds, so the shell keeps the tee write end open while it
    waits on Java — Robot never sees EOF after ``[PASS]``.  Forcing
    DEVNULL on that specific child closes the pipe when Python exits.
    """

    def _popen(*args, **kwargs):
        cmd = args[0] if args else kwargs.get("args")
        target = ""
        if isinstance(cmd, (list, tuple)) and cmd:
            target = str(cmd[0])
        elif isinstance(cmd, str):
            target = cmd
        if "start_bkps" in os.path.basename(target.replace("\\", "/")):
            kwargs.setdefault("stdin", subprocess.DEVNULL)
            kwargs.setdefault("stdout", subprocess.DEVNULL)
            kwargs.setdefault("stderr", subprocess.DEVNULL)
            if os.name != "nt":
                kwargs.setdefault("close_fds", True)
        return original_popen(*args, **kwargs)

    return _popen


def _start_bkp_service_cli(cfg: Config) -> bool:
    """Start BKPS (tee-safe), then wait for the initial token like the UI does."""
    original = subprocess.Popen
    subprocess.Popen = _popen_detach_start_script_stdio(original)
    try:
        ok = start_bkps_server(cfg)
    finally:
        subprocess.Popen = original

    if not ok:
        return False
    # Same sequence as gui/pipeline_widgets._pipe_super_admin after start.
    token = extract_token_from_logs(cfg)
    if not token:
        token = _wait_for_token(cfg, timeout=90) or ""
    if token:
        get_bkps_token(cfg)
    else:
        print_warning(
            "Initial token not found in logs yet; "
            "re-run --get-token after the server finishes booting."
        )
    return True


def _get_token_cli(cfg: Config) -> None:
    """Poll for the initial token (UI: extract + wait), then print via get_bkps_token."""
    token = extract_token_from_logs(cfg)
    if not token:
        token = _wait_for_token(cfg, timeout=90) or ""
    get_bkps_token(cfg)
    if not token:
        raise RuntimeError(
            "Initial token not found in .initial_token or bkps.log "
            "(server may still be starting, or super admin already exists)."
        )



def _with_tcp_admin_psql(fn):
    """Run a bkps_database admin op with TCP when ``DB_HOST=127.0.0.1``.

    Linux ``_admin_psql`` always uses ``sudo -u postgres`` (needs a TTY). Robot
    suites use Docker Postgres + ``DB_HOST=127.0.0.1`` +
    ``PG_SUPERUSER_PASSWORD`` and expect Windows-style TCP admin. Patch only for
    the call — durable fix belongs in ``bkps_database._admin_psql``.

    Also rebinds ``bkps_autosetup._admin_psql`` when that module is loaded
    (``from bkps_database import _admin_psql`` keeps a separate reference),
    patches ``_user_psql`` to pass ``-p <db_port>`` (schema import otherwise
    hits default 5432), sets ``PGPORT`` so bare ``psql`` argv (e.g.
    ``reset_database`` subprocess) honors Docker 5433, skips local
    ``systemctl`` PostgreSQL start, and rebinds any other loaded module that
    holds a direct ``_user_psql`` import.
    """
    import bkps_database as dbmod

    def _tcp_mode(cfg2: Config) -> bool:
        host = (cfg2.db_host or "").strip() or "localhost"
        pw = (getattr(cfg2, "pg_superuser_password", None) or "").strip()
        return os.name != "nt" and bool(pw) and host == "127.0.0.1"

    def _port_args(cfg2: Config) -> list:
        port = (getattr(cfg2, "db_port", None) or "").strip()
        return ["-p", port] if port else []

    def _rebind_attr(mod, name: str, value) -> object:
        if mod is None or not hasattr(mod, name):
            return None
        previous = getattr(mod, name)
        setattr(mod, name, value)
        return previous

    def _run(cfg: Config, *args, **kwargs):
        original_admin = dbmod._admin_psql
        original_user = dbmod._user_psql
        original_start = dbmod._start_postgresql_service
        # Modules that may hold ``from bkps_database import _admin_psql|_user_psql``.
        side_modules = [
            sys.modules.get(name)
            for name in ("bkps_autosetup", "bkps_status")
            if name in sys.modules
        ]
        side_admin_restore = []
        side_user_restore = []

        def _tcp_admin(cfg2: Config, extra: list):
            if _tcp_mode(cfg2):
                cmd = ["psql", "-h", "127.0.0.1", "-U", "postgres"]
                cmd.extend(_port_args(cfg2))
                pw = (getattr(cfg2, "pg_superuser_password", None) or "").strip()
                return cmd + list(extra), {"PGPASSWORD": pw}
            return original_admin(cfg2, extra)

        def _tcp_user(cfg2: Config, extra: list):
            # Schema import / app-role psql must honor DB_PORT (Docker 5433).
            if _tcp_mode(cfg2) or (getattr(cfg2, "db_port", None) or "").strip():
                host = (cfg2.db_host or "").strip() or "localhost"
                cmd = ["psql", "-h", host, "-U", cfg2.db_user]
                cmd.extend(_port_args(cfg2))
                return cmd + list(extra), dbmod._pg_env(cfg2)
            return original_user(cfg2, extra)

        def _skip_local_pg_start(cfg2: Config) -> None:
            if _tcp_mode(cfg2):
                print_info(
                    "Skipping local PostgreSQL systemd start "
                    "(DB_HOST=127.0.0.1 + PG_SUPERUSER_PASSWORD → Docker/TCP)."
                )
                return
            original_start(cfg2)

        dbmod._admin_psql = _tcp_admin
        dbmod._user_psql = _tcp_user
        dbmod._start_postgresql_service = _skip_local_pg_start
        for mod in side_modules:
            prev_a = _rebind_attr(mod, "_admin_psql", _tcp_admin)
            if prev_a is not None:
                side_admin_restore.append((mod, prev_a))
            prev_u = _rebind_attr(mod, "_user_psql", _tcp_user)
            if prev_u is not None:
                side_user_restore.append((mod, prev_u))

        # Bare ``psql`` (reset_database schema import, liquibase helpers) omit
        # ``-p``; libpq honors PGPORT for those calls.
        port = (getattr(cfg, "db_port", None) or "").strip()
        prev_pgport = os.environ.get("PGPORT")
        pgport_was_set = "PGPORT" in os.environ
        if port:
            os.environ["PGPORT"] = port
            print_info(f"PGPORT={port} for bare psql during DB admin op")

        try:
            return fn(cfg, *args, **kwargs)
        finally:
            if port:
                if pgport_was_set:
                    os.environ["PGPORT"] = prev_pgport
                else:
                    os.environ.pop("PGPORT", None)
            dbmod._admin_psql = original_admin
            dbmod._user_psql = original_user
            dbmod._start_postgresql_service = original_start
            for mod, prev in side_admin_restore:
                setattr(mod, "_admin_psql", prev)
            for mod, prev in side_user_restore:
                setattr(mod, "_user_psql", prev)

    return _run



def main():  # noqa: C901
    """Parse arguments, dispatch the command, and map errors to exit codes 0/1/2."""
    global _current_cmd
    command, extra, verbose, yes = _parse_args()
    _current_cmd = command

    try:
        # Detach start_bkps.sh stdio for *every* command — create-qek-ccert /
        # auto-setup / etc. may restart BKPS and would hang under ``python | tee``.
        original_popen = subprocess.Popen
        subprocess.Popen = _popen_detach_start_script_stdio(original_popen)
        try:
            _dispatch(command, extra, verbose, yes)
        finally:
            subprocess.Popen = original_popen
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(0)
    except SystemExit:
        raise
    except AlreadyExistsError as e:
        # Exit code 2 signals "nothing to do" to CI pipelines without masking real failures
        print_info(f"Already exists — skipped: {e}")
        sys.exit(2)
    except Exception as e:
        print_error(f"Operation failed: {e}")
        if verbose:
            traceback.print_exc()
        sys.exit(1)


def _dispatch(cmd: str, extra: list, verbose: bool, yes: bool = False):  # noqa: C901
    """Run the implementation for a CLI command string such as ``--build-all``."""
    # ---------------------------------------------------------------- config
    if cmd == "--create-config":
        cfg = Config()
        create_config(cfg)

    elif cmd == "--load-config":
        cfg = _cfg(verbose, yes)
        print_success("Configuration loaded successfully")

    # ---------------------------------------------------------------- full setup
    elif cmd in ("--first-time-installation", "--resume-setup"):

        cfg = _cfg(verbose, yes)
        print_header("BKPS Setup (Resume-Safe)")
        device_label = cfg.device_family or cfg.profile_name
        if cfg.build_from_source:
            print_info(f"Install mode: {device_label} -> source build (SPDM) unless pre-built JAR/SQL/admin-tools/libspdm paths are set")
        else:
            print_info(f"Install mode: {device_label} -> ZIP bundle unless pre-built JAR/SQL/admin-tools/libspdm paths are set")
        print_info("Skipping already-completed steps, resuming from incomplete ones...")

        print_info("\nPhase 1: Verifying and installing all dependencies...")
        if not ensure_dependencies(cfg):
            sys.exit(1)

        _jar   = getattr(cfg, "bkps_jar_path", "") or ""
        _sql   = getattr(cfg, "bkps_sql_path", "") or ""
        _admintool = getattr(cfg, "bkps_admin_tools_dir", "") or ""
        _libspdm   = getattr(cfg, "libspdm_wrapper_path", "") or ""
        is_agilex5 = (cfg.profile_name == "agilex5")
        if _jar and _sql and _admintool and _libspdm:
            print("Phase 2: Installing BKPS from pre-built files")
            print("="*60 + "\n")
            install_from_files(cfg)
        else:
            if is_agilex5:
                if cfg.build_from_source:
                    print("Phase 2: Building BKPS (from source, GitHub)")
                    print("="*60 + "\n")
                    build_all(cfg)
            else:
                print("Phase 2: Installing pre-built files or bundle (from ZIP)")
                print("="*60 + "\n")
                install_bundle_zip(cfg)

        print_info("\nPhase 3: Configuring BKPS server...")
        setup_bouncycastle(cfg)
        create_ssl_certificates(cfg)
        create_bkps_keystore(cfg)
        create_bkps_config(cfg)

        print_info("\nPhase 4: Setting up PostgreSQL database...")
        _with_tcp_admin_psql(setup_database)(cfg)

        print_info("\nPhase 5: Generating authentication and encryption keys...")
        create_authentication_keys(cfg)
        create_aes_key(cfg)

        print_success("\n=== Setup complete ===")
        print_info("Next steps:")
        print_info("  1. python3 bkps_main.py --start-bkp-service")
        print_info("  2. Get the initial token from logs")
        print_info("  3. Continue with the Server Pipeline")

    # ---------------------------------------------------------------- deps
    elif cmd == "--install-dependencies":
        install_dependencies(_cfg(verbose, yes))

    elif cmd == "--check-dependencies":
        check_dependencies(_cfg(verbose, yes))

    # ---------------------------------------------------------------- auto-detect prebuilt
    elif cmd == "--auto-detect-prebuilt":
        # CLI counterpart of the Config tab's bulk "Auto-Detect" button:
        # scan ``cfg.bkps_repo_dir`` for the four prebuilt artefacts
        # (JAR / SQL / libspdm / admin-tools) and update cfg accordingly.
        # By default we only PRINT the found paths (so CI pipelines can
        # eval / capture them without side effects on the config file);
        # pass ``--save`` after the command to persist them to
        # bkps_demo_config.conf via create_config().
        import glob as _glob
        cfg = _cfg(verbose, yes)
        save = "--save" in extra
        repo = (getattr(cfg, "bkps_repo_dir", "") or "").strip()
        if not repo or not os.path.isdir(repo):
            print_error(
                "bkps_repo_dir is empty or not a directory — set it in "
                "the config file (or --create-config first)."
            )
            sys.exit(1)

        lib_ext = ".dll" if sys.platform.startswith("win") else ".so"
        found: dict[str, str] = {}
        jars = sorted(_glob.glob(os.path.join(
            repo, "bkps", "build", "libs", "*.jar")))
        if jars:
            found["bkps_jar_path"] = jars[0]
        sqls = sorted(_glob.iglob(os.path.join(
            repo, "bkps", "**", "*.sql"), recursive=True))
        if sqls:
            found["bkps_sql_path"] = sqls[0]
        libs = sorted(_glob.glob(os.path.join(
            repo, "spdm_wrapper", "build", "Release", "wrapper",
            f"libspdm_wrapper*{lib_ext}")))
        if libs:
            found["libspdm_wrapper_path"] = libs[0]
        admin_dir = os.path.join(repo, "admin-tools")
        if os.path.isfile(os.path.join(admin_dir, "runner.py")):
            found["bkps_admin_tools_dir"] = admin_dir

        for attr, path in found.items():
            print_success(f"{attr} = {path}")
            setattr(cfg, attr, path)
        for attr in ("bkps_jar_path", "bkps_sql_path",
                     "libspdm_wrapper_path", "bkps_admin_tools_dir"):
            if attr not in found:
                print_info(
                    f"{attr}: not found under {repo} — build the missing "
                    "artefact or set it manually in the config."
                )
        if save and found:
            create_config(cfg)
            print_success(
                "Updated fields written to bkps_demo_config.conf."
            )
        elif not found:
            sys.exit(1)

    # ---------------------------------------------------------------- build
    elif cmd == "--build-all":
        cfg = _cfg(verbose, yes)
        _apply_build_all_extras(cfg, extra)
        if not ensure_dependencies(cfg):
            sys.exit(1)
        build_all(cfg)

    # ---------------------------------------------------------------- database
    elif cmd == "--setup-database":
        _with_tcp_admin_psql(setup_database)(_cfg(verbose, yes))

    elif cmd == "--check-sql-connection":
        _with_tcp_admin_psql(check_sql_connection)(_cfg(verbose, yes))

    elif cmd == "--reset-db-password":
        _with_tcp_admin_psql(reset_database_password)(_cfg(verbose, yes))

    elif cmd == "--show-db-stats":
        _with_tcp_admin_psql(show_db_stats)(_cfg(verbose, yes))

    elif cmd in ("--initialize-reset-database", "--reset-database"):
        _with_tcp_admin_psql(reset_database)(_cfg(verbose, yes))

    # ---------------------------------------------------------------- server setup
    elif cmd == "--setup-bkps-server":
        cfg = _cfg(verbose, yes)
        setup_bouncycastle(cfg)
        create_ssl_certificates(cfg)
        create_bkps_keystore(cfg)
        create_bkps_config(cfg)

    # ---------------------------------------------------------------- keys
    elif cmd in ("--create-authentication-keys", "--create-keys"):
        create_authentication_keys(_cfg(verbose, yes))

    elif cmd in ("--create-qek-ccert", "--softhsm-create-qek-ccert", "--create-aes-key"):
        _run_create_qek_ccert(_cfg(verbose, yes), extra[0] if extra else "")

    # ---------------------------------------------------------------- server lifecycle
    elif cmd in ("--start-bkp-service", "--start-bkps"):
        # Detach start_bkps.sh stdio (robot ``python | tee``) and wait for
        # ``.initial_token`` after readiness — wrappers only; bkps_server untouched.
        if not _start_bkp_service_cli(_cfg(verbose, yes)):
            sys.exit(1)

    elif cmd in ("--stop-bkp-service", "--stop-bkps"):
        stop_bkps_server(_cfg(verbose, yes))

    elif cmd == "--monitor-logs":
        monitor_bkps_logs(_cfg(verbose, yes))

    elif cmd == "--get-token":
        _get_token_cli(_cfg(verbose, yes))

    elif cmd == "--check-health":
        check_bkps_health(_cfg(verbose, yes))

    elif cmd == "--diagnose-jar":
        diagnose_bkps_jar(_cfg(verbose, yes))

    elif cmd == "--show-logs":
        show_logs(_cfg(verbose, yes))

    # ---------------------------------------------------------------- bkps configure
    elif cmd == "--configure-bkps-service":
        configure_bkps_service(_cfg(verbose, yes))

    elif cmd == "--auto-setup":
        # Same TCP admin bridge as --setup-database: auto-setup probes/creates
        # DB via bkps_database._admin_psql (sudo TTY fails under Robot/Docker).
        success = _with_tcp_admin_psql(auto_setup_bkps)(_cfg(verbose, yes))
        if not success:
            sys.exit(1)

    elif cmd in ("--create-activate-super-admin", "--create-super-admin"):
        token = _require(extra, 0, "TOKEN")
        create_super_admin(_cfg(verbose, yes), token)

    elif cmd == "--configure-bkps-keys":
        _configure_bkps_keys_cli(_cfg(verbose, yes))

    elif cmd in ("--create-configuration", "--upload-aes-configuration"):
        cfg = _cfg(verbose, yes)
        working = _family_aes_working_path(cfg)
        if os.path.isfile(working):
            upload_aes_configuration_file(cfg, working)
        else:
            upload_aes_configuration(cfg)

    elif cmd == "--upload-aes-configuration-file":
        config_path = _require(extra, 0, "CONFIG_JSON")
        upload_aes_configuration_file(_cfg(verbose, yes), config_path)

    # ---------------------------------------------------------------- AES Compact Certificate Pipeline
    elif cmd in ("--init-token", "--softhsm-init-token"):
        softhsm_init_token(_cfg(verbose, yes))

    elif cmd in ("--create-key", "--softhsm-generate-aes-key", "--softhsm-import-aes-key"):
        cfg = _cfg(verbose, yes)
        aes_hex = extra[0] if extra else ""
        if cmd == "--softhsm-import-aes-key":
            aes_hex = _require(extra, 0, "AES_HEX")
        if aes_hex:
            if len(aes_hex) != 64:
                print_error("AES_HEX must be exactly 64 hexadecimal characters.")
                sys.exit(1)
            softhsm_import_aes_key(cfg, aes_hex)
        else:
            softhsm_generate_aes_key(cfg)

    elif cmd == "--softhsm-show-slots":
        softhsm_show_slots(_cfg(verbose, yes))

    elif cmd == "--softhsm-delete-token":
        softhsm_delete_token(_cfg(verbose, yes))

    elif cmd == "--softhsm-list-objects":
        softhsm_list_objects(_cfg(verbose, yes))

    elif cmd == "--softhsm-delete-key":
        softhsm_delete_key(_cfg(verbose, yes))

    elif cmd == "--import-aes-key-to-bc":
        aes_hex = _require(extra, 0, "AES_HEX")
        if len(aes_hex) != 64:
            print_error("AES_HEX must be exactly 64 hexadecimal characters.")
            sys.exit(1)
        import_aes_key_to_bc_keystore(_cfg(verbose, yes), aes_hex)

    elif cmd == "--list-configurations":
        list_configurations(_cfg(verbose, yes))

    elif cmd == "--get-configuration":
        config_id = _require(extra, 0, "ID")
        get_configuration(_cfg(verbose, yes), config_id)

    elif cmd == "--update-configuration":
        config_id = _require(extra, 0, "ID")
        update_configuration(_cfg(verbose, yes), config_id)

    elif cmd == "--delete-configuration":
        config_id = extra[0] if extra else ""
        delete_configuration(_cfg(verbose, yes), config_id)

    elif cmd in ("--generate-bkp-options", "--create-bkp-config"):
        config_id_override = extra[0] if extra else None
        create_bkp_config(_cfg(verbose, yes), config_id_override)

    elif cmd == "--validate-aes-configuration":
        validate_aes_configuration(_cfg(verbose, yes))

    # ---------------------------------------------------------------- users
    elif cmd == "--list-users":
        list_users(_cfg(verbose, yes))

    elif cmd == "--delete-user":
        user_id = extra[0] if extra else ""
        delete_user(_cfg(verbose, yes), user_id)

    elif cmd == "--create-programmer-user":
        create_user(_cfg(verbose, yes), "ROLE_PROGRAMMER")

    elif cmd == "--create-user":
        role = _require(extra, 0, "ROLE")
        create_user(_cfg(verbose, yes), role)

    elif cmd == "--unset-user-role":
        user_id = _require(extra, 0, "USER_ID")
        role    = _require(extra, 1, "ROLE")
        unset_user_role(_cfg(verbose, yes), user_id, role)

    # ---------------------------------------------------------------- key management
    elif cmd == "--add-owner-root-key":
        # Same as gui/utility_widgets "Add Device Owner Root Key".
        cfg = _cfg(verbose, yes)
        qky = (extra[0] if extra else "").strip() or (
            getattr(cfg, "owner_root_key_path", "") or ""
        ).strip() or os.path.join(cfg.quartus_keys_dir, "root0.qky")
        if not os.path.isfile(qky):
            raise FileNotFoundError(f"Owner Root .qky not found: {qky}")
        print_header("Add Device Owner Root Key")
        run_runner_tool(cfg, "root-signing-key", "add", "--input", qky)
        print_success(f"root-signing-key add completed for: {qky}")

    elif cmd == "--create-sealing-key":
        create_sealing_key(_cfg(verbose, yes))

    elif cmd == "--create-import-key":
        create_import_key(_cfg(verbose, yes))

    elif cmd == "--list-signing-keys":
        list_signing_keys(_cfg(verbose, yes))

    elif cmd == "--list-root-signing-keys":
        list_root_signing_keys(_cfg(verbose, yes))

    elif cmd == "--list-sealing-keys":
        list_sealing_keys(_cfg(verbose, yes))

    elif cmd == "--rotate-sealing-key":
        rotate_sealing_key(_cfg(verbose, yes))

    elif cmd == "--delete-import-key":
        delete_import_key(_cfg(verbose, yes))

    elif cmd == "--get-import-pubkey":
        get_import_pubkey(_cfg(verbose, yes))

    elif cmd == "--backup-sealing-keys":
        backup_sealing_keys(_cfg(verbose, yes))

    elif cmd == "--restore-sealing-keys":
        backup_file = _require(extra, 0, "BACKUP_FILE")
        restore_sealing_keys(_cfg(verbose, yes), backup_file)

    elif cmd == "--rotate-context-key":
        rotate_context_key(_cfg(verbose, yes))

    # ---------------------------------------------------------------- cert management
    elif cmd == "--list-trusted-certs":
        list_trusted_certs(_cfg(verbose, yes))

    elif cmd == "--delete-trusted-cert":
        alias = extra[0] if extra else ""
        delete_trusted_cert(_cfg(verbose, yes), alias)

    elif cmd == "--import-root-cert":
        cert_file = _require(extra, 0, "CERT_FILE")
        import_root_cert(_cfg(verbose, yes), cert_file)

    # ---------------------------------------------------------------- log analysis
    # ---------------------------------------------------------------- device
    elif cmd == "--check-jtag":
        check_jtag_connection(_cfg(verbose, yes))

    elif cmd == "--check-jtag-status":
        status_type = _require(extra, 0, "TYPE")
        check_jtag_status(_cfg(verbose, yes), status_type)

    elif cmd == "--read-fuse-info":
        read_fuse_info(_cfg(verbose, yes))

    elif cmd in ("--program-root-key-hash", "--provision-rkh"):
        provision_rkh_virtual(_cfg(verbose, yes))

    elif cmd == "--program-helper-image":
        # Programming pipeline steps 2 and 7 (pre-JIC + post-PUF) both
        # call this backend.  Generates the PROVISION helper RBF on the
        # fly if it's not already in the cm_provisioning_dir.
        program_helper_image(_cfg(verbose, yes))

    elif cmd in ("--bkp-provision", "--run-bkp"):
        run_bkp(_cfg(verbose, yes))

    elif cmd == "--program-jic":
        jic_file = _require(extra, 0, "JIC_FILE")
        program_jic(_cfg(verbose, yes), jic_file)

    elif cmd == "--bkp-prefetch":
        bkp_prefetch(_cfg(verbose, yes))

    elif cmd == "--bkp-set-authority":
        puf_type = extra[0] if extra else "UDS_EFUSE"
        slot_id  = int(extra[1]) if len(extra) > 1 else 0
        bkp_set_authority(_cfg(verbose, yes), puf_type, slot_id)

    elif cmd == "--generate-jic":
        # ``generate_jic`` now needs a flash-loader identifier (defaults
        # to cfg.device_part when the caller doesn't override) and can
        # optionally take a pre-baked RBF that skips the SOF pipeline.
        # Positional layout mirrors the Programming tab's Settings box:
        #   1: SOF_FILE          (required unless --rbf is used)
        #   2: OUT_DIR           (default: dir of SOF or cwd)
        #   3: FLASH_DEVICE      (default: MT25QU02G)
        #   4: FLASH_LOADER      (default: cfg.device_part)
        #   5: RBF_FILE          (optional; when set, SOF may be "-")
        cfg        = _cfg(verbose, yes)
        sof_raw    = extra[0] if extra else ""
        sof        = None if sof_raw in ("", "-") else sof_raw
        output_dir = extra[1] if len(extra) > 1 else (
            os.path.dirname(sof) if sof else os.getcwd()
        )
        flash_dev  = extra[2] if len(extra) > 2 else "MT25QU02G"
        flash_ldr  = extra[3] if len(extra) > 3 else (
            (getattr(cfg, "device_part", "") or "").strip()
        )
        rbf        = extra[4] if len(extra) > 4 else None
        if not sof and not rbf:
            print_error(
                "generate-jic requires either SOF_FILE or an RBF_FILE "
                "(pass '-' as SOF_FILE when supplying RBF)."
            )
            sys.exit(1)
        if not flash_ldr:
            print_error(
                "generate-jic requires FLASH_LOADER (positional 4) or "
                "a non-empty device_part in the config."
            )
            sys.exit(1)
        generate_jic(cfg, sof, output_dir, flash_dev, flash_ldr, rbf=rbf)

    elif cmd == "--bkp-puf-activate":
        puf_type = _require(extra, 0, "PUF_TYPE")
        bkp_puf_activate(_cfg(verbose, yes), puf_type)

    # ---------------------------------------------------------------- status
    elif cmd == "--validate-setup":
        validate_setup(_cfg(verbose, yes))

    # ---------------------------------------------------------------- monitoring
    elif cmd == "--export-logs":
        days = int(extra[0]) if extra and extra[0].isdigit() else 7
        export_logs(_cfg(verbose, yes), days)

    # ---------------------------------------------------------------- backup/restore/cleanup
    elif cmd == "--backup":
        backup_setup(_cfg(verbose, yes))

    elif cmd == "--restore":
        backup_dir = _require(extra, 0, "BACKUP_DIR")
        restore_setup(_cfg(verbose, yes), backup_dir)

    elif cmd == "--cleanup":
        cleanup(_cfg(verbose, yes))

    # ---------------------------------------------------------------- debug
    elif cmd == "--debug-tests":
        run_debug_tests(_cfg(verbose, yes))

    elif cmd == "--debug-prechecks":
        run_prechecks(_cfg(verbose, yes))

    elif cmd == "--debug-connectivity":
        run_connectivity_tests(_cfg(verbose, yes))

    elif cmd == "--debug-cert-validity":
        run_cert_validity_tests(_cfg(verbose, yes))

    else:
        print_error(f"Unknown option: {cmd}")
        print_info("Run with --help to see all available commands.")
        sys.exit(1)


# ── Help text ────────────────────────────────────────────────────────────────

def _print_help():
    """Print CLI usage and the list of commands implemented by ``_dispatch``."""
    help_text = """
================================================================
    BKPS Demo Automation (Python)
================================================================

Usage:
    python3 bkps_main.py [--verbose] [--yes] <--command> [ARGS]

Flags:
    --verbose, -v    Print full stack traces on errors; show extra diagnostic output
    --yes, -y        Auto-confirm destructive operations (for scripting / CI use)

Project Config:
    --create-config                        Write bkps_demo_config.conf with current defaults
    --load-config                          Load configuration from file

Complete Setup:
    --first-time-installation              Full automated setup from scratch
    --resume-setup                         Resume setup from last incomplete step
    --auto-setup                           Automated: start service, token, super admin,
                                           keys, and programmer role

Installation Pipeline:
    --install-dependencies                 1. Check/Setup Dependencies
    --check-dependencies                   Re-check installed dependencies
    --auto-detect-prebuilt [--save]        Scan cfg.bkps_repo_dir for prebuilt artefacts
    --build-all [full|bkps_only] [--include-programmer]
                                           2. Setup BKPS Repository (source build).
                                           Defaults: full, programmer not included.
                                           Examples:
                                             --build-all
                                             --build-all full
                                             --build-all bkps_only
                                             --build-all full --include-programmer
                                             --build-all bkps_only --include-programmer
    --setup-bkps-server                    3. Install Security Provider
                                           4. Create SSL Certificates
                                           5. Create BKPS Keystore
                                           6. Create BKPS Configuration

Server Pipeline:
    --initialize-reset-database            1. Initialize / Reset Database
    --create-activate-super-admin <TOKEN>  2. Create + Activate Super Admin
    --create-authentication-keys           3. Create Authentication Keys
    --configure-bkps-keys                  4. Configure BKPS Keys
                                           (service start/stop during bootstrap is
                                           internal; use Server Control Panel /
                                           --start-bkp-service for ongoing control)

AES Pipeline:
    --init-token                           1. Init Token (Agilex 5 SoftHSM)
    --create-key [AES_HEX]                 2. Create Key (blank = random AES-256)
    --create-qek-ccert [AES_HEX]           3. Create QEK + ccert + Sign.
                                           Agilex 5: SoftHSM QEK/ccert, then extract
                                           CoRIM and write aesKey.value, qek.value,
                                           and corimUrl into
                                           bkps_configs/aes_config_<family>.json.
                                           Other families: create_aes_key, then the
                                           same JSON overlay.

Configuration Pipeline:
    --create-configuration                 1. Create Configuration (upload working JSON)
    --create-programmer-user               2. Create Programmer User
    --generate-bkp-options [CONFIG_ID]     3. Generate bkp_options.txt

Programming Pipeline:
    --generate-jic <SOF_FILE> [OUT_DIR] [FLASH_DEVICE] [FLASH_LOADER] [RBF_FILE]
                                           1. Generate JIC
    --program-helper-image                 2. Program Helper Image
                                           7. Program Helper Image (post-PUF)
    --program-root-key-hash                3. Program Root Key Hash
                                           8. Program Root Key Hash (post-PUF)
    --program-jic <JIC_FILE>               4. Program JIC
    --bkp-prefetch                         5. BKP Prefetch (connected JTAG device)
    --bkp-puf-activate <PUF_TYPE>          6. BKP PUF Activate
    --bkp-set-authority [PUF_TYPE] [SLOT]  9. BKP Set Authority
    --bkp-provision                        10. BKP Provision

SoftHSM / BouncyCastle Utilities:
    --softhsm-show-slots                   View Slots
    --softhsm-list-objects                 View Keys
    --softhsm-delete-token                 Delete Token
    --softhsm-delete-key                   Delete AES Key
    --import-aes-key-to-bc <AES_HEX>       Import Key to BC JKS

Service Configuration:
    --configure-bkps-service               Configure BKPS Service (runner-config.json)

Server Control Panel:
    --start-bkp-service                    Start the BKP Service
    --stop-bkp-service                     Stop the BKP Service
    --monitor-logs                         Show recent logs and extract the initial token
    --show-logs                            Show Live Logs
    --get-token                            Print the initial token
    --check-health                         Query the BKPS health endpoint
    --diagnose-jar                         Diagnose JAR files and Java classpath

Users:
    --list-users                           List users
    --create-user <ROLE>                   Create a user (ROLE_SUPER_ADMIN | ROLE_ADMIN |
                                           ROLE_PROGRAMMER)
    --delete-user <ID>                     Delete user by numeric ID
    --unset-user-role <ID> <ROLE>          Remove role from user

Key Management:
    --add-owner-root-key [PATH]            Add Device Owner Root Key
                                           PATH defaults to cfg.owner_root_key_path or
                                           quartus_keys_dir/root0.qky
    --list-signing-keys                    List Signing Keys
    --list-root-signing-keys               List root signing keys
    --create-sealing-key                   Create Sealing Key
    --list-sealing-keys                    List Sealing Keys
    --rotate-sealing-key                   Rotate Sealing Key
    --create-import-key                    Create Import Key
    --get-import-pubkey                    Get Import Public Key
    --delete-import-key                    Delete Import Key
    --backup-sealing-keys                  Backup encrypted sealing keys
    --restore-sealing-keys <FILE>          Restore sealing keys from backup
    --rotate-context-key                   Rotate Context Key

Configuration Management:
    --list-configurations                  List AES configurations
    --get-configuration <ID>               Get Configuration
    --update-configuration <ID>            Update Configuration
    --delete-configuration <ID>            Delete Configuration
    --upload-aes-configuration-file <PATH> Upload a specific AES config JSON
    --validate-aes-configuration           Validate the default AES config file

Certificate Management:
    --list-trusted-certs                   List imported trusted certificates
    --delete-trusted-cert <ALIAS>          Delete Cert
    --import-root-cert <PATH>              Import Root Certificate

Database Utilities:
    --setup-database                       Setup Database
    --check-sql-connection                 Check Connection
    --reset-db-password                    Reset Password
    --show-db-stats                        Show Stats

Debug & Device Status:
    --validate-setup                       Validate Setup (dependencies, database/server,
                                           trusted certs, Quartus keys)
    --check-jtag                           Check JTAG Connection
    --check-jtag-status <TYPE>             PROV | CONFIG status
    --read-fuse-info                       Read Fuse Info
    --debug-tests                          Run the full diagnostic suite
    --debug-prechecks                      Run pre-flight checks only
    --debug-connectivity                   Run connectivity tests only
    --debug-cert-validity                  Run certificate validity tests only

Maintenance:
    --export-logs [DAYS]                   Export Logs (default: last 7 days)
    --backup                               Backup Setup
    --restore <DIR>                        Restore from a backup directory
    --cleanup                              Cleanup

Workflow (individual steps, UI pipeline order):
    python3 bkps_main.py --create-config

    # Installation Pipeline
    python3 bkps_main.py --install-dependencies
    python3 bkps_main.py --build-all
    python3 bkps_main.py --build-all [full|bkps_only] [--include-programmer]
    python3 bkps_main.py --setup-bkps-server

    # Server Pipeline
    python3 bkps_main.py --initialize-reset-database
    python3 bkps_main.py --start-bkp-service   # token bootstrap (not a pipeline step)
    python3 bkps_main.py --create-activate-super-admin <TOKEN>
    python3 bkps_main.py --create-authentication-keys
    python3 bkps_main.py --configure-bkps-keys

    # AES Pipeline
    python3 bkps_main.py --init-token
    python3 bkps_main.py --create-key
    python3 bkps_main.py --create-qek-ccert

    # Configuration Pipeline
    python3 bkps_main.py --create-configuration
    python3 bkps_main.py --create-programmer-user
    python3 bkps_main.py --generate-bkp-options

    # Programming Pipeline
    python3 bkps_main.py --generate-jic <SOF_FILE> [OUT_DIR]
    python3 bkps_main.py --program-helper-image
    python3 bkps_main.py --program-root-key-hash
    python3 bkps_main.py --program-jic <JIC_FILE>
    python3 bkps_main.py --bkp-prefetch
    python3 bkps_main.py --bkp-puf-activate <PUF_TYPE>
    python3 bkps_main.py --program-helper-image
    python3 bkps_main.py --program-root-key-hash
    python3 bkps_main.py --bkp-set-authority [PUF_TYPE] [SLOT]
    python3 bkps_main.py --bkp-provision
"""
    print(help_text)


if __name__ == "__main__":
    main()

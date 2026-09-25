#!/usr/bin/env python3
"""PostgreSQL setup, reset, connection check, and diagnostics for BKPS."""

import os
import glob
import re
import subprocess
import sys
from bkps_config import Config
from bkps_printer import print_header, print_step, print_success, print_warning, print_error, print_info
from bkps_runner import run, stream, get_output
from bkps_audit import audit_log



def _pg_env(cfg: Config) -> dict:
    """Return credentials for the BKPS application database role."""
    return {"PGPASSWORD": cfg.db_password}


#: Neutral maintenance database used for DROP/CREATE of the BKPS DB itself.
#: PostgreSQL forbids dropping the database you are currently attached to,
#: so admin sessions always connect to ``postgres`` (guaranteed to exist)
#: instead of ``cfg.db_name``.
_MAINTENANCE_DB = "postgres"


def _sudo_pg(cfg: Config) -> list:
    """Return the Linux ``postgres`` OS-account prefix; empty on Windows.

    See ``_sudo`` for why the password is never placed on this command's stdin.
    """
    if os.name == "nt":
        return []
    if cfg.sudo_password:
        return ["sudo", "-n", "-u", "postgres"]
    return ["sudo", "-u", "postgres"]


def _admin_psql(cfg: Config, extra: list) -> tuple:
    """Return a privileged psql command and its environment.

    Windows authenticates over TCP as PostgreSQL's ``postgres`` superuser.
    Linux uses the local ``postgres`` OS account and peer authentication.
    The BKPS application role is never used for administrative bootstrap.
    """

    resolved_host = (cfg.db_host or "").strip() or "localhost"
    if os.name == "nt":
        cmd = ["psql", "-h", resolved_host, "-U", "postgres"] + list(extra)
        env = {"PGPASSWORD": cfg.pg_superuser_password}
    else:
        # Authenticating here keeps every administrative caller correct: the
        # returned command uses sudo -n and must not read a password itself.
        authenticate_sudo(cfg)
        cmd = _sudo_pg(cfg) + ["psql"] + list(extra)
        env = {}
    return cmd, env


def _user_psql(cfg: Config, extra: list) -> tuple:
    """Return a psql command authenticated as the BKPS application role."""
    resolved_host = (cfg.db_host or "").strip() or "localhost"
    cmd = ["psql", "-h", resolved_host, "-U", cfg.db_user] + list(extra)
    return cmd, _pg_env(cfg)


def _maint_psql(cfg: Config, extra: list) -> tuple:
    """Return (psql command, env) connected to the postgres maintenance DB.

    Args:
        extra: Extra psql tokens; any ``-d`` / ``--dbname=`` is stripped.
    """
    filtered = []
    skip_next = False
    for tok in extra:
        if skip_next:
            skip_next = False
            continue
        if tok == "-d":
            skip_next = True
            continue
        if tok.startswith("--dbname="):
            continue
        filtered.append(tok)
    return _admin_psql(cfg, ["-d", _MAINTENANCE_DB] + filtered)


def _db_identifier(value: str, label: str) -> str:
    """Validate an unquoted PostgreSQL identifier sourced from configuration."""
    value = (value or "").strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        raise ValueError(
            f"{label} must start with a letter or underscore and contain only "
            "letters, digits, and underscores"
        )
    return value


def _sql_literal(value: str) -> str:
    """Return a PostgreSQL string literal without exposing it in argv."""
    return "'" + str(value).replace("'", "''") + "'"


# ---------------------------------------------------------------------------
# sudo helpers — avoid interactive password prompts when sudo_password is set
# ---------------------------------------------------------------------------

def _sudo(cfg: Config) -> list:
    """Return the sudo prefix for privileged commands (empty on Windows).

    ``sudo -S`` reads the password from stdin only while its credential
    timestamp is expired, so a command cannot reliably share one stdin stream
    between the password and its own payload: once sudo is authenticated it
    stops consuming the password line and passes it to the command. The
    password is supplied by ``authenticate_sudo`` instead, and ``-n`` keeps
    sudo away from this command's stdin entirely.
    """
    if os.name == 'nt':
        return []
    if cfg.sudo_password:
        return ["sudo", "-n"]
    return ["sudo"]


def authenticate_sudo(cfg: Config) -> None:
    """Refresh sudo's credential timestamp so later ``sudo -n`` calls succeed."""
    if os.name == 'nt' or not cfg.sudo_password:
        return
    result = run(
        ["sudo", "-S", "-v"],
        input_text=cfg.sudo_password + "\n",
        capture=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(
            "sudo authentication failed. Verify Sudo Password on the Config "
            "tab." + (f" Details: {detail}" if detail else "")
        )
    cached = run(["sudo", "-n", "true"], capture=True, check=False)
    if cached.returncode != 0:
        raise RuntimeError(
            "sudo does not retain credentials for this session, so a password "
            "cannot be supplied without also sending it to the command's "
            "input. Grant this account NOPASSWD access to psql and systemctl, "
            "or remove 'timestamp_timeout=0' from the sudoers policy."
        )


# ---------------------------------------------------------------------------

def _postgresql_service_units(cfg: Config) -> list[str]:
    """Return candidate systemd units for PostgreSQL, most general first.

    Debian and Ubuntu run per-cluster instances such as
    ``postgresql@16-main.service`` behind the ``postgresql.service`` wrapper,
    and the wrapper is absent on some distributions. This mirrors the Windows
    branch, which tries several service names.
    """
    units = ["postgresql.service"]
    result = run(
        _sudo(cfg) + [
            "systemctl", "list-units", "--all", "--plain", "--no-legend",
            "postgresql*.service",
        ],
        capture=True, check=False,
    )
    for line in (result.stdout or "").splitlines():
        fields = line.split()
        if not fields:
            continue
        name = fields[0]
        # ``postgresql@.service`` is a template and cannot be started directly.
        if name.endswith(".service") and "@." not in name and name not in units:
            units.append(name)
    return units


def _start_postgresql_service(cfg: Config) -> None:
    """Start and enable the first PostgreSQL unit that this system provides."""
    authenticate_sudo(cfg)
    attempted: list[str] = []
    for unit in _postgresql_service_units(cfg):
        attempted.append(unit)
        result = run(
            _sudo(cfg) + ["systemctl", "start", unit],
            capture=True, check=False,
        )
        if result.returncode == 0:
            run(
                _sudo(cfg) + ["systemctl", "enable", unit],
                capture=True, check=False,
            )
            print_info(f"PostgreSQL unit started: {unit}")
            return
    raise RuntimeError(
        "Could not start PostgreSQL through systemd. Units tried: "
        + ", ".join(attempted)
    )


def _db_exists(cfg: Config) -> bool:
    """Return True if the database already exists."""
    _cmd, env = _maint_psql(cfg, ["-lqt"])
    result = run(
        _cmd,
        capture=True, check=False,
        env=env,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        if detail:
            print_error(detail)
        if os.name == "nt":
            raise RuntimeError(
                "Cannot connect to PostgreSQL as the postgres administrator. "
                "Verify PG_SUPERUSER_PASSWORD in the Configuration tab."
            )
        raise RuntimeError(
            "Cannot connect to PostgreSQL through the local postgres OS account. "
            "Verify that PostgreSQL is running and the configured sudo access works."
        )
    return cfg.db_name in result.stdout


def setup_database(cfg: Config) -> None:
    """Create PostgreSQL database, user, and import schema."""
    print_header("Setting Up PostgreSQL Database")

    if _db_exists(cfg):
        print_success(f"Database {cfg.db_name} already exists")
        print_info("Checking if schema is populated...")

        result = run(
            ["psql", "-h", cfg.db_host or "localhost", "-U", cfg.db_user, "-d", cfg.db_name, "-c",
             "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';"],
            env=_pg_env(cfg),
            capture=True,
            check=False,
        )

        lines = result.stdout.split('\n')
        if result.returncode == 0 and len(lines) > 2 and lines[2].strip() == "0":
            print_warning("Database exists but has no tables!")
            print_info("Use Setup Phase → Reset Database, Server Utilities → Reset Database")
            return

        print_info("Database appears to have tables - skipping setup")
        return

    print_step(1, "Starting PostgreSQL service...")
    if os.name == 'nt':
        # Windows: try common PostgreSQL service names (installer uses versioned names)
        for svc in ("postgresql", "postgresql-x64-17", "postgresql-x64-16",
                    "postgresql-x64-15", "postgresql-x64-14"):
            r = subprocess.run(["net", "start", svc], capture_output=True)
            if r.returncode == 0:
                break
    else:
        _start_postgresql_service(cfg)
    print_success("PostgreSQL service started")

    print_step(2, "Creating database and user...")
    db_name = _db_identifier(cfg.db_name, "DB_NAME")
    db_user = _db_identifier(cfg.db_user, "DB_USER")
    db_password = _sql_literal(cfg.db_password)
    sql = (
        f"DO $$ BEGIN "
        f"IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = {_sql_literal(db_user)}) THEN "
        f"CREATE ROLE {db_user} WITH LOGIN; "
        f"END IF; END $$;\n"
        f"ALTER ROLE {db_user} WITH LOGIN PASSWORD {db_password};\n"
        f"CREATE DATABASE {db_name} OWNER {db_user};\n"
        f"GRANT ALL PRIVILEGES ON DATABASE {db_name} TO {db_user};\n"
    )
    _cmd, env = _maint_psql(cfg, [])
    run(_cmd, input_text=sql, env=env)
    print_success(f"Database created: {cfg.db_name}")

    print_step(3, "Importing schema...")
    # Same pattern as reset_database: the staged name varies by release.
    sql_files = glob.glob(os.path.join(cfg.bkps_dir, "bkps*.sql"))
    liquibase_dir = os.path.join(cfg.bkps_dir, "liquibase")

    if sql_files:
        sql_file = sql_files[0]
        print_info(f"Importing schema from SQL file: {os.path.basename(sql_file)}")
        _cmd, env = _user_psql(
            cfg,
            ["-d", cfg.db_name, f"--file={sql_file}"]
        )
        run(_cmd, env=env, check=False)
        print_success("Schema imported from SQL file")
    elif os.path.isdir(liquibase_dir):
        print_info("Using Liquibase changelog-based schema")
        print_warning("Schema will be applied automatically when BKPS server starts")
        print_info("Liquibase will create tables on first run (spring.liquibase.enabled=true)")
        print_success("Database prepared for Liquibase migration")
    else:
        print_error(f"No SQL schema file or Liquibase changelogs found in {cfg.bkps_dir}")
        print_info(f"Expected: {cfg.bkps_dir}/bkps*.sql OR {cfg.bkps_dir}/liquibase/")
        raise RuntimeError("Database schema not found")


def reset_database(cfg: Config) -> None:
    """Drop the BKPS database and recreate it from the SQL schema in cfg.bkps_dir."""
    db_name = _db_identifier(cfg.db_name, "DB_NAME")
    db_user = _db_identifier(cfg.db_user, "DB_USER")
    db_password = _sql_literal(cfg.db_password)
    audit_log(cfg, "reset_database", details=cfg.db_name, outcome="started")
    print_header("Resetting BKPS Database")

    print_step(1, "Dropping existing database...")
    if _db_exists(cfg):
        _cmd, env = _maint_psql(cfg, ["-c", f"DROP DATABASE {db_name};"])
        run(_cmd, env=env, check=False)
        print_success(f"Database dropped: {cfg.db_name}")
    else:
        print_info(f"Database '{cfg.db_name}' does not exist — skipping drop")

    print_step(2, "Creating database and user...")
    commands = [
        (f"DO $$ BEGIN "
         f"IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = {_sql_literal(db_user)}) THEN "
         f"CREATE ROLE {db_user} WITH LOGIN; "
         f"END IF; END $$;"),
        f"ALTER ROLE {db_user} WITH LOGIN PASSWORD {db_password};",
        f"CREATE DATABASE {db_name} OWNER {db_user};",
        f"GRANT ALL PRIVILEGES ON DATABASE {db_name} TO {db_user};",
    ]

    for sql_command in commands:
        _cmd, env = _maint_psql(cfg, ["-v", "ON_ERROR_STOP=1"])
        run(
            _cmd,
            env=env,
            input_text=sql_command + "\n",
        )

    print_success(f"Database created: {cfg.db_name}")

    print_step(3, "Importing schema...")

    sql_pattern = os.path.join(cfg.bkps_dir, "bkps*.sql")
    print_info(f"Looking for SQL files: {sql_pattern}")
    sql_files = glob.glob(sql_pattern)

    if not sql_files:
        print_warning(f"No SQL files found matching: {sql_pattern}")
        liquibase_dir = os.path.join(cfg.bkps_dir, "liquibase")
        if os.path.isdir(liquibase_dir):
            print_info("Found liquibase directory - schema will be applied by Liquibase on server start")
        else:
            print_warning("No SQL schema or Liquibase directory found")
        print_success("Database reset complete (no schema to import)")
        return

    print_info(f"Found {len(sql_files)} SQL file(s): {[os.path.basename(f) for f in sql_files]}")

    sql_file = sql_files[0]
    print_info(f"Importing schema from: {os.path.basename(sql_file)}")
    print_info("This may take a moment...")

    env = {**os.environ, **_pg_env(cfg)}

    result = subprocess.run(
        ["psql", "-h", cfg.db_host or "localhost", "-U", cfg.db_user, "-d", cfg.db_name, f"--file={sql_file}"],
        env=env,
        capture_output=True,
        text=True,
    )

    if result.returncode == 0:
        print_success("Schema imported successfully")
        if result.stdout:
            print(result.stdout[-500:] if len(result.stdout) > 500 else result.stdout)

        print_info("Marking Liquibase changesets as executed...")
        subprocess.run(
            ["psql", "-h", cfg.db_host or "localhost", "-U", cfg.db_user, "-d", cfg.db_name, "-c",
             "CREATE TABLE IF NOT EXISTS databasechangeloglock (ID INT NOT NULL, LOCKED BOOLEAN NOT NULL, LOCKGRANTED TIMESTAMP, LOCKEDBY VARCHAR(255), CONSTRAINT PK_DATABASECHANGELOGLOCK PRIMARY KEY (ID));"],
            env={**os.environ, **_pg_env(cfg)},
            capture_output=True,
        )
        subprocess.run(
            ["psql", "-h", cfg.db_host or "localhost", "-U", cfg.db_user, "-d", cfg.db_name, "-c",
             "INSERT INTO databasechangeloglock (ID, LOCKED) VALUES (1, FALSE) ON CONFLICT (ID) DO UPDATE SET LOCKED = FALSE;"],
            env={**os.environ, **_pg_env(cfg)},
            capture_output=True,
        )
        print_success("Liquibase prepared - server will skip executed changesets")
    else:
        print_error(f"Schema import failed with code {result.returncode}")
        if result.stderr:
            print(result.stderr[-500:] if len(result.stderr) > 500 else result.stderr)
        # Continuing here previously reported success and left an empty
        # database, which surfaced much later as a broken server start.
        raise RuntimeError(
            f"Schema import from {os.path.basename(sql_file)} failed with "
            f"exit code {result.returncode}"
        )

    sys.stdout.flush()
    print_success("Database reset complete")

    # Remove setup-complete marker so the Auto Setup button is re-enabled in the GUI
    marker = os.path.join(cfg.bkps_dir, ".bkps_setup_complete")
    if os.path.isfile(marker):
        os.remove(marker)
        print_info("Setup-complete marker removed — Setup Phase can be re-run.")

    # Remove the import public key — it is tied to the DB state and must be regenerated
    # after a reset. Without this, check_setup_complete() would incorrectly return True
    # (finding the stale file) and re-write the marker before setup is re-run.
    import_pubkey = os.path.join(cfg.quartus_keys_dir, "bkps_import_pubkey.pem")
    if os.path.isfile(import_pubkey):
        os.remove(import_pubkey)
        print_info("Removed stale bkps_import_pubkey.pem — regenerated by Setup Phase → Configure BKPS Keys.")


def check_sql_connection(cfg: Config) -> bool:
    """Test connection to the database. Return True on success."""
    print_header("Checking SQL Connection")

    print_step(1, f"Testing connection to {cfg.db_name} as {cfg.db_user}...")
    result = run(
        ["psql", "-h", cfg.db_host or "localhost", "-U", cfg.db_user, "-d", cfg.db_name, "-c", "SELECT 1;"],
        env=_pg_env(cfg),
        capture=True,
        check=False,
    )

    if result.returncode == 0:
        print_success("Database connection successful")

        print_step(2, "Listing database tables...")
        run(
            ["psql", "-h", cfg.db_host or "localhost", "-U", cfg.db_user, "-d", cfg.db_name, "-c", r"\dt"],
            env=_pg_env(cfg),
        )
        return True
    else:
        print_error(f"Cannot connect to database (exit code: {result.returncode})")
        print_error("PostgreSQL error:")
        for line in (result.stderr or "").splitlines():
            print(f"    {line}")
        print_info("")
        print_info("Troubleshooting:")
        if os.name == 'nt':
            print_info("  1. Check if PostgreSQL is running:")
            print_info("     services.msc  (look for a 'postgresql' service)")
            print_info("     or PowerShell: Get-Service postgresql* | Start-Service")
            print_info(f"  2. Verify database exists:")
            print_info(f"     psql -U postgres -lqt")
            print_info(f"  3. Verify user exists:")
            print_info(f"     psql -U postgres -c \"\\du\" | findstr {cfg.db_user}")
            print_info(f"  4. Test password:")
            print_info(f"     set PGPASSWORD=<DB_PASSWORD> && psql -h {cfg.db_host or 'localhost'} -U {cfg.db_user} -c \"SELECT version();\"")
        else:
            print_info("  1. Check if PostgreSQL is running:")
            print_info("     sudo systemctl status postgresql")
            print_info(f"  2. Verify database exists:")
            print_info(f"     sudo -u postgres psql -lqt | grep {cfg.db_name}")
            print_info(f"  3. Verify user exists:")
            print_info(f"     sudo -u postgres psql -c '\\du' | grep {cfg.db_user}")
            print_info(f"  4. Test password:")
            print_info(f"     PGPASSWORD='<DB_PASSWORD>' psql -h {cfg.db_host or 'localhost'} -U {cfg.db_user} -c 'SELECT version();'")
        print_info("  5. Reset password: Server Utilities → Reset Password")
        return False


def reset_database_password(cfg: Config) -> None:
    """Reset the database user password to match cfg.db_password via ALTER ROLE."""
    print_header("Resetting Database Password")

    print_info(f"Resetting password for user: {cfg.db_user}")
    print_info("New password: ***")

    db_user = _db_identifier(cfg.db_user, "DB_USER")
    sql = f"ALTER ROLE {db_user} WITH PASSWORD {_sql_literal(cfg.db_password)};\n"
    _cmd, env = _maint_psql(cfg, [])
    result = run(_cmd, input_text=sql, env=env, check=False)

    if result.returncode == 0:
        print_success("Database password reset successfully")
    else:
        print_error("Failed to reset database password")
        raise RuntimeError("Password reset failed")


def show_db_stats(cfg: Config) -> None:
    """Display database size, public tables, and per-table storage size."""
    print_header("Database Statistics")

    print_info(f"Connecting to database: {cfg.db_name}...")
    env = {**os.environ, **_pg_env(cfg)}
    base = ["psql", "-h", cfg.db_host or "localhost", "-U", cfg.db_user, "-d", cfg.db_name]

    def _run_psql(query: str, title: str):
        print(f"\n{title}:")
        try:
            result = subprocess.run(
                base + ["-c", query],
                env=env,
                capture_output=True,
                text=True,
            )
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr)
        except Exception as e:
            print(f"Query failed: {e}")

    _run_psql(
        f"SELECT pg_size_pretty(pg_database_size('{cfg.db_name}')) as database_size;",
        "Database Size"
    )

    _run_psql(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema = 'public' ORDER BY table_name;",
        "Tables"
    )

    _run_psql(
        "SELECT c.relname as table_name, pg_size_pretty(pg_total_relation_size(c.oid)) as size "
        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'public' AND c.relkind = 'r' "
        "ORDER BY pg_total_relation_size(c.oid) DESC;",
        "Table Sizes"
    )

    print_success("Database statistics retrieved")

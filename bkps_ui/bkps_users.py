#!/usr/bin/env python3
"""BKPS user account and role management via admin-tools runner.py."""

import os
import re
import sys
from bkps_config import Config
from bkps_printer import print_header, print_step, print_success, print_warning, print_error, print_info
from bkps_runner import run, get_output, run_runner_tool as _runner
from bkps_configure import _runner_capture_retry, _extract_user_id_from_create_output, _user_has_role
from bkps_audit import audit_log


# ── Public API ───────────────────────────────────────────────────────────────

def list_users(cfg: Config) -> None:
    """Print all registered BKPS users with their IDs, certificates, and roles."""
    print_header("List All Users")

    # Check if runner-config.json exists
    config_path = os.path.join(cfg.bkps_dir, "admin-tools", "runner-config.json")
    if not os.path.exists(config_path):
        print_error("runner-config.json not found!")
        print_info("Please click 'Configure BKPS Service' in Configure tab first")
        raise FileNotFoundError(f"Missing {config_path}")

    print_info("Fetching user list from BKPS...")
    _runner(cfg, "user", "list")
    print_success("User list retrieved")


def delete_user(cfg: Config, user_id: str) -> None:
    """Remove a BKPS user by numeric ID."""
    audit_log(cfg, "delete_user", details=f"id={user_id}", outcome="started")
    print_header("Delete User")

    if not user_id:
        _runner(cfg, "user", "list")
        if not sys.stdin.isatty():
            raise ValueError(
                "User ID required. Pass it as an argument: --delete-user <ID>"
            )
        user_id = input("Enter user ID to delete: ").strip()

    if not user_id.isdigit():
        print_error(f"Invalid user ID: {user_id} (must be numeric)")
        raise ValueError("User ID must be numeric")

    print_warning(f"Deleting user ID: {user_id}...")

    result = _runner(cfg, "user", "delete", "--id", user_id, capture=True, check=False)
    if result.returncode == 0:
        print_success(f"User {user_id} deleted successfully")
    else:
        print_error(f"Failed to delete user {user_id} (exit code: {result.returncode})")
        for line in (result.stderr or "").splitlines():
            print(f"    {line}")
        print_info("Troubleshooting:")
        print_info(f"  1. Verify user exists: --list-users | grep {user_id}")
        print_info("  2. Check if user is the last super admin (cannot delete)")
        print_info("  3. Wait for BKPS to stabilize and retry")
        raise RuntimeError("User delete failed")


def create_user(cfg: Config, role: str) -> None:
    """Create a user certificate, register it in BKPS, assign the given role, and build a PFX on Windows.

    Args:
        role: BKPS role string such as ROLE_ADMIN or ROLE_SUPER_ADMIN.
    """
    user_role_str = role.split("_")[1].lower()
    print_header(f"Creating {user_role_str} User")

    keys_dir = cfg.quartus_keys_dir

    # user create requires ROLE_SUPER_ADMIN credentials (bkps_admin §"Create user").
    # When called manually from the GUI, warn if neither super-admin nor admin is active.
    pre_list_result = _runner(cfg, "user", "list", capture=True, check=False)
    pre_list_text = (pre_list_result.stdout or "") + (pre_list_result.stderr or "")
    if "ROLE_SUPER_ADMIN" not in pre_list_text and "ROLE_ADMIN" not in pre_list_text:
        print_error(
            "No ROLE_SUPER_ADMIN or ROLE_ADMIN user detected in user list.\n"
            "Creating a user requires ROLE_SUPER_ADMIN credentials in runner-config.json"
        )

    # Capture current users first so we can reliably detect the newly created user.
    before_users_result = _runner_capture_retry(cfg, "user", "list", attempts=6, delay_sec=3,
                                                stage="pre-create user list")
    before_user_list = before_users_result.stdout if before_users_result.stdout else ""

    # Write an OpenSSL config following the manual's user-cert pattern.
    # The user cert is signed by the BKPS SSL CA (not self-signed) so that
    # Quartus Programmer can verify it against bkp_tls_ca_cert (= bkps_ssl_cert.crt).
    cnf = os.path.join(keys_dir, "openssl.cnf")
    with open(cnf, "w", encoding="utf-8") as _f:
        _f.write(
            "[ req ]\n"
            f"distinguished_name = {user_role_str}_dn\n"
            "req_extensions = v3_req\n"
            "prompt = no\n"
            f"[ {user_role_str}_dn ]\n"
            f"CN = {user_role_str}\n"
            "[ v3_req ]\n"
            "basicConstraints = CA:false\n"
            "keyUsage = digitalSignature\n"
            "subjectAltName = @alt_names\n"
            "extendedKeyUsage = clientAuth\n"
            "[ alt_names ]\n"
            "DNS.1 = localhost\n"
            "IP.1 = 127.0.0.1\n"
        )

    ssl_dir    = os.path.join(cfg.bkps_dir, "keys", "bkps_ssl_cert")
    ca_cert    = os.path.join(ssl_dir, "bkps_ssl_cert.crt")
    cert_path  = os.path.join(keys_dir, f"{user_role_str}_cert.crt")
    key_path   = os.path.join(keys_dir, f"{user_role_str}_private.pem")

    print_step(1, "Creating user key and certificate ...")
    key_cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_path,
        "-nodes",
        "-out", cert_path,
        "-days", "365",
        "-extensions", "v3_req",
        "-config", cnf,
    ]
    run(key_cmd)

    print_step(2, f"Registering {user_role_str} user in BKPS...")
    create_result = _runner(
        cfg,
        "user", "create",
        "--input", cert_path,
        "--output", os.path.join(keys_dir, f"{user_role_str}_bkps_signed.crt"),
        capture=True,
    )
    print_success(f"{user_role_str} user registered in BKPS")

    signed_cert_path = os.path.join(keys_dir, f"{user_role_str}_bkps_signed.crt")
    if not os.path.isfile(signed_cert_path):
        raise RuntimeError(
            f"{user_role_str} signed certificate was not generated: {signed_cert_path}\n"
            "Retry user creation and check runner.py output."
        )

    is_windows = sys.platform.startswith("win")

    if is_windows:
        print_step("2.1", f"Creating {user_role_str}.pfx...")
        pfx_path = os.path.join(keys_dir, f"{user_role_str}.pfx")
        pfx_base_cmd = [
            "openssl", "pkcs12", "-export",
            "-out",     pfx_path,
            "-passout", f"pass:{cfg.programmer_cert_password}",
            "-inkey",   key_path,
            "-in",      cert_path,
        ]
        pfx_result = run(pfx_base_cmd + ["-legacy"], cwd=keys_dir, check=False)
        used_legacy = pfx_result.returncode == 0
        if not used_legacy:
            run(pfx_base_cmd, cwd=keys_dir)
        print_success(f"{user_role_str} PFX created")

        # Verify the PFX is readable with the configured password (same -legacy flag if used).
        verify_cmd = [
            "openssl", "pkcs12", "-in", pfx_path,
            "-passin", f"pass:{cfg.programmer_cert_password}", "-noout",
        ]
        if used_legacy:
            verify_cmd.append("-legacy")
        verify_result = run(verify_cmd, check=False, capture=True)
        if verify_result.returncode != 0:
            err = (verify_result.stderr or "").strip()
            raise RuntimeError(
                f"{user_role_str}.pfx was created but cannot be read back (wrong password or format issue).\n"
                f"OpenSSL error: {err}\n"
                f"Expected password: {cfg.programmer_cert_password!r}. "
                f"Ensure bkp_options.txt uses the same password."
            )
        fmt = "legacy PBE-SHA1-3DES (OpenSSL 1.x compatible)" if used_legacy else "AES-256-CBC (OpenSSL 3.x default)"
        print_info(f"PFX format: {fmt}")

    print_step(3, "Getting user ID (pre-role assignment state)...")
    result = _runner_capture_retry(cfg, "user", "list", attempts=6, delay_sec=3,
                                   stage="post-create user list")
    user_list = result.stdout if result.stdout else ""
    print_info(f"User list output before {role} assignment:")
    print(user_list)

    _id_re = re.compile(r'"id"\s*:\s*(\d+)')
    before_ids = set(_id_re.findall(before_user_list))
    after_ids  = set(_id_re.findall(user_list))
    new_ids = after_ids - before_ids
    if len(new_ids) == 1:
        user_id = next(iter(new_ids))
        print_info(f"Detected new user ID by list diff: {user_id}")

    print_step(4, f"Assigning {role}...")
    if user_id:
        print_info(f"User ID: {user_id}")
        role_result = _runner(
            cfg,
            "user", "role-set", "--id", user_id, "--role", role,
            capture=True,
            check=False,
        )

        if role_result.returncode != 0:
            role_out = (role_result.stdout or "") + (role_result.stderr or "")
            print_error(f"{role} assignment command failed")
            if role_out.strip():
                print_info("BKPS response:")
                for line in role_out.splitlines():
                    print(f"    {line}")
            raise RuntimeError(f"Failed to assign {role}")

        verify_result = _runner_capture_retry(cfg, "user", "list", attempts=6, delay_sec=3,
                                              stage=f"verify {role}")
        verify_list = verify_result.stdout if verify_result.stdout else ""
        if _user_has_role(verify_list, user_id, role):
            print_success("Role assigned")
            print_info(f"User list output after {role} assignment:")
            print(verify_list)
        else:
            print_error(f"{user_role_str} user was created, but {role} is still missing in user list")
            print_info("This commonly happens when using a non-admin certificate for role assignment")
            print_info("Per bkps_quick, use ROLE_ADMIN account for this step")
            print_info(f"Manual retry: python3 runner.py user role-set --id {user_id} --role {role}")
            raise RuntimeError(f"{role} not present after role-set")
    else:
        print_error("Could not automatically extract user ID")
        print_info("Please check the user list above and assign the role manually with:")
        print_info(f"  cd {cfg.bkps_dir}/admin-tools")
        print_info(f"  python3 runner.py user role-set --id <ID> --role {role}")
        raise RuntimeError(f"{user_role_str} user was created but role assignment could not be completed automatically")


def unset_user_role(cfg: Config, user_id: str, role: str) -> None:
    """Remove a named role from a BKPS user.

    Args:
        user_id: Numeric BKPS user ID.
        role: Role name to remove, e.g. ROLE_ADMIN.
    """
    audit_log(cfg, "unset_user_role", details=f"id={user_id} role={role}", outcome="started")
    print_header("Unset User Role")

    if not user_id or not role:
        print_error("User ID and Role required")
        print_info("Usage: --unset-user-role <USER_ID> <ROLE>")
        raise ValueError("Missing user_id or role")

    if not user_id.isdigit():
        print_error(f"Invalid user ID: {user_id} (must be numeric)")
        raise ValueError("User ID must be numeric")

    print_info(f"Removing role {role} from user ID: {user_id}...")
    print_warning("Note: Cannot remove ROLE_SUPER_ADMIN if it's the only super admin")

    result = _runner(cfg, "user", "role-unset", "--id", user_id, "--role", role, capture=True, check=False)

    if result.returncode == 0:
        print_success(f"Role {role} removed from user {user_id}")
    else:
        print_error(f"Failed to unset role (exit code: {result.returncode})")
        for line in (result.stderr or "").splitlines():
            print(f"    {line}")
        print_info("Troubleshooting:")
        print_info(f"  1. Check current roles: --list-users | grep {user_id}")
        print_info("  2. Verify user doesn't have restrictions preventing role removal")
        print_info("  3. Especially if removing only ROLE_SUPER_ADMIN (not allowed)")
        raise RuntimeError("Role unset failed")

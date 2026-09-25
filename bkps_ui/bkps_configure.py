#!/usr/bin/env python3
"""BKPS service configuration, AES config upload, prefetch, and bkp_options.txt generation."""

import os
import json
import re
import hashlib
import ssl
import subprocess
import tempfile
import time
import sys
from typing import Optional, Tuple
from bkps_config import Config, DEVICE_FAMILIES
from bkps_printer import print_header, print_step, print_success, print_warning, print_error, print_info
from bkps_runner import run, _ps_run, get_output, run_runner_tool as _runner
from bkps_audit import audit_log
import shutil
from bkps_keys import create_authentication_keys, register_bkps_signing_key

# User Roles
USER_ROLES = [
    "ROLE_ADMIN",
    "ROLE_PROGRAMMER"
]


def _signing_key_list_raw(
    cfg: Config,
    attempts: int = 5,
    delay_sec: float = 3.0,
) -> str:
    """Return the raw stdout+stderr of ``runner.py signing-key list``.

    Retries transient non-zero exits (common right after Super Admin / service
    start). Includes runner stderr in the final error for diagnosis.
    """
    last_error: Optional[Exception] = None
    for attempt in range(1, max(1, attempts) + 1):
        result = _runner(cfg, "signing-key", "list", capture=True, check=False)
        text = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0:
            return text
        detail = text.strip()
        last_error = RuntimeError(
            f"runner.py signing-key list failed (exit {result.returncode})"
            + (f": {detail[:800]}" if detail else "")
        )
        if attempt >= attempts:
            break
        print_warning(
            f"signing-key list attempt {attempt}/{attempts} failed "
            f"(exit {result.returncode}); retrying in {delay_sec}s…"
        )
        time.sleep(delay_sec)
    assert last_error is not None
    raise last_error


def _signing_key_ids(cfg: Config) -> set:
    """Return the current set of BKPS signing-key IDs from ``signing-key list``."""
    text = _signing_key_list_raw(cfg)
    if not text:
        return set()
    return set(re.findall(r'"(?:signingKeyId|id)"\s*:\s*(\d+)', text))


def _create_signing_key_and_get_id(cfg: Config) -> str:
    """Create a BKPS signing key and return its numeric ID as a string."""
    before_ids = _signing_key_ids(cfg)
    _runner(cfg, "signing-key", "create")
    after_ids = _signing_key_ids(cfg)

    new_ids = after_ids - before_ids
    if len(new_ids):
        return next(iter(new_ids))
    if new_ids:
        chosen = max(new_ids, key=int)
        return chosen
    raise RuntimeError("No new signing key created.\n" +
    "Check BKPS log for errors. Fix and rerun \"Configure BKPS Keys\".")

    return ""


def _quartus_create_root(keys_dir: str, family: str, stem: str) -> None:
    """Generate an Owner Root key pair (private PEM, public PEM, and .qky) in *keys_dir*.

    Args:
        keys_dir: Directory that receives ``<stem>_private.pem``, ``<stem>_public.pem``, and ``<stem>.qky``.
        family: Quartus ``--family`` value.
        stem: Output filename prefix.
    """
    private_pem = f"{stem}_private.pem"
    public_pem  = f"{stem}_public.pem"
    root_qky    = f"{stem}.qky"

    run([
        "quartus_sign", f"--family={family}", "--operation=make_private_pem",
        "--curve=secp384r1",
        "--no_passphrase",
        private_pem,
    ], cwd=keys_dir)
    run([
        "quartus_sign", f"--family={family}", "--operation=make_public_pem",
        private_pem, public_pem,
    ], cwd=keys_dir)
    run([
        "quartus_sign", f"--family={family}", "--operation=make_root",
        public_pem, root_qky,
    ], cwd=keys_dir)


def _sign_bkps_chain(
    keys_dir: str,
    family: str,
    previous_pem: str,
    previous_qky: str,
    cancel_id: str,
    out_qky: str,
) -> None:
    """Append the BKPS signing public key to a root and emit *out_qky*."""
    run([
        "quartus_sign", f"--family={family}", "--operation=append_key",
        f"--previous_pem={previous_pem}",
        f"--previous_qky={previous_qky}",
        "--permission=16",
        f"--cancel={cancel_id}",
        "--input_pem=bkps_signing_public.pem",
        out_qky,
    ], cwd=keys_dir)


def _runner_env_with_ssl_ca(cfg: Config) -> dict:
    """Return env vars that point requests at the BKPS self-signed SSL cert."""
    ssl_cert = os.path.join(cfg.bkps_dir, "keys", "bkps_ssl_cert", "bkps_ssl_cert.crt")
    if os.path.isfile(ssl_cert):
        return {"REQUESTS_CA_BUNDLE": ssl_cert, "SSL_CERT_FILE": ssl_cert}
    return {}


def _is_secure_enclave_error(output: str) -> bool:
    """Return True if BKPS output indicates a secure enclave failure (code 2080).

    Args:
        output: Combined stdout/stderr from a runner.py invocation.
    """
    text = (output or "").lower()
    return (
        '"code": 2080' in text or
        '"code":2080' in text or
        "connection to secure enclave failed" in text
    )


def _print_secure_enclave_recovery(cfg: Config) -> None:
    """Print recovery steps for a BKPS secure-enclave (code 2080) failure."""
    provider = (cfg.security_provider or "bouncycastle").strip().lower()
    print_error("BKPS secure enclave is not reachable (code 2080)")
    print_info("Common causes:")
    print_info("  1. BKPS server started with the wrong security provider configuration")
    print_info("  2. Provider backend is not initialized/available")
    print_info("  3. BKPS was not restarted after changing provider settings")
    print_info("")
    print_info("Recommended fix sequence:")
    print_info("  2. BKPS Setup → Install Security Provider")
    print_info("  2. Ensure provider is set to: " + provider)
    print_info("  3. Restart BKPS server (Setup Phase → Stop Server, then Start Server)")
    print_info("  4. Debug → Check Health")
    print_info("  5. Retry Create Configuration (BKPS Configuration tab)")
    if provider in ("luna", "ncipher"):
        print_info("  6. Verify HSM connectivity and keystore credentials on the Config tab")


def _print_secure_enclave_diagnostics(cfg: Config) -> None:
    """Print local diagnostics for common 2080 root causes."""
    provider = (cfg.security_provider or "bouncycastle").strip().lower()
    print_info("")
    print_info("Secure enclave diagnostics:")

    profile_yml = os.path.join(cfg.bkps_dir, "config", f"application-{provider}.yml")
    if os.path.isfile(profile_yml):
        print_success(f"  Found provider profile: {profile_yml}")
    else:
        print_error(f"  Missing provider profile: {profile_yml}")
        print_info("  Run BKPS Setup → Install Security Provider, then restart BKPS.")

    if provider == "bouncycastle":
        bc_keystore = os.path.join(cfg.bkps_dir, "keys", "bc-keystore-bkps-static.jks")
        if os.path.isfile(bc_keystore):
            print_success(f"  Found BC keystore: {bc_keystore}")
        else:
            print_error(f"  Missing BC keystore: {bc_keystore}")
            print_info("  Run Setup Phase → Installation, or recreate keystore artifacts, then restart BKPS.")

    log_path = os.path.join(cfg.bkps_dir, "logs", "bkps.log")
    if not os.path.isfile(log_path):
        print_warning(f"  BKPS log not found at: {log_path}")
        return

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        print_warning(f"  Could not read BKPS log: {log_path}")
        return

    tail = lines[-200:]
    keywords = (
        "security provider",
        "secure enclave",
        "failed to initialize",
        "jcesecurityproviderexception",
        "health check for security provider failed",
        "failed to store keypair",
        "keystore",
        "token",
    )
    hits = [ln.rstrip() for ln in tail if any(k in ln.lower() for k in keywords)]

    if hits:
        print_info("  Recent BKPS log hints:")
        for ln in hits[-20:]:
            print(f"    {ln}")
    else:
        print_info("  No provider-related hints found in the last BKPS log lines.")


def _config_has_qek_field(config_path: str) -> bool:
    """Return True if the JSON config includes ``confidentialData.qek.value``.

    Args:
        config_path: Path to an AES configuration JSON file.
    """
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return False

    conf = data.get("confidentialData", {})
    qek = conf.get("qek", {}) if isinstance(conf, dict) else {}
    return isinstance(qek, dict) and "value" in qek


def _bc_keystore_has_alias(cfg: Config, alias: str) -> bool:
    """Return True if the BC UBER keystore contains *alias*.

    Args:
        alias: Keystore alias to look for (e.g. ``qek_encryption_key``).
    """
    bc_jar = os.path.join(cfg.bkps_dir, "libs-ext", "bcprov-jdk18on-1.78.1.jar")
    bc_keystore = os.path.join(cfg.bkps_dir, "keys", "bc-keystore-bkps-static.jks")
    if not os.path.isfile(bc_jar) or not os.path.isfile(bc_keystore):
        return False

    result = subprocess.run(
        [
            "keytool", "-list",
            "-storetype", "UBER",
            "-keystore", bc_keystore,
            "-storepass", cfg.bc_keystore_password,
            "-provider", "org.bouncycastle.jce.provider.BouncyCastleProvider",
            "-providerpath", bc_jar,
            "-alias", alias,
        ],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0



def _ensure_qek_alias_ready_for_upload(cfg: Config, config_path: str) -> None:
    """Ensure qek_encryption_key exists when uploading configs that include qek field."""
    if not _config_has_qek_field(config_path):
        return

    provider = (cfg.security_provider or "bouncycastle").strip().lower()
    if provider != "bouncycastle":
        return

    alias = "qek_encryption_key"
    has_alias = _bc_keystore_has_alias(cfg, alias)
    if has_alias:
        print_success("QEK alias precheck passed: qek_encryption_key found in BC keystore")
        return
    else:
        print_warning("QEK alias precheck: qek_encryption_key not found in BC keystore")

    raise RuntimeError(
        "Missing qek_encryption_key in BC keystore. "
        "Use AES Utilities → Import Key to BC JKS, then retry upload."
    )


# ---------------------------------------------------------------------------
# configure_bkps_service
# ---------------------------------------------------------------------------

def configure_bkps_service(
    cfg: Config,
    cert_override: str = "",
    key_override: str = "",
) -> None:
    """Write initial runner-config.json (no signed cert yet)."""
    print_header("Configuring BKPS Service")

    ssl_cert = os.path.join(cfg.bkps_dir, "keys", "bkps_ssl_cert", "bkps_ssl_cert.crt")
    if not os.path.exists(ssl_cert):
        print_warning("Missing required files:")
        print_warning("  - BKPS SSL certificate")
        print_info("Run Create SSL Certificates (Setup Phase) first")
        print_info("Continuing anyway - you'll need these files later...")

    # Resolve certificate + private key.  Overrides win when supplied; otherwise
    # fall back to the historical super-admin auto-detection.
    keys_dir = os.path.join(cfg.bkps_dir, "keys")
    default_admin_key = os.path.join(keys_dir, "super_admin_private.pem")
    cert = cert_override
    certificate_key = key_override
    if cert_override and key_override:
        if not os.path.isfile(cert_override):
            raise RuntimeError(
                f"Certificate does not exist: {cert_override}"
            )
        if not os.path.isfile(key_override):
            raise RuntimeError(
                f"Private key does not exist: {key_override}"
            )
        print_info(f"Certificate: {cert_override} Private key : {key_override}")
    else:
        cert = os.path.join(keys_dir, "super_admin_bkps_signed.crt")
        certificate_key = os.path.join(keys_dir, "super_admin_private.pem")
        if os.path.isfile(cert) and os.path.isfile(certificate_key):
            print_info(f"Certificate: {cert} Private Key: {certificate_key}")
        else:
            cert = ""
            certificate_key = ""
            print_warning("No super admin certificate found — certificate field will be empty")

    # admintools/runner.py cannot use encrypted client-side private keys
    if certificate_key and os.path.isfile(certificate_key):
        _reject_encrypted_client_key(certificate_key)

    config_path = os.path.join(cfg.bkps_dir, "admin-tools", "runner-config.json")
    _write_runner_config(cfg, config_path, cert=cert, certificate_key=certificate_key)

    print_success(f"Created: {config_path}")
    print_info("")
    print_info("Configuration details:")
    print_info(f"  Server: {cfg.bkps_server_ip}:{cfg.bkps_server_port}")
    print_info(f"  Certificate key: {certificate_key}")
    print_info(f"  CA cert: {ssl_cert}")
    print_info("")
    print_info("Next steps:")
    print_info("  1. Start BKPS server (Setup Phase → Start Server)")
    print_info("  2. Create super admin (Setup Phase → Create + Activate Super Admin)")


def _pem_key_is_encrypted(key_path: str) -> bool:
    """Return True when *key_path* is a PEM private key encrypted with a passphrase."""
    try:
        with open(key_path, "rb") as f:
            head = f.read(2048)
    except OSError:
        return False
    text = head.decode("ascii", errors="replace")
    return ("BEGIN ENCRYPTED PRIVATE KEY" in text
            or "Proc-Type: 4,ENCRYPTED" in text)


def _reject_encrypted_client_key(key_path: str) -> None:
    """Raise if *key_path* is a PEM whose first header advertises encryption."""
    if _pem_key_is_encrypted(key_path):
        raise RuntimeError(
            f"Client private key is encrypted with a passphrase, but "
            f"admintools/runner.py rejects encrypted keys (its Requester "
            f"raises PassPhraseError immediately).\n"
            f"  Offending file: {key_path}\n"
            f"Fix: recreate this user with an EMPTY 'Certificate Password' "
            f"in the Config tab (or clear it and re-run the corresponding "
            f"Admin tab → Create User button).  User private keys must be "
            f"generated with `openssl req -nodes` so runner.py can load "
            f"them without a passphrase."
        )


# ---------------------------------------------------------------------------
# create_super_admin
# ---------------------------------------------------------------------------

def create_super_admin(cfg: Config, token: str, parent_step=None) -> None:
    """Create super admin user using the initial one-time token.

    Args:
        parent_step: When set, print inner steps as parent.1, parent.2, ...
    """
    audit_log(cfg, "create_super_admin", outcome="started")
    print_header("Creating Super Admin User")

    if not token:
        print_error("Token required")
        print_info("A one-time initial token is required (CLI: --create-super-admin <TOKEN>)")
        raise ValueError("Token required")


    signed_cert = os.path.join(cfg.bkps_dir, "keys", "super_admin_bkps_signed.crt")

    config_path = os.path.join(cfg.bkps_dir, "admin-tools", "runner-config.json")
    _write_runner_config(cfg, config_path, cert="")

    ssl_env = _runner_env_with_ssl_ca(cfg)
    ssl_cert_path = os.path.join(cfg.bkps_dir, "keys", "bkps_ssl_cert", "bkps_ssl_cert.crt")
    if ssl_env:
        print_info(f"SSL CA cert: {ssl_cert_path} (found, setting REQUESTS_CA_BUNDLE)")
    else:
        print_warning(f"SSL CA cert NOT FOUND: {ssl_cert_path}")
        print_warning("runner.py will use system CAs — self-signed cert will fail!")
        print_warning("Fix: Setup Phase → Create SSL Certificates, then retry.")

    print_step(1, "Creating super admin user...", parent=parent_step)
    try:
        _runner(cfg, "user", "initial-create",
                "-i", os.path.join(cfg.bkps_dir, "keys", "super_admin_cert.crt"),
                "-o", signed_cert,
                "--token", token,
                env=ssl_env)
        if not os.path.isfile(signed_cert):
            raise RuntimeError(
                "Super admin creation command completed, but signed certificate was not generated: "
                f"{signed_cert}.\n"
                "Check runner.py output above. Common causes:\n"
                "  • BKPS server not running or token expired\n"
                "  • SSL CA cert missing (Setup Phase → Create SSL Certificates)\n"
                "  • admin-tools Python packages missing — run Setup Phase → Install Dependencies\n"
                f"      or: {sys.executable} -m pip install requests packaging pyOpenSSL docopt"
            )
        print_success("Super admin user created")
        # Clean up the one-time token file — it cannot be used again
        token_file = os.path.join(cfg.bkps_dir, ".initial_token")
        if os.path.isfile(token_file):
            try:
                os.remove(token_file)
                print_info("Removed .initial_token (one-time token consumed)")
            except OSError:
                pass
    except Exception as e:
        error_msg = str(e)
        if "certificate fingerprint already exists" in error_msg or "already exists" in error_msg.lower():
            print_warning("Super admin user already exists - skipping creation")
            print_info("The signed certificate should already be in keys/super_admin_bkps_signed.crt")
            # Check if the signed cert exists
            if not os.path.exists(signed_cert):
                print_error(f"Signed certificate not found: {signed_cert}")
                print_info("You may need to manually retrieve it from BKPS or recreate the user")
                raise
        else:
            raise

    print_step(2, "Updating runner-config.json with signed certificate...", parent=parent_step)
    _write_runner_config(
        cfg, config_path,
        cert=signed_cert
    )
    print_success("Runner config updated")


# ---------------------------------------------------------------------------
# configure_bkps_keys
# ---------------------------------------------------------------------------

def configure_bkps_keys(cfg: Config, skip_qky: bool = False, parent_step=None) -> None:
    """Create and activate BKPS signing, sealing, import, and context keys.

    Args:
        skip_qky: When True, skip regenerating Design/AES-cert signing keys (still creates the root).
        parent_step: When set, print inner steps as parent.1, parent.2, ...
    """
    audit_log(cfg, "configure_bkps_keys", outcome="started")
    print_header("Configuring BKPS Keys")

    # Ensure runner-config.json uses the BKPS-signed certificate.
    # The server rejects the unsigned cert with SSLV3_ALERT_CERTIFICATE_UNKNOWN.
    config_path = os.path.join(cfg.bkps_dir, "admin-tools", "runner-config.json")
    signed_cert = os.path.join(cfg.bkps_dir, "keys", "super_admin_bkps_signed.crt")
    if not os.path.isfile(signed_cert):
        raise RuntimeError(
            f"Signed certificate not found: {signed_cert}\n"
            "Create the super admin first (Setup Phase → Create + Activate Super Admin)."
        )
    _write_runner_config(cfg, config_path, cert=signed_cert)
    print_info(f"Runner config refreshed with signed certificate.")

    keys_dir = cfg.quartus_keys_dir

    sid = print_step(1, "Creating authentication keys(Owner Root, Design, AES Cert signing chains)...", parent=parent_step)
    create_authentication_keys(cfg, skip_qky=skip_qky, parent_step=sid)

    root_qky = os.path.join(keys_dir, "root0.qky")
    root_private = os.path.join(keys_dir, "root0_private.pem")
    if not (os.path.isfile(root_qky) and os.path.isfile(root_private)):
        raise RuntimeError(
            "Required Quartus authentication keys are missing.\n"
            f"Expected files:\n  - {root_qky}\n  - {root_private}"
        )

    sid = print_step(2, "Create and activate BKPS signing key on server...", parent=parent_step)
    register_bkps_signing_key(cfg, parent_step=sid)

    print_step(3, "Creating sealing key...", parent=parent_step)
    _runner(cfg, "sealing-key", "create")
    print_success("Sealing key ready")

    print_step(4, "Creating import key...", parent=parent_step)
    _runner(cfg, "service-import-key", "create")
    print_success("Import key ready")

    print_step(5, "Exporting import public key...", parent=parent_step)
    import_pubkey_out = os.path.join(keys_dir, "bkps_import_pubkey.pem")
    result = _runner(cfg, "service-import-pub-key", "get", capture=True)
    if result.returncode == 0 and result.stdout:
        with open(import_pubkey_out, "w") as f:
            f.write(result.stdout)
        print_success(f"Import public key exported: {import_pubkey_out}")
    else:
        raise RuntimeError(
            "Import key was created, but failed to export import public key.\n"
            "Run manually: python3 runner.py service-import-pub-key get"
        )

    print_step(6, "Rotating context key...", parent=parent_step)
    _runner(cfg, "context-key", "rotate")
    print_success("Context key ready")


# ---------------------------------------------------------------------------
# AES Configuration
# ---------------------------------------------------------------------------

_REFERENCE_TEMPLATE_MARKER_SUFFIX = ".reference-template.sha256"


def _atomic_write_text(path: str, text: str) -> None:
    """Atomically replace *path* with UTF-8 *text* in the same directory."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".bkps-config-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _reference_template_digest(template_path: str) -> str:
    """Return the SHA-256 digest used to track a working file's template."""
    with open(template_path, "rb") as stream:
        return hashlib.sha256(stream.read()).hexdigest()


def _read_json_object(path: str, *, required: bool) -> Optional[dict]:
    """Load a JSON object, optionally treating a missing/invalid file as absent."""
    try:
        with open(path, "r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError):
        if required:
            raise
        return None
    if not isinstance(value, dict):
        if required:
            raise ValueError(f"Configuration JSON must contain an object: {path}")
        return None
    return value


def _generated_configuration_values(data: Optional[dict]) -> Tuple[str, str, str]:
    """Read only the generated AES, QEK, and CoRIM values from *data*."""
    if not isinstance(data, dict):
        return "", "", ""
    confidential = data.get("confidentialData")
    if not isinstance(confidential, dict):
        confidential = {}
    aes = confidential.get("aesKey")
    qek = confidential.get("qek")
    aes_value = aes.get("value", "") if isinstance(aes, dict) else ""
    qek_value = qek.get("value", "") if isinstance(qek, dict) else ""
    return str(aes_value or ""), str(qek_value or ""), str(data.get("corimUrl") or "")


def materialize_reference_configuration(
    template_path: str,
    working_path: str,
    *,
    aes_hex: str = "",
    qek_hex: str = "",
    corim_url: str = "",
    force: bool = False,
) -> bool:
    """Create a working BKPS JSON from its complete family reference template.

    The reference template owns every policy and attestation field.  Only the
    three project-generated inputs are overlaid: ``aesKey.value``,
    ``qek.value``, and ``corimUrl``.  Canonical values supplied by the current
    project take precedence; values from an older working file are retained as
    a fallback so a template migration does not discard generated artifacts.

    A sidecar SHA-256 marker prevents ordinary GUI reloads from overwriting
    deliberate operator edits.  A missing marker (legacy working file), a
    changed reference template, or ``force=True`` rebuilds the working file.

    Returns ``True`` when the working file was rebuilt and ``False`` when the
    existing marked file was already current.
    """
    if not os.path.isfile(template_path):
        raise FileNotFoundError(template_path)

    digest = _reference_template_digest(template_path)
    marker_path = working_path + _REFERENCE_TEMPLATE_MARKER_SUFFIX
    if not force and os.path.isfile(working_path):
        try:
            with open(marker_path, "r", encoding="utf-8") as stream:
                if stream.read().strip().lower() == digest:
                    return False
        except OSError:
            pass

    reference = _read_json_object(template_path, required=True)
    existing = _read_json_object(working_path, required=False)
    old_aes, old_qek, old_corim = _generated_configuration_values(existing)

    confidential = reference.get("confidentialData")
    if not isinstance(confidential, dict):
        raise ValueError(
            f"Reference template is missing object confidentialData: {template_path}"
        )
    aes = confidential.get("aesKey")
    if not isinstance(aes, dict) or "value" not in aes:
        raise ValueError(
            f"Reference template is missing confidentialData.aesKey.value: {template_path}"
        )

    effective_aes = str(aes_hex or old_aes or "").lower()
    effective_qek = str(qek_hex or old_qek or "").lower()
    effective_corim = str(corim_url or old_corim or "")
    if effective_aes:
        aes["value"] = effective_aes
    qek = confidential.get("qek")
    if effective_qek and isinstance(qek, dict) and "value" in qek:
        qek["value"] = effective_qek
    if effective_corim and "corimUrl" in reference:
        reference["corimUrl"] = effective_corim

    serialized = json.dumps(reference, indent=2) + "\n"
    _atomic_write_text(working_path, serialized)
    _atomic_write_text(marker_path, digest + "\n")
    return True

def prepare_aes_configuration(cfg: Config) -> None:
    """Copy template JSON and replace placeholder hex value with real AES cert hex."""
    # Default: create in quartus_keys_dir with hardcoded name
    prepare_aes_configuration_named(cfg, None)


def prepare_aes_configuration_named(cfg: Config, config_name: str = None,
                                    corim_url: str = None) -> None:
    """Copy the family template and inject the signed AES cert hex (and QEK hex when present).

    Args:
        config_name: Output name; None writes ``agilex5_config.json`` in quartus_keys_dir, otherwise ``bkps_configs/{name}.json``.
        corim_url: Optional override for the generated JSON ``corimUrl`` field.
    """
    print_header("Preparing AES Configuration")

    keys_dir = cfg.quartus_keys_dir
    ccert_path = os.path.join(keys_dir, "signed_aes_efuse.ccert")

    if not os.path.isfile(ccert_path):
        print_error("signed_aes_efuse.ccert not found!")
        raise FileNotFoundError(ccert_path)

    cert_size = os.path.getsize(ccert_path)
    print_info(f"Certificate file size: {cert_size} bytes")

    print_step(1, "Getting hex value of signed AES certificate...")
    with open(ccert_path, "rb") as f:
        hex_value = f.read().hex()
    if not hex_value:
        raise RuntimeError("Failed to extract hex value from signed_aes_efuse.ccert")
    print_success(f"Hex value extracted ({len(hex_value)} characters)")
    print_info(f"First 64 characters: {hex_value[:64]}...")
    print_info(f"Last  64 characters: ...{hex_value[-64:]}")

    print_step(2, "Loading template and creating config file...")
    admin_tools_dir = os.path.join(cfg.bkps_dir, "admin-tools")
    profile = (cfg.profile_name or "").strip().lower()
    template_name = next(
        (tpl for _, (pname, _, _, tpl) in DEVICE_FAMILIES.items()
         if pname == profile),
        None,
    )
    template = (
        os.path.join(admin_tools_dir, template_name) if template_name else None
    )

    # Determine destination path
    if config_name:
        # Create in bkps_configs/ with user-specified name
        configs_dir = os.path.join(cfg.bkps_dir, "bkps_configs")
        os.makedirs(configs_dir, exist_ok=True)
        # Ensure .json extension
        if not config_name.endswith('.json'):
            config_name += '.json'
        dest = os.path.join(configs_dir, config_name)
        print_info(f"Creating config: {config_name}")
    else:
        # Default: in quartus_keys_dir
        dest = os.path.join(keys_dir, "agilex5_config.json")

    # Load template as JSON and update only required fields.
    if template:
        with open(template, "r", encoding="utf-8") as f:
            data = json.load(f)
        print_success(f"Template loaded: {os.path.basename(template)}")
    else:
        existing = []
        if os.path.isdir(admin_tools_dir):
            try:
                existing = sorted(
                    f for f in os.listdir(admin_tools_dir)
                    if f.lower().startswith("sample") and f.lower().endswith(".json")
                )
            except Exception:
                existing = []
        print_warning(
            "Expected one of: "
            f"{', '.join(tpl for _, (_, _, _, tpl) in DEVICE_FAMILIES.items())}. "
            f"Found sample JSON files: {existing if existing else 'none'}"
        )

    if corim_url:
        data["corimUrl"] = corim_url
        print_info(f"corimUrl set: {corim_url}")

    conf = data.get("confidentialData")
    if not isinstance(conf, dict):
        raise RuntimeError("Template is missing object: confidentialData")
    aes_key_obj = conf.get("aesKey")
    if not isinstance(aes_key_obj, dict):
        raise RuntimeError("Template is missing object: confidentialData.aesKey")

    old_aes = aes_key_obj.get("value", "")
    aes_key_obj["value"] = hex_value
    print_info(f"Updated aesKey.value (template: {len(old_aes)} chars -> new: {len(hex_value)} chars)")

    # Replace qek.value if the template has one.
    # HSM flow produces aes_hsm_root.qek; non-HSM flow produces aes_root.qek.
    qek_obj = conf.get("qek")
    if isinstance(qek_obj, dict) and "value" in qek_obj:
        qek_candidates = [
            os.path.join(keys_dir, "aes_hsm_root.qek"),
            os.path.join(keys_dir, "aes_root.qek"),
        ]
        qek_file = next((p for p in qek_candidates if os.path.isfile(p)), "")
        if os.path.isfile(qek_file):
            with open(qek_file, "rb") as f:
                qek_hex = f.read().hex()
            qek_obj["value"] = qek_hex
            print_info(f"Updated qek.value from {os.path.basename(qek_file)} ({len(qek_hex)} chars)")
        else:
            print_warning("qek.value placeholder found in template but no .qek file found — leaving placeholder")
            print_warning(
                "Expected one of: "
                f"{os.path.join(keys_dir, 'aes_hsm_root.qek')}, "
                f"{os.path.join(keys_dir, 'aes_root.qek')}"
            )

    with open(dest, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    print_step(3, "Configuration ready for review")
    print_success(f"File created: {dest}")

    # Display truncated preview
    with open(dest) as f:
        data = json.load(f)
    for field in ["aesKey", "qek"]:
        if field in data.get("confidentialData", {}):
            v = data["confidentialData"][field].get("value", "")
            if len(v) > 64:
                data["confidentialData"][field]["value"] = f"{v[:32]}...{v[-32:]}"
    print(json.dumps(data, indent=2))

    print_info("\nNext step: Review the configuration file")
    print_info(f"  cat {dest}")
    print_info("\nThen validate and upload when ready")


def validate_aes_configuration(cfg: Config) -> bool:
    """Validate default agilex5_config.json in quartus_keys_dir. Returns True if valid."""
    config_path = os.path.join(cfg.quartus_keys_dir, "agilex5_config.json")
    return validate_aes_configuration_file(cfg, config_path)


def validate_aes_configuration_file(cfg: Config, config_path: str, parent_step=None) -> bool:
    """Validate any AES config JSON file. Returns True if valid.

    Args:
        parent_step: When set, print inner steps as parent.1, parent.2, ...
    """
    print_header("Validating AES Configuration File")

    print_info(f"Config file: {config_path}")

    print_step(1, "Checking file size...", parent=parent_step)
    if not os.path.isfile(config_path):
        print_error(f"Configuration file not found: {config_path}")
        return False
    size = os.path.getsize(config_path)
    if size == 0:
        print_error("Configuration file is empty")
        return False
    print_success(f"File size: {size} bytes")

    print_step(2, "Validating JSON format...", parent=parent_step)
    try:
        with open(config_path) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print_error(f"Invalid JSON format: {e}")
        return False
    print_success("JSON format is valid")

    print_step(3, "Validating required fields...", parent=parent_step)
    if "confidentialData" not in data:
        print_error("Missing required field: confidentialData")
        return False
    conf = data["confidentialData"]
    if "aesKey" not in conf:
        print_error("Missing field: confidentialData.aesKey")
        return False
    if "value" not in conf["aesKey"]:
        print_error("Missing field: confidentialData.aesKey.value")
        return False

    hex_val = conf["aesKey"]["value"]
    if not isinstance(hex_val, str):
        print_error(f"aesKey.value must be a string, got {type(hex_val).__name__}")
        return False
    if len(hex_val) % 2 != 0:
        print_error(f"Hex value has odd length ({len(hex_val)}), must be even")
        return False
    try:
        int(hex_val, 16)
    except ValueError:
        print_error("Invalid hex characters in aesKey.value")
        return False

    print_success(f"All required fields present")
    print_success(f"Hex value format valid ({len(hex_val)} characters)")

    # Validate qek.value if present — BKPS rejects non-hex or placeholder values
    if "qek" in conf and "value" in conf["qek"]:
        qek_val = conf["qek"]["value"]
        if not isinstance(qek_val, str) or not qek_val:
            print_error("confidentialData.qek.value is missing or not a string")
            return False
        try:
            int(qek_val, 16)
        except ValueError:
            print_error(f"confidentialData.qek.value contains non-hex characters — likely an unreplaced placeholder")
            print_info("Re-run Create QEK + ccert + Sign, then Create Configuration (BKPS Configuration tab).")
            return False
        print_success(f"qek.value format valid ({len(qek_val)} characters)")

    print_success("Configuration file is valid and ready for upload")
    return True


def upload_aes_configuration(cfg: Config) -> None:
    """Validate then upload default agilex5_config.json to BKPS."""
    config_json = os.path.join(cfg.quartus_keys_dir, "agilex5_config.json")
    upload_aes_configuration_file(cfg, config_json)


def read_config_id(cfg: Config) -> str:
    """Return the saved BKPS configuration ID from config_id.txt, or '' if absent."""
    try:
        with open(os.path.join(cfg.bkps_dir, "config_id.txt")) as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""


def write_config_id(cfg: Config, config_id: str) -> None:
    """Persist *config_id* to ``config_id.txt`` in bkps_dir.

    Args:
        config_id: Numeric configuration ID returned by BKPS on upload.
    """
    with open(os.path.join(cfg.bkps_dir, "config_id.txt"), "w") as f:
        f.write(config_id)


def upload_aes_configuration_file(cfg: Config, config_path: str) -> None:
    """Validate then upload any AES config file to BKPS."""
    audit_log(cfg, "upload_aes_configuration", details=os.path.basename(config_path), outcome="started")
    print_header("Uploading AES Configuration to BKPS")

    print_info(f"Config file: {config_path}")

    if not os.path.isfile(config_path):
        print_error(f"Configuration file not found: {config_path}")
        print_info("Please create a config file first")
        raise FileNotFoundError(config_path)

    sid = print_step(1, "Validating configuration file...")
    if not validate_aes_configuration_file(cfg, config_path, parent_step=sid):
        raise RuntimeError("Configuration validation failed - cannot proceed with upload")

    # Preflight: BKPS must have a service import key before accepting AES config uploads
    print_step(2, "Checking BKPS key prerequisites...")
    precheck = _runner(cfg, "service-import-pub-key", "get", capture=True, check=False)
    precheck_out = (precheck.stdout or "") + (precheck.stderr or "")
    if precheck.returncode != 0:
        if _is_secure_enclave_error(precheck_out):
            _print_secure_enclave_recovery(cfg)
            _print_secure_enclave_diagnostics(cfg)
            if precheck_out.strip():
                print_info("BKPS response:")
                for line in precheck_out.splitlines():
                    print(f"    {line}")
            raise RuntimeError("BKPS secure enclave connection failed")

        print_error("BKPS Service Import Key Pair is missing")
        print_info("Run Configure BKPS Keys first (Setup Phase).")
        if precheck_out.strip():
            print_info("BKPS response:")
            for line in precheck_out.splitlines():
                print(f"    {line}")
        raise RuntimeError("Missing BKPS service import key pair")
    print_success("BKPS key prerequisites are ready")

    print_step(3, "Checking QEK alias readiness...")
    _ensure_qek_alias_ready_for_upload(cfg, config_path)

    print_step(4, "Uploading configuration to BKPS...")
    print_info(f"Target: {cfg.bkps_server_ip}:{cfg.bkps_server_port}")

    result = _runner(cfg, "configuration", "create", "--json", "-i", config_path, capture=True, check=False)
    output = (result.stdout or "") + (result.stderr or "")
    print_info("BKPS response:")
    for line in output.splitlines():
        print(f"    {line}")

    if result.returncode != 0:
        if _is_secure_enclave_error(output):
            _print_secure_enclave_recovery(cfg)
            _print_secure_enclave_diagnostics(cfg)
            raise RuntimeError("BKPS secure enclave connection failed")
        raise RuntimeError("Upload failed (runner.py returned non-zero exit code)")

    # Extract config ID from BKPS JSON response
    # NOTE: some BKPS versions return the full config object; we pick just the id field
    config_id = None
    m = re.search(r'"id"\s*:\s*(\d+)', output)
    if m:
        config_id = m.group(1)

    if config_id:
        print_success(f"Configuration uploaded successfully (ID: {config_id})")
        write_config_id(cfg, config_id)
        print_info(f"Configuration ID saved to: {os.path.join(cfg.bkps_dir, 'config_id.txt')}")
        print_info("Next step: Generate bkp_options.txt (BKPS Configuration tab).")
    else:
        if _is_secure_enclave_error(output):
            _print_secure_enclave_recovery(cfg)
            _print_secure_enclave_diagnostics(cfg)
            raise RuntimeError("BKPS secure enclave connection failed")
        if "service import key pair does not exist" in output.lower():
            print_error("BKPS rejected upload: Service Import Key Pair does not exist")
            print_info("Run Configure BKPS Keys (Setup Phase), then retry upload.")
        else:
            print_error("Failed to extract configuration ID from BKPS response")
        raise RuntimeError("Upload may have failed or ID not returned")


def list_configurations(cfg: Config) -> None:
    """Print all AES configurations registered in BKPS."""
    print_header("Listing All Configurations")
    print_info("Fetching configuration list from BKPS...")
    _runner(cfg, "configuration", "list")
    print_success("Configuration list retrieved")


def get_configuration(cfg: Config, config_id: str) -> None:
    """Print detail for a single AES configuration by its numeric ID.

    Args:
        config_id: Numeric configuration ID (from ``--list-configurations`` or Server Utilities).
    """
    print_header("Get Configuration Details")
    _runner(cfg, "configuration", "get", "--id", config_id)
    print_success(f"Configuration {config_id} details retrieved")


def update_configuration(cfg: Config, config_id: str) -> None:
    """Update an existing BKPS configuration interactively via runner.py.

    Args:
        config_id: Numeric configuration ID.
    """
    print_header("Update Configuration")
    print_info(f"Updating configuration ID: {config_id}")
    _runner(cfg, "configuration", "update", "--id", config_id, "--interactive")
    print_success(f"Configuration {config_id} updated")


def update_configuration_file(cfg: Config, config_id: str, config_path: str) -> None:
    """Update an existing BKPS configuration by ID using a JSON file."""
    print_header("Update Configuration")

    if not config_id or not config_id.strip().isdigit():
        print_error(f"Invalid configuration ID: {config_id!r}")
        raise ValueError("Configuration ID must be numeric")

    if not os.path.isfile(config_path):
        print_error(f"Configuration file not found: {config_path}")
        raise FileNotFoundError(config_path)

    print_info(f"Configuration ID: {config_id}")
    print_info(f"Config file: {config_path}")

    sid = print_step(1, "Validating configuration file...")
    if not validate_aes_configuration_file(cfg, config_path, parent_step=sid):
        raise RuntimeError("Configuration validation failed - cannot proceed with update")

    print_step(2, "Updating configuration in BKPS...")
    result = _runner(
        cfg, "configuration", "update",
        "--id", config_id,
        "--json", "-i", config_path,
        capture=True,
    )
    output = (result.stdout or "") + (result.stderr or "")
    if output.strip():
        print_info("BKPS response:")
        for line in output.splitlines():
            print(f"    {line}")
    print_success(f"Configuration {config_id} updated")


def delete_configuration(cfg: Config, config_id: str) -> None:
    """Delete an AES configuration from BKPS and clear matching ``config_id.txt``.

    Args:
        config_id: Numeric configuration ID.
    """
    audit_log(cfg, "delete_configuration", details=f"id={config_id}", outcome="started")
    print_header("Deleting Configuration")
    if not config_id:
        print_error("Configuration ID is required")
        print_info("Use Server Utilities → Get Configuration to find the ID")
        raise ValueError("Configuration ID required")

    if not config_id.isdigit():
        print_error(f"Invalid configuration ID: {config_id}")
        raise ValueError("Configuration ID must be numeric")

    print_warning(f"Deleting configuration ID: {config_id}...")
    result = _runner(cfg, "configuration", "delete", "--id", config_id, capture=True, check=False)
    if result.returncode == 0:
        print_success(f"Configuration {config_id} deleted successfully")
        # Remove saved config_id.txt if it matches
        if read_config_id(cfg) == config_id:
            try:
                os.remove(os.path.join(cfg.bkps_dir, "config_id.txt"))
                print_info("Removed saved config_id.txt")
            except FileNotFoundError:
                pass  # Already gone — no action needed
    else:
        print_error(f"Failed to delete configuration (exit code: {result.returncode})")
        raise RuntimeError("Delete failed")


# ── Prefetch ──────────────────────────────────────────────────────────────

def run_prefetch(cfg: Config, family_id: str, device_id: str,
                 pdi: str = "", er_cert: str = "") -> None:
    """Send a prefetch request to BKPS for a specific device.

    Args:
        family_id: Hex family ID (e.g. ``0x35`` for Agilex 5).
        device_id: Device UID hex string.
        pdi: Optional PDI hex string.
        er_cert: Optional path to a DeviceID ER certificate file.
    """
    print_header("Running Prefetch")
    if not family_id:
        raise ValueError("Family ID is required (e.g. 0x35)")
    if not device_id:
        raise ValueError("Device ID is required (e.g. 0102030405060708)")
    args = ["prefetch", "--familyId", family_id, "--deviceId", device_id]
    if pdi:
        args += ["--pdi", pdi]
    if er_cert:
        if not os.path.isfile(er_cert):
            raise FileNotFoundError(f"DeviceID ER Cert not found: {er_cert}")
        args += ["--deviceIdErCert", er_cert]
    print_info(f"Family ID: {family_id}  Device ID: {device_id}")
    if pdi:
        print_info(f"PDI: {pdi}")
    if er_cert:
        print_info(f"ER Cert: {er_cert}")
    _runner(cfg, *args)
    print_success("Prefetch completed")


def run_prefetch_status(cfg: Config, device_id: str = "", family_id: str = "") -> None:
    """Query prefetch status from BKPS, optionally filtered by device or family.

    Args:
        device_id: Optional device UID hex filter.
        family_id: Optional family ID hex filter.
    """
    print_header("Prefetch Status")
    args = ["prefetch-status"]
    if device_id:
        args += ["--deviceId", device_id]
    if family_id:
        args += ["--familyId", family_id]
    _runner(cfg, *args)
    print_success("Prefetch status retrieved")


# ── CM provisioning bundle generation ───────────────────────────────────────

_THUMBPRINT_RE = re.compile(r"[0-9A-F]{40}")


def _certificate_sha1_thumbprint(cert_path: str) -> str:
    """Return the Windows-style SHA-1 thumbprint of a PEM certificate."""
    try:
        with open(cert_path, "r", encoding="ascii", errors="replace") as fh:
            pem = fh.read()
        der = ssl.PEM_cert_to_DER_cert(pem)
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            f"Cannot read programmer certificate {cert_path}: {exc}"
        ) from exc
    return hashlib.sha1(der).hexdigest().upper()


def _parse_imported_thumbprint(stdout: str, pfx_path: str) -> str:
    """Return the single thumbprint reported by ``Import-PfxCertificate``.

    A PFX carrying a chain makes the cmdlet emit one thumbprint per line,
    which would otherwise land in bkp_options.txt as a multi-line value
    that Quartus cannot parse.
    """
    found = [
        token
        for token in (
            line.strip().replace(" ", "").upper()
            for line in (stdout or "").splitlines()
        )
        if _THUMBPRINT_RE.fullmatch(token)
    ]
    if len(found) != 1:
        raise RuntimeError(
            f"Expected exactly one certificate thumbprint from {pfx_path}, "
            f"found {len(found)}. PowerShell output:\n{(stdout or '').strip()}"
        )
    return found[0]


def create_bkp_config(cfg: Config, config_id_override: str = None) -> None:
    """Write bkp_options.txt and copy programmer credentials for CM provisioning.

    Args:
        config_id_override: Numeric ID to use instead of ``config_id.txt``.
    """
    print_header("Generating Provisioning bkp_options.txt")

    if config_id_override:
        config_id = config_id_override.strip()
        if not config_id.isdigit():
            print_error(f"Config ID must be numeric, got: {config_id!r}")
            raise ValueError(f"Invalid config ID: {config_id!r}")
        # A supplied ID that disagrees with the last created configuration
        # silently provisions against a configuration the server may not
        # have, so surface it here instead of at prefetch time.
        recorded_config_id = read_config_id(cfg)
        if recorded_config_id and recorded_config_id != config_id:
            print_error(
                f"Supplied config ID {config_id} does not match the last "
                f"created configuration {recorded_config_id}."
            )
            print_info(
                f"Recorded in: {os.path.join(cfg.bkps_dir, 'config_id.txt')}"
            )
            print_info(
                "Clear the Config ID field to use the recorded ID, or run "
                "Create Configuration to create a new one."
            )
            raise RuntimeError(
                f"Config ID mismatch: supplied {config_id}, "
                f"recorded {recorded_config_id}"
            )
        print_info(f"Using supplied config ID: {config_id}")
    else:
        config_id = read_config_id(cfg)
        if not config_id:
            id_file = os.path.join(cfg.bkps_dir, "config_id.txt")
            print_error("Configuration ID file not found")
            print_info(f"Expected: {id_file}")
            print_info("This step is separate from creating the AES JSON config file.")
            print_info("Run Create Configuration (BKPS Configuration tab) first.")
            raise FileNotFoundError(id_file)

    cm_dir = cfg.cm_provisioning_dir
    os.makedirs(cm_dir, exist_ok=True)

    source_ca_cert      = os.path.join(cfg.bkps_dir, "keys", "bkps_ssl_cert", "bkps_ssl_cert.crt")
    source_prog_cert    = os.path.join(cfg.quartus_keys_dir, "programmer_bkps_signed.crt")
    source_prog_key     = os.path.join(cfg.quartus_keys_dir, "programmer_private.pem")
    source_prog_pfx     = os.path.join(cfg.quartus_keys_dir, "programmer.pfx")
    required_files = [source_ca_cert, source_prog_cert, source_prog_key]
    missing = [path for path in required_files if not os.path.isfile(path)]
    if missing:
        print_error("Required credential files are missing")
        for path in missing:
            print_error(f"  - {path}")
        raise FileNotFoundError("Missing files required for CM provisioning package")

    creds_dir = os.path.join(cm_dir, "programmer_credentials")
    os.makedirs(creds_dir, exist_ok=True)

    copied_ca_cert   = os.path.join(creds_dir, "bkps_ssl_cert.crt")
    copied_prog_cert = os.path.join(creds_dir, "programmer_cert.crt")
    copied_prog_key  = os.path.join(creds_dir, "programmer_private.pem")

    try:
        shutil.copy2(source_ca_cert,   copied_ca_cert)
        shutil.copy2(source_prog_cert, copied_prog_cert)
        shutil.copy2(source_prog_key,  copied_prog_key)
    except OSError as e:
        raise RuntimeError(
            f"Failed to copy credentials to {creds_dir}: {e}\n"
            "Check disk space and folder permissions."
        ) from e

    print_info(f"Copied CM credential files to: {creds_dir}")

    # Do not quote Linux paths — Quartus keeps the quote characters in get_config
    # and curl then fails to open the cert/key (error 58).
    options = (
        f"bkp_cfg_id = {config_id}\n"
        f"bkp_ip = {cfg.bkps_server_ip}\n"
        f"bkp_port = {cfg.bkps_server_port}\n"
        f"bkp_tls_ca_cert = \"{copied_ca_cert}\"\n"
    )

    is_windows = sys.platform.startswith("win")
    if is_windows:
        print_info(f"Importing {source_prog_pfx} into Windows Certificate Store CurrentUser\\Personal(MY) ...")
        # Import the PFX into CurrentUser\My and return the thumbprint
        ps_script = rf"""
        $password = ConvertTo-SecureString "{cfg.programmer_cert_password}" -AsPlainText -Force
        $cert = Import-PfxCertificate `
            -FilePath "{source_prog_pfx}" `
            -Password $password `
            -CertStoreLocation Cert:\\CurrentUser\\My

        $cert.Thumbprint
        """
        result = _ps_run(ps_script, capture=True, check=True)
        thumbprint = _parse_imported_thumbprint(result.stdout, source_prog_pfx)
        # The store entry must be the certificate BKPS registered for this
        # programmer. A PFX left over from an earlier run imports cleanly but
        # authenticates as an identity the server no longer knows, which the
        # BKP plugin only reports as a transport-level failure.
        expected_thumbprint = _certificate_sha1_thumbprint(source_prog_cert)
        if thumbprint != expected_thumbprint:
            print_error(
                "The imported PFX is not the current programmer certificate."
            )
            print_info(f"  {source_prog_pfx}: {thumbprint}")
            print_info(f"  {source_prog_cert}: {expected_thumbprint}")
            print_info(
                "Run Create Programmer User so the PFX, the certificate, and "
                "the identity registered in BKPS come from the same run."
            )
            raise RuntimeError(
                f"Programmer certificate mismatch: PFX {thumbprint} does not "
                f"match certificate {expected_thumbprint}"
            )
        print_success(f"Programmer certificate verified: {thumbprint}")
        options += f"bkp_tls_prog_cert = \"CurrentUser\\MY\\{thumbprint}\"\n"
    else:
        options += f"bkp_tls_prog_cert = \"{copied_prog_cert}\"\n"
        options += f"bkp_tls_prog_key = \"{copied_prog_key}\"\n"

    if cfg.profile_name == "agilex5":
        options += f"bkp_device_opn = {cfg.device_part}\n"
    with open(os.path.join(cm_dir, "bkp_options.txt"), "w") as f:
        f.write(options)
    print_success("BKP options file created")
    print_info(f"Configuration ID: {config_id}")

    # Copy root0.qky — required by the CM provisioning bundle
    root_qky_src = os.path.join(cfg.quartus_keys_dir, "root0.qky")
    if os.path.isfile(root_qky_src):
        root_qky_dst = os.path.join(cm_dir, "root0.qky")
        shutil.copy2(root_qky_src, root_qky_dst)
        print_success(f"Copied root0.qky to: {root_qky_dst}")
    else:
        print_warning(f"root0.qky not found at: {root_qky_src}")
        print_warning("The CM provisioning bundle is incomplete without root0.qky.")


# ── Internal helpers ──────────────────────────────────────────────────────────────

def _write_runner_config(cfg: Config, path: str, cert: str, certificate_key: str = None) -> None:
    """Write runner-config.json for admin-tools/runner.py.

    Args:
        path: Destination file path.
        cert: Admin certificate path for mTLS (may be empty).
        certificate_key: Admin private key path; defaults to ``keys/super_admin_private.pem``.
    """
    ssl_cert = os.path.join(cfg.bkps_dir, "keys", "bkps_ssl_cert", "bkps_ssl_cert.crt")
    if certificate_key is None:
        certificate_key = os.path.join(cfg.bkps_dir, "keys", "super_admin_private.pem")

    data = {
        "service_url":     cfg.bkps_server_ip,
        "service_port":    int(cfg.bkps_server_port),
        "certificate_key": certificate_key,
        "certificate":     cert,
        "certificate_ca":  ssl_cert,
        "system_proxy":    "",
        "debug":           False,
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def _runner_capture_retry(cfg: Config, *args, attempts: int = 6, delay_sec: int = 5, stage: str = ""):
    """Run a runner.py command, retrying on transient BKPS/auth failures.

    Args:
        *args: Positional arguments forwarded to _runner.
        attempts: Maximum number of attempts.
        delay_sec: Seconds to wait between attempts.
        stage: Optional label included in retry warnings.
    """
    last_result = None
    for attempt in range(1, attempts + 1):
        result = _runner(cfg, *args, capture=True, check=False)
        last_result = result
        if result.returncode == 0:
            return result
        if attempt < attempts:
            stage_label = f" ({stage})" if stage else ""
            print_warning(
                f"runner.py {' '.join(args)} failed{stage_label} "
                f"(attempt {attempt}/{attempts}), retrying in {delay_sec}s..."
            )
            time.sleep(delay_sec)
    return last_result


def _extract_user_id_from_create_output(output: str) -> str:
    """Extract a numeric user ID from runner.py ``user create`` output.

    Args:
        output: Combined stdout/stderr from the create command.
    """
    if not output:
        return ""

    patterns = [
        r'"id"\s*:\s*(\d+)',
        r'\bid\s*[:=]\s*(\d+)\b',
        r'\buser\s+id\s*[:=]\s*(\d+)\b',
    ]
    for pattern in patterns:
        match = re.search(pattern, output, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def _user_has_role(user_list: str, user_id: str, role: str) -> bool:
    """Return True if a user-list snapshot associates *user_id* with *role*.

    Args:
        user_list: Raw text from ``runner.py user list``.
        user_id: Numeric user ID to match.
        role: Role name to search for on the same row/block.
    """
    if not user_list or not user_id or not role:
        return False

    table_pattern = rf"^\|?\s*{re.escape(user_id)}\s*(?:\||\s).*\b{re.escape(role)}\b"
    if re.search(table_pattern, user_list, flags=re.IGNORECASE | re.MULTILINE):
        return True

    json_pattern = rf'"id"\s*:\s*{re.escape(user_id)}[\s\S]{{0,400}}\b{re.escape(role)}\b'
    if re.search(json_pattern, user_list, flags=re.IGNORECASE):
        return True

    return False

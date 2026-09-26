#!/usr/bin/env python3
"""SoftHSM PKCS#11 key operations for Agilex 5 AES provisioning."""

import os
import re
import subprocess
from bkps_config import Config, configure_system_softhsm_defaults
from bkps_windows_runtime import configure_windows_softhsm_defaults, windows_softhsm_root
from bkps_printer import (
    print_header, print_step, print_success, print_warning,
    print_error, print_info,
)
from bkps_runner import run
from bkps_server_setup import import_aes_key_to_bc_keystore
from bkps_keys import _qe, _qpfg, _qs, _assert_file
from bkps_server import start_bkps_server, stop_bkps_server
from bkps_autosetup import _check_server_running, _wait_for_runner_health
from bkps_config import aes_ccert_requires_iv


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _pkcs11_tool(cfg: Config) -> str:
    """Return cfg.pkcs11_tool_path if set, otherwise the command name pkcs11-tool."""
    configure_windows_softhsm_defaults(cfg)
    configured = (getattr(cfg, "pkcs11_tool_path", "") or "").strip()
    return configured or "pkcs11-tool"


def _softhsm_util(cfg: Config) -> str:
    """Return cfg.softhsm_util_path if set, otherwise the command name softhsm2-util."""
    configure_windows_softhsm_defaults(cfg)
    configured = (getattr(cfg, "softhsm_util_path", "") or "").strip()
    return configured or "softhsm2-util"


def _softhsm_cwd(cfg: Config) -> str | None:
    """Return the directory of cfg.softhsm_lib_path so softhsm2-util can resolve its DLL, or None."""
    configure_windows_softhsm_defaults(cfg)
    lib = (getattr(cfg, "softhsm_lib_path", "") or "").strip()
    if lib and os.path.isfile(lib):
        return os.path.dirname(lib) or None
    return None


def _softhsm_env(cfg: Config) -> dict:
    """Return os.environ with SOFTHSM2_CONF set when cfg.softhsm_conf_path is configured."""
    configure_windows_softhsm_defaults(cfg)
    configure_system_softhsm_defaults(cfg)
    env = os.environ.copy()
    conf = cfg.softhsm_conf_path.strip() if cfg.softhsm_conf_path else ""
    if conf:
        env["SOFTHSM2_CONF"] = conf
    if os.name == "nt":
        root = windows_softhsm_root()
        runtime_dirs = [os.path.join(root, "bin"), os.path.join(root, "lib")]
        existing = env.get("PATH", "")
        env["PATH"] = os.pathsep.join(
            [path for path in runtime_dirs if os.path.isdir(path)] + ([existing] if existing else [])
        )
    return env


def _quartus_softhsm_env(cfg: Config) -> dict:
    """Return the complete child environment for Quartus PKCS#11 loading.

    Quartus uses an embedded Python process to load the configured provider.
    That child needs the same ``SOFTHSM2_CONF`` and Windows runtime search
    directories as ``pkcs11-tool`` in addition to the headless Qt settings.
    """
    env = _softhsm_env(cfg)
    env.update({"QT_QPA_PLATFORM": "offscreen", "DISPLAY": ""})
    return env


def _validate_softhsm_module_for_quartus(cfg: Config) -> str:
    """Fail before key generation unless the selected provider is loadable."""
    configure_windows_softhsm_defaults(cfg)
    configure_system_softhsm_defaults(cfg)
    provider = (getattr(cfg, "softhsm_lib_path", "") or "").strip()
    if not provider or not os.path.isfile(provider):
        raise RuntimeError(
            "SoftHSM PKCS#11 provider not found. Configure SOFTHSM_LIB_PATH "
            f"with a valid library path; current value: {provider or '[empty]'}"
        )
    if "libspdm" in os.path.basename(provider).lower():
        raise RuntimeError(
            "SOFTHSM_LIB_PATH points to the BKPS SPDM wrapper, not a SoftHSM "
            f"PKCS#11 provider: {provider}"
        )

    env = _quartus_softhsm_env(cfg)
    conf = env.get("SOFTHSM2_CONF", "").strip()
    if not conf or not os.path.isfile(conf):
        raise RuntimeError(
            "SoftHSM configuration not found. Configure SOFTHSM_CONF_PATH "
            f"with a valid softhsm2.conf path; current value: {conf or '[empty]'}"
        )

    result = run(
        [_pkcs11_tool(cfg), "--module", provider, "--show-info"],
        cwd=os.path.dirname(provider) or None,
        env=env,
        capture=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown loader error").strip()
        detail = " ".join(detail.split())[:400]
        raise RuntimeError(
            f"SoftHSM provider could not be loaded for Quartus: {provider}. "
            f"{detail}"
        )

    print_success("SoftHSM provider preflight passed for Quartus")
    return provider


def _pkcs11(cfg: Config, args: list, check: bool = False):
    """Run pkcs11-tool with module, login, and PIN args pre-filled.

    Args:
        args: Additional pkcs11-tool arguments after the standard auth flags.
        check: If True, raise on non-zero exit code.
    """
    return run(
        [_pkcs11_tool(cfg),
         "--module", cfg.softhsm_lib_path,
         "--login", "--pin", cfg.softhsm_user_pin,
         ] + args,
        check=check,
        cwd=_softhsm_cwd(cfg),
        env=_softhsm_env(cfg),
    )


def _resolve_slot(cfg: Config) -> str:
    """Return the slot ID string for cfg.softhsm_token_label, or '' if not found."""
    try:
        result = subprocess.run(
            [_softhsm_util(cfg), "--show-slots"],
            capture_output=True, text=True,
            cwd=_softhsm_cwd(cfg),
            env=_softhsm_env(cfg),
        )
        output = result.stdout + result.stderr
        # Parse blocks: find the slot that contains our token label.
        # softhsm2-util output format:
        #   Slot 0
        #     Slot info: ...
        #     Token info:
        #       ...
        #       Token label: AlteraAESToken
        slot_id = ""
        current_slot = ""
        for line in output.splitlines():
            m = re.match(r"^Slot (\d+)", line.strip())
            if m:
                current_slot = m.group(1)
            if cfg.softhsm_token_label in line and current_slot:
                slot_id = current_slot
                break
    except Exception:
        slot_id = ""
    return slot_id


def _token_exists(cfg: Config) -> bool:
    """Return True if a token with cfg.softhsm_token_label exists."""
    return bool(_resolve_slot(cfg))


def _list_slot_ids(cfg: Config) -> list:
    """Return slot IDs from softhsm2-util --show-slots, in print order."""
    try:
        result = subprocess.run(
            [_softhsm_util(cfg), "--show-slots"],
            capture_output=True, text=True,
            cwd=_softhsm_cwd(cfg),
            env=_softhsm_env(cfg),
        )
    except Exception:
        return []

    output = (result.stdout or "") + (result.stderr or "")
    slots: list = []
    for line in output.splitlines():
        m = re.match(r"^Slot\s+(\d+)\b", line.strip())
        if m and m.group(1) not in slots:
            slots.append(m.group(1))
    return slots


# ── Public API ──────────────────────────────────────────────────────────────────

def softhsm_show_slots(cfg: Config) -> None:
    """Print all SoftHSM slots and token information."""
    print_header("SoftHSM Slots")
    run([_softhsm_util(cfg), "--show-slots"],
        cwd=_softhsm_cwd(cfg), env=_softhsm_env(cfg))


def _quartus_aes_key_line(aes_hex: str) -> str:
    """Format a 64-char hex AES-256 key as Quartus' 8-word --aes_key line.

    Args:
        aes_hex: 64-character hex string.
    """
    s = (aes_hex or "").strip()
    if len(s) != 64 or not all(c in "0123456789abcdefABCDEF" for c in s):
        raise ValueError(
            f"AES key must be exactly 64 hex characters, got {len(s)}."
        )
    return " ".join(f"0x{s[i:i + 8].upper()}" for i in range(0, 64, 8))


def _write_quartus_aes_key_file(path: str, aes_hex: str) -> None:
    """Write *aes_hex* to *path* in Quartus' ``--aes_key`` 8-word format."""
    with open(path, "w") as f:
        f.write(_quartus_aes_key_line(aes_hex) + "\n")


def _shred_files(*paths: str) -> None:
    """Best-effort delete of files containing plaintext key material."""
    for p in paths:
        try:
            if p and os.path.isfile(p):
                os.remove(p)
        except OSError:
            pass


def softhsm_init_token(cfg: Config, parent_step=None) -> None:
    """Initialize a new SoftHSM token for Agilex 5 AES key generation, skipping if the token label already exists.

    Args:
        parent_step: When set, print inner steps as parent.1, parent.2, ...
    """
    print_header("Initializing SoftHSM Token")

    util = _softhsm_util(cfg)
    env  = _softhsm_env(cfg)
    cwd  = _softhsm_cwd(cfg)

    if _token_exists(cfg):
        print_success(f"Token '{cfg.softhsm_token_label}' already exists — skipping init")
        softhsm_show_slots(cfg)
        return

    # Fail early with a clear message when no slots are visible at all.
    # softhsm2-util --free selects the slot itself, so we don't pass --slot.
    if not _list_slot_ids(cfg):
        raise RuntimeError(
            "No SoftHSM slots reported by 'softhsm2-util --show-slots'. "
            "Verify SoftHSM is installed and its config is valid."
        )

    so_pin = (cfg.softhsm_so_pin or cfg.softhsm_user_pin or "").strip()

    print_step(1, f"Initializing token '{cfg.softhsm_token_label}'...", parent=parent_step)
    run([
        util, "--init-token", "--free",
        "--label",  cfg.softhsm_token_label,
        "--so-pin", so_pin,
        "--pin",    cfg.softhsm_user_pin,
    ], cwd=cwd, env=env)

    print_step(2, "Verifying token was created...", parent=parent_step)
    softhsm_show_slots(cfg)

    if _token_exists(cfg):
        print_success(f"Token '{cfg.softhsm_token_label}' initialized successfully")
    else:
        raise RuntimeError(
            f"Token initialization appeared to succeed but token "
            f"'{cfg.softhsm_token_label}' is not visible in --show-slots output."
        )


def softhsm_delete_token(cfg: Config) -> None:
    """Delete the SoftHSM token (and all keys inside it)."""
    print_header("Deleting SoftHSM Token")

    slot_id = _resolve_slot(cfg)
    if not slot_id:
        print_warning(f"Token '{cfg.softhsm_token_label}' not found — nothing to delete")
        return

    print_step(1, f"Deleting token at slot {slot_id}...")
    run([
        _softhsm_util(cfg), "--delete-token",
        "--token", cfg.softhsm_token_label,
    ], cwd=_softhsm_cwd(cfg), env=_softhsm_env(cfg))
    print_success("Token deleted")


def softhsm_list_objects(cfg: Config) -> None:
    """List all objects (keys, certs) in the token."""
    print_header("SoftHSM Token Objects")
    _pkcs11(cfg, ["--list-objects"])


def softhsm_delete_key(cfg: Config) -> None:
    """Delete the AES secret key with cfg.softhsm_key_label from the token, plus legacy label AESKey32 if present."""
    print_header(f"Deleting Key '{cfg.softhsm_key_label}' from SoftHSM")

    # Remove both the configured label and legacy label used by earlier flows.
    # Errors (key absent) are intentionally suppressed via check=False.
    labels = [cfg.softhsm_key_label]  # always include the current label
    if "AESKey32" not in labels:  # also clean up the legacy label if distinct
        labels.append("AESKey32")

    deleted_any = False
    for label in labels:
        result = _pkcs11(cfg, [
            "--delete-object", "--type", "secrkey",
            "--label", label,
        ], check=False)
        if result.returncode == 0:
            print_success(f"Key '{label}' deleted")
            deleted_any = True
        else:
            print_info(f"Key '{label}' not found (already absent)")

    if not deleted_any:
        print_info("No matching AES secret keys were deleted")


def softhsm_generate_aes_key(cfg: Config) -> None:
    """Generate a fresh AES-256 key directly inside SoftHSM."""
    print_header("Generating AES Key in SoftHSM")

    if not _token_exists(cfg):
        raise RuntimeError(
            f"Token '{cfg.softhsm_token_label}' not found. Run 'Init Token' first."
        )

    print_step(1, "Deleting any existing key with same label...")
    softhsm_delete_key(cfg)

    print_step(2, f"Generating AES-256 key '{cfg.softhsm_key_label}'...")
    _pkcs11(cfg, [
        "--keygen", "--key-type", "aes:32",
        "--label", cfg.softhsm_key_label,
        "--id", "01",
    ], check=True)
    print_success(f"AES-256 key '{cfg.softhsm_key_label}' generated in SoftHSM")

    print_step(3, "Listing token objects to confirm...")
    softhsm_list_objects(cfg)


def softhsm_import_aes_key(cfg: Config, aes_hex: str, parent_step=None) -> None:
    """Import a specific 256-bit AES key (64 hex chars) into SoftHSM.

    Args:
        aes_hex: 64 uppercase or lowercase hex characters representing 32 bytes.
        parent_step: When set, print inner steps as parent.1, parent.2, ...
    """
    print_header("Importing AES Key into SoftHSM")

    aes_hex = aes_hex.strip().upper()
    if len(aes_hex) != 64 or not all(c in "0123456789ABCDEF" for c in aes_hex):
        raise ValueError(
            f"Invalid AES hex key: must be exactly 64 hex characters, got {len(aes_hex)}"
        )

    if not _token_exists(cfg):
        raise RuntimeError(
            f"Token '{cfg.softhsm_token_label}' not found. Run 'Init Token' first."
        )

    keys_dir = cfg.quartus_keys_dir
    os.makedirs(keys_dir, exist_ok=True)

    print_step(1, "Resolving slot ID...", parent=parent_step)
    slot_id = _resolve_slot(cfg)
    if not slot_id:
        raise RuntimeError(f"Could not resolve slot for token '{cfg.softhsm_token_label}'")
    print_info(f"Using slot: {slot_id}")

    raw_bin = os.path.join(keys_dir, "aes_key.bin")
    with open(raw_bin, "wb") as f:
        f.write(bytes.fromhex(aes_hex))

    try:
        print_step(2, "Deleting any existing key with same label...", parent=parent_step)
        softhsm_delete_key(cfg)

        print_step(3, f"Importing AES-256 key '{cfg.softhsm_key_label}' (slot {slot_id})...", parent=parent_step)
        run([
            _pkcs11_tool(cfg),
            "--module", cfg.softhsm_lib_path,
            "--login", "--pin", cfg.softhsm_user_pin,
            "--slot", slot_id,
            "--write-object", raw_bin,
            "--type", "secrkey",
            "--key-type", "AES:32",
            "--id", "01",
            "--label", cfg.softhsm_key_label,
        ], check=True, cwd=_softhsm_cwd(cfg), env=_softhsm_env(cfg))
        print_success(f"Key '{cfg.softhsm_key_label}' imported successfully")

        print_step(4, "Listing token objects to confirm...", parent=parent_step)
        softhsm_list_objects(cfg)

    finally:
        try:
            os.remove(raw_bin)
        except OSError:
            pass





def softhsm_create_qek_and_ccert(cfg: Config, aes_hex: str = "") -> None:
    """Run the Agilex 5 AES key → QEK → ccert → sign flow using SoftHSM.

    Args:
        aes_hex: Optional 64-char hex AES key; leave empty to generate a fresh random 256-bit key.
    """
    print_header("Creating AES Root Key via SoftHSM (Agilex 5)")

    # Verify the exact provider and child-process environment before generating
    # or replacing any AES key material.
    _validate_softhsm_module_for_quartus(cfg)

    # Re-use helpers from bkps_keys to avoid code duplication.
    # QT_QPA_PLATFORM=offscreen suppresses Qt GUI warnings in headless environments.
    keys_dir = cfg.quartus_keys_dir
    os.makedirs(keys_dir, exist_ok=True)
    qt_env  = _quartus_softhsm_env(cfg)
    pfg_env = {**os.environ, "QT_QPA_PLATFORM": "offscreen", "DISPLAY": ""}

    # ------------------------------------------------------------------
    print_step(1, "Preparing AES key bytes...")
    if aes_hex:
        aes_hex = aes_hex.strip().upper()
        if len(aes_hex) != 64 or not all(c in "0123456789ABCDEF" for c in aes_hex):
            raise ValueError(
                f"Invalid AES hex: must be 64 hex characters, got {len(aes_hex)}"
            )
        aes_bytes = bytes.fromhex(aes_hex)
        print_info("Using provided AES key")
    else:
        aes_bytes = os.urandom(32)
        aes_hex   = aes_bytes.hex().upper()
        print_info("Generated fresh random AES-256 key")

    # ------------------------------------------------------------------
    sid = print_step(2, "Initializing SoftHSM token...")
    softhsm_init_token(cfg, parent_step=sid)

    # ------------------------------------------------------------------
    sid = print_step(3, "Importing AES key into SoftHSM...")
    softhsm_import_aes_key(cfg, aes_hex, parent_step=sid)

    # ------------------------------------------------------------------
    sid = print_step(4, "Importing AES key to BKPS BouncyCastle keystore...")
    import_aes_key_to_bc_keystore(cfg, aes_hex, parent_step=sid)
    print_success("AES key imported to BC keystore as 'qek_encryption_key'")

    # ------------------------------------------------------------------
    print_step(5, "Creating QEK via quartus_encrypt...")
    passphrase = (getattr(cfg, "aes_passphrase", "") or "").strip()
    if not passphrase:
        raise ValueError(
            "cfg.aes_passphrase is empty — set the AES passphrase on the "
            "Config tab before running the AES pipeline."
        )
    # The plaintext AES-key file MUST be in Quartus' 8-word
    # ``0xXXXXXXXX`` format on the first line — Quartus rejects a raw
    # 64-char hex blob with a cryptic "8 hexadecimal words" error.  We
    # write it (and the passphrase file) only inside the try block so
    # a failure earlier in the function never leaves either file on
    # disk, and the finally guarantees both are shredded on every exit.
    pass_file = os.path.join(keys_dir, "password.txt")
    hex_file  = os.path.join(keys_dir, "aes_key_hex.txt")
    try:
        with open(pass_file, "w") as f:
            f.write(passphrase)
        _write_quartus_aes_key_file(hex_file, aes_hex)
        _qe(cfg, ["--family=agilex5",
            "--operation=make_aes_key",
            f"--aes_key={hex_file}",
            f"--passphrase={pass_file}",
            "aes_root.qek"
        ], cwd=keys_dir, env=qt_env)
        print_success("QEK created")
    finally:
        _shred_files(pass_file, hex_file)
    _assert_file(keys_dir, "aes_root.qek",  "quartus_encrypt did not produce aes_root.qek")
    print_step("5.1", "Creating QEK via quartus_encrypt + SoftHSM module...")
    module_args = (
        f"--token_label={cfg.softhsm_token_label} "
        f"--user_pin={cfg.softhsm_user_pin} "
        f"--hsm_lib={cfg.softhsm_lib_path}"
    )
    _qe(cfg, [
        "--family=agilex5",
        "--operation=make_aes_key",
        "--module=softHSM",
        f"--module_args={module_args}",
        f"--keyname={cfg.softhsm_key_label}",
        "aes_hsm_root.qek",
        f"--aes_key_info=aes_keyinfo.txt",
    ], cwd=keys_dir, env=qt_env)

    # Compatibility: some Quartus environments may still emit legacy aes_32.qek.
    # If that happens, normalize to the new name so the rest of the flow is consistent.
    # TODO: Remove this rename once all Quartus versions produce aes_hsm_root.qek.
    legacy_qek = os.path.join(keys_dir, "aes_32.qek")
    new_qek = os.path.join(keys_dir, "aes_hsm_root.qek")
    if not os.path.isfile(new_qek) and os.path.isfile(legacy_qek):
        os.replace(legacy_qek, new_qek)
        print_warning("Legacy output aes_32.qek detected; renamed to aes_hsm_root.qek")

    _assert_file(keys_dir, "aes_hsm_root.qek",  "quartus_encrypt did not produce aes_hsm_root.qek")
    _assert_file(keys_dir, "aes_keyinfo.txt",   "quartus_encrypt did not produce aes_keyinfo.txt")
    print_success("QEK created: aes_hsm_root.qek + aes_keyinfo.txt")

    # ------------------------------------------------------------------
    print_step(6, "Creating unsigned AES compact certificate...")
    extra_opt = []
    if aes_ccert_requires_iv(cfg.profile_name, cfg.aes_ccert_type):
        # ``list.append`` takes exactly one argument — the previous
        # ``append("-o", …)`` call raised TypeError at runtime and
        # aborted step 6 whenever the ccert type required an IV.
        # ``extend`` with the two-token pair is the right idiom (matches
        # how the surrounding ``_qpfg([...])`` list is constructed).
        extra_opt.extend(["-o", f"iv={cfg.aes_ccert_iv}"])
    _qpfg([
        "--ccert",
        "-o", f"ccert_type={cfg.aes_ccert_type}",
        "-o", f"ccert_device={cfg.device_part}",
        "-o", "qek_file=aes_hsm_root.qek",
        "-o", "aes_key_info=aes_keyinfo.txt",
        *extra_opt,
        "unsigned_aes_efuse.ccert",
    ], cwd=keys_dir, env=pfg_env)
    _assert_file(keys_dir, "unsigned_aes_efuse.ccert", "quartus_pfg did not produce unsigned ccert")
    print_success("Unsigned certificate created")

    # ------------------------------------------------------------------
    print_step(7, "Signing AES compact certificate...")
    extra_opt = []
    if cfg.aes_cancel_id:
        extra_opt.append(f"--cancel={cfg.aes_cancel_id}")
    _qs([
        "--family=agilex5",
        "--operation=sign",
        "--qky=aesccert1_sign_chain.qky",
        "--pem=aesccert1_private.pem",
        *extra_opt,
        "unsigned_aes_efuse.ccert",
        "signed_aes_efuse.ccert",
    ], cwd=keys_dir)
    _assert_file(keys_dir, "signed_aes_efuse.ccert", "quartus_sign did not produce signed_aes_efuse.ccert")
    print_success("AES certificate signed: signed_aes_efuse.ccert")

    # ------------------------------------------------------------------
    print_step(8, "Extracting hex values for BKPS provisioning...")

    # Convert QEK to hex for JSON submission.
    # LOWERCASE: BKPS server's confidentialData.qek.value / aesKey.value
    # parser is case-sensitive and rejects uppercase hex with
    # "Failed to parse ..." — match the reference tooling in
    # bkps_configure.create_aes_configuration_file which uses the
    # Python default (lowercase) .hex().
    qek_file = os.path.join(keys_dir, "aes_hsm_root.qek")
    with open(qek_file, "rb") as f:
        qek_hex = f.read().hex()
    qek_file_out = os.path.join(keys_dir, "aes_hsm_root.qek_hex.txt")
    with open(qek_file_out, "w") as f:
        f.write(qek_hex + "\n")
    print_success(f"QEK hex extracted: {qek_file_out}")

    # Convert ccert to hex for JSON submission (also lowercase — same
    # server-side parser).
    ccert_file = os.path.join(keys_dir, "signed_aes_efuse.ccert")
    with open(ccert_file, "rb") as f:
        ccert_hex = f.read().hex()
    ccert_file_out = os.path.join(keys_dir, "signed_aes_efuse.ccert_hex.txt")
    with open(ccert_file_out, "w") as f:
        f.write(ccert_hex + "\n")
    print_success(f"CCERT hex extracted: {ccert_file_out}")

    # ------------------------------------------------------------------
    # Cleanup sensitive intermediates.  Belt-and-braces for the plaintext
    # key + passphrase files (already shredded in Step 5's finally) so no
    # code path can leave them behind.  Also drops the unsigned ccert.
    _shred_files(
        os.path.join(keys_dir, "aes_key.txt"),
        os.path.join(keys_dir, "aes_key_hex.txt"),
        os.path.join(keys_dir, "password.txt"),
        os.path.join(keys_dir, "unsigned_aes_efuse.ccert"),
    )

    # ------------------------------------------------------------------
    # Reload the running BKPS server so it picks up the new
    # ``qek_encryption_key`` we just imported into
    # ``bc-keystore-bkps-static.jks``.  Spring Boot loads the BC keystore
    # ONCE at startup and caches the SecretKey in memory, so overwriting
    # the file on disk is invisible to the running JVM.  Without this
    # restart, the very next Configuration-upload step fails with
    # "Failed to decrypt QEK data ... key that associated with the key
    # name is mismatch" because the server is decrypting our fresh
    # aes_hsm_root.qek with the STALE key it cached at boot.
    #
    # Guarded: only restart if a server is actually running — we must not
    # spin one up here for users who intentionally stopped it.

    if _check_server_running(cfg):
        print_header("Reloading BKPS Server (refresh qek_encryption_key)")
        try:
            stop_bkps_server(cfg)
            start_bkps_server(cfg)
            if not _wait_for_runner_health(cfg, timeout=180):
                print_warning(
                    "BKPS server did not report ready within 180s after "
                    "reload; the Configuration upload step may still fail. "
                    "Wait a bit and retry, or restart the server manually."
                )
            else:
                print_success(
                    "BKPS server reloaded — new qek_encryption_key is now "
                    "active in memory."
                )
        except Exception as e:
            print_warning(
                f"BKPS server reload failed: {e}\n"
                "Restart the server manually before uploading the "
                "configuration, otherwise QEK decryption will fail with "
                "the previous (stale) key."
            )
    else:
        print_info(
            "BKPS server is not running — skipping auto-reload. The new "
            "qek_encryption_key will be loaded when you next start the "
            "server."
        )

    print_success("Done. Outputs:")
    print_info(f"  {qek_file_out}         (QEK as hex for JSON submission)")
    print_info(f"  {ccert_file_out} (CCERT as hex for JSON submission)")
    print_info(f"  {os.path.join(keys_dir, 'aes_keyinfo.txt')}        (key info for reference)")
    print_info("\nNext step: Provisioning tab → Create AES Config File")

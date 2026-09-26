#!/usr/bin/env python3
"""Quartus authentication key and AES key generation for BKPS provisioning."""

import os
import re
import filecmp
from bkps_config import Config, aes_ccert_requires_iv
from bkps_printer import print_header, print_step, print_success, print_warning, print_error, print_info
from bkps_runner import run, run_runner_tool as _runner
import shutil
import subprocess, os as _os
import subprocess, os as _os, tempfile, stat, contextlib



def create_authentication_keys(cfg: Config, skip_qky: bool = False, parent_step=None) -> None:
    """Create Owner Root Key, Design Signing Key, and AES Cert Signing Key.

    Args:
        skip_qky: Skip regenerating Owner Root when root0.qky and the private PEM already exist. Design and AES keys are skipped only when their files already exist.
        parent_step: When set, print inner steps as parent.1, parent.2, ...
    """

    print_header("Creating Authentication Keys")

    keys_dir = cfg.quartus_keys_dir
    family = cfg.profile_name
    os.makedirs(keys_dir, exist_ok=True)

    # Operator supplied their own Owner Root .qky — skip Quartus creation flow.
    provided_root = (getattr(cfg, "owner_root_key_path", "") or "").strip()
    provided_pem = (getattr(cfg, "owner_root_key_private_path", "") or "").strip()
    root_qky = os.path.join(keys_dir, "root0.qky")
    root_pem = os.path.join(keys_dir, "root0_private.pem")
    root_created = False
    # ------------------------------------------------------------------ Step 1
    print_step(1, "Creating Owner Root Key...", parent=parent_step)
    if provided_root:
        if not os.path.isfile(provided_root):
            raise RuntimeError(f"cfg.owner_root_key_path points at a missing file: {provided_root}")
        if os.path.isfile(root_qky) and filecmp.cmp(provided_root, root_qky, shallow=False):
            print_info(f"root0.qky already matches cfg.owner_root_key_path ({provided_root}) — skip copy")
        else:
            shutil.copy2(provided_root, root_qky)
            print_success(f"Copied Owner Root .qky to {root_qky}")

        if provided_pem:
            if not os.path.isfile(provided_pem):
                raise RuntimeError(f"cfg.owner_root_key_private_path points at a missing file: {provided_pem}")
            if os.path.isfile(root_pem) and filecmp.cmp(provided_pem, root_pem, shallow=False):
                print_info(
                    f"root0_private.pem already matches cfg.owner_root_key_private_path "
                    f"({provided_pem}) — skip copy"
                )
            else:
                shutil.copy2(provided_pem, root_pem)
                print_success(f"Copied Owner Root private PEM to {root_pem}")
        elif not os.path.isfile(root_pem):
            print_error(
                "cfg.owner_root_key_path is set but no paired private PEM is available.\n"
                "  Provide cfg.owner_root_key_private_path — \"Configure BKPS Keys\" "
                "needs a matching private key to sign the BKPS signing chain."
            )
    else:
        root_qky_path = os.path.join(keys_dir, root_qky)
        root_pem_path = os.path.join(keys_dir, root_pem)
        if os.path.isfile(root_qky_path) and os.path.isfile(root_pem_path) and skip_qky:
            print_info(
                f"Owner Root Key already present at {root_qky_path} — skip generation"
            )
        else:
            _qs([f"--family={family}", "--operation=make_private_pem",
                "--curve=secp384r1", "--no_passphrase", root_pem],
                cwd=keys_dir)
            _assert_file(keys_dir, root_pem, f"Failed to create {root_pem}")

            _qs([f"--family={family}", "--operation=make_public_pem",
                root_pem, "root0_public.pem"], cwd=keys_dir)

            _qs([f"--family={family}", "--operation=make_root",
                "root0_public.pem", root_qky], cwd=keys_dir)
            _assert_file(keys_dir, root_qky, f"Failed to create {root_qky}")
            root_created = True
            print_success("Owner Root Key created")

    # ------------------------------------------------------------------ Step 2
    print_step(2, "Creating Design Signing Key...", parent=parent_step)
    if root_created or not (os.path.isfile(os.path.join(keys_dir, "design0_sign_chain.qky")) and os.path.isfile(os.path.join(keys_dir, "design0_sign_private.pem"))):
        _qs([f"--family={family}", "--operation=make_private_pem",
            "--curve=secp384r1", "--no_passphrase", "design0_sign_private.pem"], cwd=keys_dir)
        _qs([f"--family={family}", "--operation=make_public_pem",
            "design0_sign_private.pem", "design0_sign_public.pem"], cwd=keys_dir)
        _qs([f"--family={family}", "--operation=append_key",
            f"--previous_pem={root_pem}",
            f"--previous_qky={root_qky}",
            "--permission=6", "--cancel=0",
            "--input_pem=design0_sign_public.pem",
            "design0_sign_chain.qky"], cwd=keys_dir)
        _assert_file(keys_dir, "design0_sign_chain.qky", "Failed to create design0_sign_chain.qky")
        print_success("Design Signing Key created")
    else:
        print_info("Design Signing Key already present — skip")

    # ------------------------------------------------------------------ Step 3
    print_step(3, "Creating AES Certificate Signing Key...", parent=parent_step)
    if root_created or not (os.path.isfile(os.path.join(keys_dir, "aesccert1_sign_chain.qky")) and os.path.isfile(os.path.join(keys_dir, "aesccert1_private.pem"))):
        _qs([f"--family={family}", "--operation=make_private_pem",
            "--curve=secp384r1", "--no_passphrase", "aesccert1_private.pem"], cwd=keys_dir)
        _qs([f"--family={family}", "--operation=make_public_pem",
            "aesccert1_private.pem", "aesccert1_public.pem"], cwd=keys_dir)
        _qs([f"--family={family}", "--operation=append_key",
            f"--previous_pem={root_pem}",
            f"--previous_qky={root_qky}",
            "--permission=0x40", f"--cancel={cfg.aes_cancel_id}",
            "--input_pem=aesccert1_public.pem",
            "aesccert1_sign_chain.qky"], cwd=keys_dir)
        _assert_file(keys_dir, "aesccert1_sign_chain.qky", "Failed to create aesccert1_sign_chain.qky")
        print_success("AES Certificate Signing Key created")
    else:
        print_info("AES Certificate Signing Key already present — skip")

def register_bkps_signing_key(cfg: Config, parent_step=None) -> str:
    """Create, upload, and activate the BKPS signing key on the running server.

    Args:
        parent_step: When set, print inner steps as parent.1, parent.2, ...
    """
    # Lazy import — see the module-header NOTE.  DO NOT hoist this to the
    # top of the file: bkps_configure -> bkps_softhsm -> bkps_keys creates
    # a partial-init circular import (see traceback with `_qe` at load).
    from bkps_configure import (  # noqa: PLC0415  (intentional lazy import)
        _create_signing_key_and_get_id,
        _sign_bkps_chain,
        _quartus_create_root,
    )

    keys_dir = cfg.quartus_keys_dir

    print_step(1, "Creating BKPS signing key on server...", parent=parent_step)
    signing_key_id = _create_signing_key_and_get_id(cfg)
    print_success(f"BKPS signing key ID: {signing_key_id}")

    print_step(2, "Exporting BKPS signing public key...", parent=parent_step)
    pub_key_path = os.path.join(keys_dir, "bkps_signing_public.pem")
    try:
        os.remove(pub_key_path)
    except FileNotFoundError:
        pass
    _runner(cfg, "signing-key", "get", "--id", signing_key_id, "-o", pub_key_path)
    _assert_file(keys_dir, "bkps_signing_public.pem",
                 "Failed to export bkps_signing_public.pem")
    print_success("Public key exported")

    print_step(3, "Signing BKPS signing key with Owner Root...", parent=parent_step)
    chain_single = os.path.join(keys_dir, "bkps_signing_chain_single.qky")
    chain_multi = os.path.join(keys_dir, "bkps_signing_chain_multi.qky")
    cancel_id = cfg.bkps_signing_key_cancel_id or "0"
    if cfg.profile_name == "stratix10":
        # Native single chain uses the operator-supplied Owner Root.
        _sign_bkps_chain(
            keys_dir, family=cfg.profile_name,
            previous_pem="root0_private.pem",
            previous_qky="root0.qky",
            cancel_id=cancel_id,
            out_qky="bkps_signing_chain_single.qky",
        )
        # Multi chain needs a cross-family (agilex) root that admin-tools
        # can consume — generate a throwaway root and use it.
        stem = "root_agilex"
        if not (os.path.isfile(f"{stem}_private.pem") and os.path.isfile(f"{stem}.qky")):
            _quartus_create_root(keys_dir, family="agilex", stem=stem)
        _sign_bkps_chain(
            keys_dir, family="agilex",
            previous_pem=f"{stem}_private.pem",
            previous_qky=f"{stem}.qky",
            cancel_id=cancel_id,
            out_qky="bkps_signing_chain_multi.qky",
        )
        _runner(cfg, "root-signing-key", "add",
            "--input", os.path.join(keys_dir, "root_agilex.qky"),
            skip_if=["already exists"])
    else:
        # Native profile (agilex family) — single chain needs a cross-
        # family (stratix10) root that admin-tools can consume.
        stem = "root_stratix10"
        if not (os.path.isfile(f"{stem}_private.pem") and os.path.isfile(f"{stem}.qky")):
            _quartus_create_root(keys_dir, family="stratix10", stem=stem)
        _sign_bkps_chain(
            keys_dir, family="stratix10",
            previous_pem=f"{stem}_private.pem",
            previous_qky=f"{stem}.qky",
            cancel_id=cancel_id,
            out_qky="bkps_signing_chain_single.qky",
        )
        _sign_bkps_chain(
            keys_dir, family=cfg.profile_name,
            previous_pem="root0_private.pem",
            previous_qky="root0.qky",
            cancel_id=cancel_id,
            out_qky="bkps_signing_chain_multi.qky",
        )

        _runner(cfg, "root-signing-key", "add",
            "--input", os.path.join(keys_dir, "root_stratix10.qky"),
            skip_if=["already exists"])
    print_success("BKPS signing chain ready")

    print_step(4, "Uploading keys to BKPS...", parent=parent_step)
    # All three runner.py calls go through _runner (run_runner_tool), which
    # scans stdout for any non-2xx "Status:" line and raises RuntimeError.
    # No skip-phrase matching — HTTP status code is the sole source of truth.
    _runner(cfg, "root-signing-key", "add",
        "--input", os.path.join(keys_dir, "root0.qky"),
        skip_if=["already exists"])
    _runner(cfg, "signing-key", "upload", "--id", signing_key_id,
            "--single", chain_single,
            "--multi", chain_multi)
    _runner(cfg, "signing-key", "activate", "--id", signing_key_id)

    # Post-verify: even with strict HTTP-status checking in _runner, re-read
    # signing-key list and make sure the key we just registered is not left
    # in status=DISABLED with an empty chain (belt-and-braces).
    _verify_signing_key_active(cfg, signing_key_id)
    print_success("Keys uploaded and activated")

    return signing_key_id


def _verify_signing_key_active(cfg: Config, signing_key_id: str) -> None:
    """Confirm the just-registered BKPS signing key is ENABLED with populated chains.

    Args:
        signing_key_id: Server-assigned numeric signing-key ID as a string.
    """
    from bkps_configure import _signing_key_list_raw  # noqa: PLC0415
    import json  # noqa: PLC0415  (small, keeps top imports tidy)

    text = _signing_key_list_raw(cfg)

    # runner.py prints framing lines ("---------------------", "Status: 200 OK",
    # etc.) before the JSON body.  Extract the outermost JSON array/object.
    match = re.search(r'(\[.*\]|\{.*\})', text, re.DOTALL)
    entries = []
    if match:
        try:
            payload = json.loads(match.group(1))
            if isinstance(payload, list):
                entries = payload
            elif isinstance(payload, dict):
                entries = [payload]
        except json.JSONDecodeError:
            entries = []

    entry = next(
        (e for e in entries
         if str(e.get("signingKeyId", e.get("id", ""))) == str(signing_key_id)),
        None,
    )
    if entry is None:
        raise RuntimeError(
            f"BKPS signing-key {signing_key_id} not present in server list "
            f"after upload+activate.  runner.py may have silently swallowed "
            f"an HTTP failure — inspect the log above for a 'Status: 4xx/5xx' line."
        )

    status = str(entry.get("status", "?"))
    chain_empty = not entry.get("chain")
    multi_empty = not entry.get("multiChain")

    if status.upper() != "ENABLED" or chain_empty or multi_empty:
        raise RuntimeError(
            f"BKPS signing-key {signing_key_id} is not fully registered:\n"
            f"  status      = {status!r} (expected 'ENABLED')\n"
            f"  chain empty = {chain_empty}\n"
            f"  multi empty = {multi_empty}\n"
            f"upload and/or activate reported success but the server did "
            f"not persist the chain.  This usually means the signing chain "
            f"QKYs were rejected by BKPS (wrong Owner Root Key, wrong "
            f"family, or upload HTTP 4xx swallowed by runner.py).  Re-run "
            f"Configure BKPS Keys after fixing the underlying issue."
        )
    print_info(f"Verified signing-key {signing_key_id}: status=ENABLED, chain populated.")


def create_aes_key(cfg: Config) -> None:
    """Create AES root key and unsigned ccert, then sign it (Agilex 5 uses key-info extraction; others use the .qek directly)."""
    print_header("Creating AES Root Key")

    keys_dir = cfg.quartus_keys_dir
    family = cfg.profile_name

    if (os.path.isfile(os.path.join(keys_dir, "aes_root.qek")) and
            os.path.isfile(os.path.join(keys_dir, "signed_aes_efuse.ccert"))):
        print_success("AES root key already created - skipping")
        return

    # Write passphrase file (no trailing newline)
    pass_file = os.path.join(keys_dir, "aes_pass.txt")
    with open(pass_file, "w") as f:
        f.write(cfg.aes_passphrase)

    # Disable GUI mode for Quartus tools
    qt_env = {"QT_QPA_PLATFORM": "offscreen", "DISPLAY": ""}

    # ------------------------------------------------------------------ Step 1
    print_step(1, "Generating AES root key...")
    _qe(cfg, [f"--family={family}", "--operation=MAKE_AES_KEY",
               f"--passphrase={pass_file}", "aes_root.qek"],
        cwd=keys_dir, env=qt_env)
    _assert_file(keys_dir, "aes_root.qek", "Failed to create AES root key")
    print_success("AES root key created")

    # os.environ first so our headless overrides take priority
    pfg_env = {**os.environ, "QT_QPA_PLATFORM": "offscreen", "DISPLAY": ""}

    # ---------------------------------------------------------------- Step 2 (Agilex 7)
    # Agilex 7 takes the .qek directly — no get_aes_key_info step needed.
    print_step(2, "Creating unsigned AES compact certificate...")
    extra_opt = []
    if aes_ccert_requires_iv(cfg.profile_name, cfg.aes_ccert_type):
        extra_opt.extend(["-o", f"iv={cfg.aes_ccert_iv}"])
    _qpfg([
        "--ccert",
        "-o", f"ccert_type={cfg.aes_ccert_type}",
        "-o", "qek_file=aes_root.qek",
        "-o", f"password={pass_file}",
        *extra_opt,
        "unsigned_aes_efuse.ccert",
    ], cwd=keys_dir, env=pfg_env)
    _assert_file(keys_dir, "unsigned_aes_efuse.ccert", "Failed to create unsigned AES certificate")
    print_success("Unsigned certificate created")

    # ---------------------------------------------------------------- Step 3 (Agilex 7)
    print_step(3, "Signing AES compact certificate...")
    extra_opt = []
    if cfg.aes_cancel_id:
        extra_opt.append(f"--cancel={cfg.aes_cancel_id}")
    _qs([f"--family={family}", "--operation=sign",
            "--qky=aesccert1_sign_chain.qky",
            "--pem=aesccert1_private.pem",
            *extra_opt,
            "unsigned_aes_efuse.ccert", "signed_aes_efuse.ccert"],
        cwd=keys_dir)
    _assert_file(keys_dir, "signed_aes_efuse.ccert", "Failed to sign AES certificate")
    print_success("AES certificate signed")

    # Clean up passphrase file
    try:
        os.remove(pass_file)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Internal Quartus tool wrappers
# ---------------------------------------------------------------------------

def _qs(args: list, cwd: str, env: dict = None) -> None:
    """Run quartus_sign with the given args."""
    run(["quartus_sign"] + args, cwd=cwd, env=env)


def _qe(cfg: Config, args: list, cwd: str, env: dict = None) -> None:
    """Run quartus_encrypt with the given args, filtering xterm noise from output."""
    full_env = {**_os.environ, **(env or {})}
    result = subprocess.run(
        ["quartus_encrypt"] + args,
        cwd=cwd, env=full_env,
        capture_output=True, text=True
    )
    # Quartus echoes its complete command, including --module_args. Scrub the
    # SoftHSM PIN before any child output reaches the GUI or persistent logs.
    output = result.stdout + result.stderr
    pin = (getattr(cfg, "softhsm_user_pin", "") or "").strip()
    if pin:
        output = output.replace(pin, "[REDACTED]")

    # Filter xterm noise from output
    for line in output.splitlines():
        if not line.startswith("xterm:"):
            print(line)


def _qpfg(args: list, cwd: str, env: dict = None) -> None:
    """Run quartus_pfg, streaming output and filtering xterm noise via a no-op xterm shim on non-Windows."""
    full_env = {**_os.environ, **(env or {})}

    # On Windows xterm is never spawned — use a no-op context to skip shim creation
    shim_ctx = (tempfile.TemporaryDirectory() if _os.name != 'nt'
                else contextlib.nullcontext(None))

    with shim_ctx as shim_dir:
        if shim_dir is not None:
            # Drop a no-op xterm so quartus_pfg's xterm call exits cleanly
            fake_xterm = _os.path.join(shim_dir, "xterm")
            with open(fake_xterm, "w") as f:
                f.write("#!/bin/sh\nexit 0\n")
            _os.chmod(fake_xterm,
                      stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP |
                      stat.S_IROTH | stat.S_IXOTH)
            full_env["PATH"] = shim_dir + ":" + full_env.get("PATH", "")

        with subprocess.Popen(
            ["quartus_pfg"] + args,
            cwd=cwd, env=full_env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        ) as proc:
            for line in proc.stdout:
                line = line.rstrip()
                if not line.startswith("xterm:"):
                    print(line)
            proc.wait()
            if proc.returncode != 0:
                raise subprocess.CalledProcessError(proc.returncode, ["quartus_pfg"] + args)


def _assert_file(directory: str, filename: str, msg: str) -> None:
    """Raise RuntimeError if a file does not exist after a Quartus tool step.

    Args:
        directory: Directory that should contain the file.
        filename: Expected filename within that directory.
        msg: Error message to display and include in the exception.
    """
    if not os.path.isfile(os.path.join(directory, filename)):
        print_error(msg)
        raise RuntimeError(msg)

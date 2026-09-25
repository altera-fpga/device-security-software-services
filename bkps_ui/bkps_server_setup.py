#!/usr/bin/env python3
"""Prepare BKPS security-provider, SSL, keystore, and application YAML files."""

import os
import glob
import hashlib
import re
import shutil
import ssl
import subprocess
import sys
from bkps_config import Config
from bkps_printer import print_header, print_step, print_success, print_warning, print_error, print_info
from bkps_runner import run, stream


# ---------------------------------------------------------------------------
# Security-provider profiles
# ---------------------------------------------------------------------------

# ── Security-provider profiles ───────────────────────────────────────────────────────

# The application-<provider>.yml profiles ship with BKPS. They are copied verbatim
# and only the deployment-specific lines are overwritten, so provider settings stay
# in sync with the ones the server was built against.
_REPO_CONFIG_SUBPATH = os.path.join("bkps", "src", "main", "resources", "config")


def _read_stock_profile(cfg: Config, name: str) -> list:
    """Return the lines of the stock ``name`` profile from the BKPS repo."""
    repo_yml = os.path.join(cfg.bkps_repo_dir, _REPO_CONFIG_SUBPATH, name)
    if os.path.isfile(repo_yml):
        with open(repo_yml) as f:
            return f.readlines()
    raise RuntimeError(
        f"Could not find the stock {name}.\n"
        f"Looked in: {repo_yml}\n"
        f"Point BKPS_REPO_DIR at a BKPS checkout that contains that file."
    )


def _write_profile(cfg: Config, name: str, dest: str, overrides: dict) -> None:
    """Copy the stock ``name`` profile to ``dest``, rewriting only the keys in ``overrides``.

    Indentation and every other line are preserved. An override value of ``None``
    drops the line instead of rewriting it.
    """
    pending = dict(overrides)
    out = []

    for line in _read_stock_profile(cfg, name):
        match = re.match(r"^(\s*)([\w.-]+):", line)
        key = match.group(2) if match else None
        if key not in pending:
            out.append(line)
            continue
        value = pending.pop(key)
        if value is not None:
            out.append(f"{match.group(1)}{key}: {value}\n")

    if pending:
        raise RuntimeError(f"{name} has no line to overwrite for: {', '.join(sorted(pending))}")

    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w") as f:
        f.writelines(out)


# ---------------------------------------------------------------------------
# BouncyCastle
# ---------------------------------------------------------------------------

# ── BouncyCastle ─────────────────────────────────────────────────────────────────────

def setup_bouncycastle(cfg: Config) -> None:
    """Download the BouncyCastle JAR and write application-bouncycastle.yml (plus a bc profile copy)."""
    print_header("Setting Up BouncyCastle Security Provider")

    bc_jar = os.path.join(cfg.bkps_dir, "libs-ext", "bcprov-jdk18on-1.78.1.jar")
    bc_yml = os.path.join(cfg.bkps_dir, "config", "application-bouncycastle.yml")

    if os.path.isfile(bc_jar) and os.path.isfile(bc_yml):
        print_success("BouncyCastle already configured - skipping")
        return

    print_step(1, "Downloading BouncyCastle...")
    libs_ext = os.path.join(cfg.bkps_dir, "libs-ext")
    os.makedirs(libs_ext, exist_ok=True)

    if not os.path.isfile(bc_jar):
        # LOCAL-FILE OVERRIDE (TEMP WORKAROUND) — grep-remove `local_override_`
        _override = (getattr(cfg, "local_override_bouncycastle_jar", "") or "").strip()
        if _override:
            if not os.path.isfile(_override):
                raise RuntimeError(
                    f"local_override_bouncycastle_jar points at a file that does not exist: {_override}"
                )
            print_info(f"  Using local BouncyCastle JAR override: {_override}")
            shutil.copy2(_override, bc_jar)
            print_success("BouncyCastle JAR copied from local override")
        else:
            bc_url = "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.78.1/bcprov-jdk18on-1.78.1.jar"
            bc_name = "bcprov-jdk18on-1.78.1.jar"
            downloaded = False

            if shutil.which("wget"):
                result = run(["wget", "-q", bc_url], cwd=libs_ext, check=False)
                downloaded = (result.returncode == 0 and os.path.isfile(bc_jar))

            if not downloaded and shutil.which("curl"):
                print_info("wget unavailable or failed, trying curl...")
                result = run(["curl", "-fsSL", "-o", bc_name, bc_url], cwd=libs_ext, check=False)
                downloaded = (result.returncode == 0 and os.path.isfile(bc_jar))

            if not downloaded:
                raise RuntimeError(
                    f"Failed to download BouncyCastle JAR.\n"
                    f"Try manually: wget '{bc_url}'\n"
                    f"Destination:  {libs_ext}/"
                )
            print_success("BouncyCastle downloaded")
    else:
        print_info("BouncyCastle JAR already exists")

    print_step(2, "Creating application-bouncycastle.yml...")
    _write_profile(cfg, "application-bouncycastle.yml", bc_yml, {
        "password": cfg.bc_keystore_password,
        "input-stream-param": f"{cfg.bkps_dir}/keys/bc-keystore-bkps-static.jks",
    })

    # Also create application-bc.yml symlink/copy for 'bc' profile
    bc_yml_short = os.path.join(cfg.bkps_dir, "config", "application-bc.yml")
    try:
        if os.path.exists(bc_yml_short):
            os.remove(bc_yml_short)
        os.symlink(bc_yml, bc_yml_short)
        print_success("BouncyCastle configuration created (with bc profile symlink)")
    except (OSError, NotImplementedError):
        # Symlink failed (Windows without privileges), copy instead
        shutil.copyfile(bc_yml, bc_yml_short)
        print_success("BouncyCastle configuration created (with bc profile copy)")


# ---------------------------------------------------------------------------
# Luna HSM
# ---------------------------------------------------------------------------

# ── Luna HSM ─────────────────────────────────────────────────────────────────────────

def setup_luna_config(cfg: Config) -> None:
    """Write application-luna.yml for the Luna HSM provider (JARs must be copied manually)."""
    print_header("Setting Up Luna HSM Security Provider")

    luna_yml = os.path.join(cfg.bkps_dir, "config", "application-luna.yml")
    if os.path.isfile(luna_yml):
        print_success("Luna configuration already exists - skipping")
        return

    # Default input-stream-param: tokenlabel:BKPPartition (admin doc default)
    input_stream = cfg.hsm_keystore_path or "tokenlabel:BKPPartition"

    print_info("Luna provider JARs must be installed manually from the SafeNet distribution:")
    print_info("  cp /usr/safenet/lunaclient/jsp/lib/libLunaAPI.so /usr/lib/libLunaAPI.so")
    print_info(f"  cp /usr/safenet/lunaclient/jsp/lib/LunaProvider.jar {cfg.bkps_dir}/libs-ext/LunaProvider.jar")

    _write_profile(cfg, "application-luna.yml", luna_yml, {
        "password": cfg.hsm_keystore_password,
        "input-stream-param": input_stream,
    })
    print_success(f"Luna configuration created: {luna_yml}")


# ---------------------------------------------------------------------------
# nCipher HSM
# ---------------------------------------------------------------------------

# ── nCipher HSM ─────────────────────────────────────────────────────────────────────

def setup_ncipher_config(cfg: Config) -> None:
    """Write application-ncipher.yml (module-protection or file-based JCA/JCE CSP)."""
    print_header("Setting Up nCipher HSM Security Provider")

    ncipher_yml = os.path.join(cfg.bkps_dir, "config", "application-ncipher.yml")
    if os.path.isfile(ncipher_yml):
        print_success("nCipher configuration already exists - skipping")
        return

    # If a JKS keystore path is given, use file-based (JCA/JCE CSP) mode.
    # Otherwise use module-protection mode (file-based: false).
    file_based = "true" if cfg.hsm_keystore_path else "false"

    _write_profile(cfg, "application-ncipher.yml", ncipher_yml, {
        "file-based": file_based,
        "password": cfg.hsm_keystore_password,
        # Module protection keeps keys in the HSM, so there is no keystore to point at.
        "input-stream-param": cfg.hsm_keystore_path or None,
    })
    print_success(f"nCipher configuration created: {ncipher_yml}")
    if cfg.hsm_keystore_path:
        print_info("file-based mode (JCA/JCE CSP): using nShield KeyStore file")
        print_info("Remember to add -Dprotect=module -DignorePassphrase=true when starting BKPS")
    else:
        print_info("Module-protection mode: keys are stored directly in the HSM")


# ---------------------------------------------------------------------------
# SSL Certificates
# ---------------------------------------------------------------------------

# ── SSL Certificates ─────────────────────────────────────────────────────────────────

def _certificate_sha1_thumbprint(cert_path: str) -> str:
    """Return the Windows-style SHA-1 thumbprint for a PEM certificate."""
    try:
        with open(cert_path, "r", encoding="ascii") as cert_file:
            pem = cert_file.read()
        # PEM_cert_to_DER_cert already returns the decoded DER byte sequence.
        # Decoding it with base64 again corrupts valid certificates and raises
        # "Incorrect padding" on current Python releases.
        der = ssl.PEM_cert_to_DER_cert(pem)
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            f"Cannot read BKPS SSL CA certificate: {cert_path}: {exc}"
        ) from exc
    return hashlib.sha1(der).hexdigest().upper()


def _windows_current_user_root_contains(thumbprint: str) -> bool:
    """Return whether CurrentUser\\Root contains the exact thumbprint."""
    command = (
        "$match = Get-ChildItem -LiteralPath 'Cert:\\CurrentUser\\Root' "
        f"| Where-Object {{ $_.Thumbprint -eq '{thumbprint}' }}; "
        "if ($null -ne $match) { exit 0 } else { exit 1 }"
    )
    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", command,
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            f"Could not inspect the Windows CurrentUser Root certificate store: {exc}"
        ) from exc
    return result.returncode == 0


def _install_windows_demo_ca(cert_path: str) -> None:
    """Trust the generated demo CA in the current Windows user's Root store.

    The operation is idempotent and deliberately avoids LocalMachine\\Root so
    the guided demo does not require elevation or affect other Windows users.
    """
    if not sys.platform.startswith("win"):
        return
    if not os.path.isfile(cert_path):
        raise RuntimeError(f"BKPS SSL CA certificate not found: {cert_path}")

    thumbprint = _certificate_sha1_thumbprint(cert_path)
    if _windows_current_user_root_contains(thumbprint):
        print_success(
            "BKPS demo CA already trusted in Windows CurrentUser\\Root "
            f"(thumbprint {thumbprint})"
        )
        return

    print_info("Installing BKPS demo CA in Windows CurrentUser\\Root...")
    # Do not use ``certutil -addstore Root`` or ``Import-Certificate`` here.
    # Adding a self-signed root through those command wrappers can enter the
    # Windows root-certificate confirmation UI.  The GUI worker is deliberately
    # non-interactive, so that prompt either fails with "UI is not allowed" or
    # leaves certutil waiting until our timeout.  X509Store.Add calls the
    # certificate-store API directly and keeps this per-user demo operation
    # non-interactive.
    #
    # Embed the absolute path inside ``-Command``.  Extra argv after a string
    # ``-Command`` is not bound to a scriptblock ``param()`` when launched via
    # CreateProcess/subprocess, so ``X509Certificate2::new($CertificatePath)``
    # would see an empty path and raise "The path is not of a legal form."
    abs_cert = os.path.abspath(cert_path)
    ps_cert_literal = abs_cert.replace("'", "''")
    import_script = f"""
$ErrorActionPreference = 'Stop'
$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    '{ps_cert_literal}'
)
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
)
try {{
    $store.Open(
        [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite
    )
    $store.Add($certificate)
}}
finally {{
    $store.Close()
    $certificate.Dispose()
}}
"""
    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", import_script,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            f"Failed to install the BKPS demo CA in CurrentUser\\Root: {exc}"
        ) from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown certificate-store error").strip()
        raise RuntimeError(
            "Failed to install the BKPS demo CA in Windows CurrentUser\\Root: "
            + detail
        )
    if not _windows_current_user_root_contains(thumbprint):
        raise RuntimeError(
            "Windows reported a successful CA import, but the certificate "
            f"thumbprint was not found in CurrentUser\\Root: {thumbprint}"
        )
    print_success(
        "BKPS demo CA trusted in Windows CurrentUser\\Root "
        f"(thumbprint {thumbprint})"
    )


def _ssl_certificate_outputs_complete(paths: tuple[str, ...]) -> bool:
    """Return true only when every artifact produced by this step exists."""
    return all(os.path.isfile(path) for path in paths)


def create_ssl_certificates(cfg: Config) -> None:
    """Generate the BKPS SSL cert, super-admin client cert, and download the TSCI cert."""
    print_header("Creating SSL Certificates")

    ssl_dir = os.path.join(cfg.bkps_dir, "keys", "bkps_ssl_cert")
    ssl_cert = os.path.join(ssl_dir, "bkps_ssl_cert.crt")
    ssl_private = os.path.join(ssl_dir, "bkps_ssl_private.pem")
    ssl_p12 = os.path.join(ssl_dir, "bkps_ssl.p12")
    admin_cert = os.path.join(cfg.bkps_dir, "keys", "super_admin_cert.crt")
    tsci_cert  = os.path.join(cfg.bkps_dir, "keys", "tsci_cert", "tsci_altera_com.pem")

    required_outputs = (ssl_cert, ssl_private, ssl_p12, admin_cert, tsci_cert)
    if _ssl_certificate_outputs_complete(required_outputs):
        # Verify the existing SSL cert has CA:TRUE — older versions generated
        # it without this flag, which makes OpenSSL 3.x reject it as a trust anchor.
        try:
            result = subprocess.run(
                ["openssl", "x509", "-in", ssl_cert, "-text", "-noout"],
                capture_output=True, text=True, timeout=5
            )
            if "CA:TRUE" not in result.stdout.upper():
                print_warning("Existing SSL cert lacks CA:TRUE — regenerating (OpenSSL 3.x requires it).")
                for stale in [ssl_cert,
                               ssl_private,
                               ssl_p12,
                               os.path.join(cfg.bkps_dir, "keys", "bkps_keystore.p12")]:
                    if os.path.isfile(stale):
                        os.remove(stale)
                        print_info(f"Removed stale file: {os.path.basename(stale)}")
            else:
                _install_windows_demo_ca(ssl_cert)
                print_success("SSL certificates already created - skipping")
                return
        except (OSError, subprocess.TimeoutExpired):
            _install_windows_demo_ca(ssl_cert)
            print_success("SSL certificates already created - skipping")
            return

    # --- OpenSSL config ---
    print_step(1, "Creating OpenSSL configuration...")
    openssl_cnf = os.path.join(cfg.bkps_dir, "config", "openssl.cnf")
    os.makedirs(os.path.dirname(openssl_cnf), exist_ok=True)
    with open(openssl_cnf, "w") as f:
        f.write(_bkps_openssl_cnf(cfg))
    print_success("OpenSSL config created")

    # --- BKPS SSL cert ---
    print_step(2, "Generating BKPS SSL certificate...")
    os.makedirs(ssl_dir, exist_ok=True)

    # Use v3_ca extensions: CA:true is required so runner.py can use this cert
    # as the trust store (session.verify). OpenSSL 3.x rejects CA:false certs
    # as trust anchors.
    run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-passout", f"pass:{cfg.ssl_password}",
        "-keyout", ssl_private,
        "-out",    os.path.join(ssl_dir, "bkps_ssl_cert.crt"),
        "-days", "365", "-extensions", "v3_req",
        "-config", openssl_cnf,
    ])
    print_success("SSL certificate created")

    # Convert to PKCS12
    p12_path = ssl_p12
    run([
        "openssl", "pkcs12", "-export",
        "-name", "bkps_server_ssl",
        "-in",   os.path.join(ssl_dir, "bkps_ssl_cert.crt"),
        "-inkey",ssl_private,
        "-passin",  f"pass:{cfg.ssl_password}",
        "-out",     p12_path,
        "-passout", f"pass:{cfg.pkcs11_password}",
    ])
    if not os.path.isfile(p12_path):
        raise RuntimeError("Failed to create PKCS12 file")
    print_success("PKCS12 file created")

    # --- Super admin cert ---
    print_step(3, "Creating Super Admin OpenSSL configuration...")
    sa_cnf = os.path.join(cfg.bkps_dir, "config", "superadmin_openssl.cnf")
    with open(sa_cnf, "w") as f:
        f.write(_superadmin_openssl_cnf())
    print_success("Super Admin OpenSSL config created")

    print_step(4, "Creating Super Admin certificate...")
    keys_dir = os.path.join(cfg.bkps_dir, "keys")
    os.makedirs(keys_dir, exist_ok=True)
    run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", os.path.join(keys_dir, "super_admin_private.pem"), "-nodes",
        "-out",    os.path.join(keys_dir, "super_admin_cert.crt"),
        "-days", "365", "-extensions", "v3_req",
        "-config", sa_cnf,
    ])
    if not os.path.isfile(admin_cert):
        raise RuntimeError("Failed to create Super Admin certificate")
    print_success("Super Admin certificate created")

    # --- TSCI cert ---
    print_step(5, "Downloading TSCI certificate from tsci.altera.com...")
    tsci_dir = os.path.join(cfg.bkps_dir, "keys", "tsci_cert")
    os.makedirs(tsci_dir, exist_ok=True)
    if not os.path.isfile(tsci_cert):
        # LOCAL-FILE OVERRIDE (TEMP WORKAROUND) — grep-remove `local_override_`
        _override = (getattr(cfg, "local_override_tsci_cert", "") or "").strip()
        if _override:
            if not os.path.isfile(_override):
                raise RuntimeError(
                    f"local_override_tsci_cert points at a file that does not exist: {_override}"
                )
            print_info(f"  Using local TSCI cert override: {_override}")
            shutil.copy2(_override, tsci_cert)
            print_success("TSCI certificate copied from local override")
        else:
            _download_tsci_cert(tsci_cert)
    else:
        print_success("TSCI certificate already exists - skipping download")

    missing_outputs = [
        path for path in required_outputs if not os.path.isfile(path)
    ]
    if missing_outputs:
        raise RuntimeError(
            "SSL certificate generation did not produce all required files: "
            + ", ".join(os.path.basename(path) for path in missing_outputs)
        )

    # Trust the demo CA only after the complete certificate set exists. This
    # avoids leaving an unused trusted root behind after a partial setup run.
    _install_windows_demo_ca(ssl_cert)


def _download_tsci_cert(tsci_cert_path: str) -> None:
    """Fetch the TSCI certificate from tsci.altera.com via openssl s_client.

    Args:
        tsci_cert_path: Absolute path where the PEM file should be written.
    """
    try:
        # Use pipeline: echo -n | openssl s_client ... | sed ...
        proc1 = subprocess.run(
            ["openssl", "s_client", "-connect", "tsci.altera.com:443"],
            input=b"",
            capture_output=True,
            timeout=15,
        )
        pem_lines = []
        in_cert = False
        for line in proc1.stdout.decode(errors="replace").splitlines():
            if "-----BEGIN CERTIFICATE-----" in line:
                in_cert = True
            if in_cert:
                pem_lines.append(line)
            if "-----END CERTIFICATE-----" in line:
                in_cert = False
                break

        if pem_lines:
            with open(tsci_cert_path, "w") as f:
                f.write("\n".join(pem_lines) + "\n")
            print_success("TSCI certificate downloaded")
        else:
            _tsci_warning()
    except Exception:
        _tsci_warning()


def _tsci_warning() -> None:
    """Print troubleshooting instructions when the TSCI certificate download fails."""
    print_warning("Failed to download TSCI certificate from tsci.altera.com")
    print_info("This is often due to network restrictions")
    print_info("Troubleshooting:")
    print_info("  1. Check internet connectivity: ping tsci.altera.com")
    print_info("  2. Try manual download:")
    print_info("     openssl s_client -connect tsci.altera.com:443 -showcerts 2>/dev/null | tee tsci_output.txt")
    print_info("  3. Extract cert manually from tsci_output.txt")
    print_warning("Continuing without TSCI cert (may affect some operations)")


# ---------------------------------------------------------------------------
# Keystore
# ---------------------------------------------------------------------------

# ── Keystore ───────────────────────────────────────────────────────────────────────

def create_bkps_keystore(cfg: Config) -> None:
    """Import the BKPS SSL PKCS12 and TSCI certificate into bkps_keystore.p12."""
    print_header("Creating BKPS Keystore")

    ks_path = os.path.join(cfg.bkps_dir, "keys", "bkps_keystore.p12")
    if os.path.isfile(ks_path):
        print_success("BKPS keystore already created - skipping")
        return

    print_step(1, "Importing SSL certificate to keystore...")
    keys_dir = os.path.join(cfg.bkps_dir, "keys")
    p12_src  = os.path.join(keys_dir, "bkps_ssl_cert", "bkps_ssl.p12")

    run([
        "keytool", "-importkeystore",
        "-srckeystore",  p12_src,
        "-srcstoretype", "PKCS12",
        "-srcstorepass", cfg.pkcs11_password,
        "-destkeystore", ks_path,
        "-deststoretype","PKCS12",
        "-deststorepass",cfg.keystore_password,
        "-noprompt",
    ])
    print_success("SSL certificate imported")

    print_step(2, "Importing TSCI certificate...")
    tsci_pem = os.path.join(keys_dir, "tsci_cert", "tsci_altera_com.pem")
    run([
        "keytool", "-importcert",
        "-keystore",  ks_path,
        "-alias",     "tsci-altera-com-cert",
        "-file",      tsci_pem,
        "-storepass", cfg.keystore_password,
        "-noprompt", "-v",
    ])
    print_success("TSCI certificate imported")


# ---------------------------------------------------------------------------
# Application config
# ---------------------------------------------------------------------------

# ── Application config ──────────────────────────────────────────────────────────────

def create_bkps_config(cfg: Config) -> None:
    """Write application-<profile>.yml with datasource, SSL, logging, and SPDM settings."""
    print_header("Creating BKPS Application Configuration")

    dest = os.path.join(cfg.bkps_dir, "config", f"application-{cfg.profile_name}.yml")

    # Resolve wrapper library path from config (populated by the build step or set manually).
    # Fall back to scanning bkps_dir in case this step runs standalone without a prior build.
    wrapper_path = cfg.libspdm_wrapper_path or ""
    if not wrapper_path or not os.path.isfile(wrapper_path):
        ext = "*.dll" if os.name == "nt" else "*.so"
        candidates = (
            glob.glob(os.path.join(cfg.bkps_dir, f"libspdm{ext}")) +
            glob.glob(os.path.join(cfg.bkps_dir, f"spdm_wrapper{ext}")) +
            glob.glob(os.path.join(cfg.bkps_dir, "**", f"libspdm_wrapper{ext}"), recursive=True)
        )
        wrapper_path = candidates[0] if candidates else "${LIBSPDM_WRAPPER_LIBRARY_PATH:}"

    if wrapper_path.startswith("${"):
        print_info("libspdm wrapper not found — using env var placeholder (set LIBSPDM_WRAPPER_LIBRARY_PATH at runtime)")
    else:
        print_info(f"libspdm wrapper: {wrapper_path}")

    # Agilex 5 is SPDM-only — sigma must default to false or Spring fails to
    # autowire SigmaProtocol bean (no qualifying bean available).
    sigma_default = "false" if cfg.profile_name == "agilex5" else "true"
    spdm_section = f"""
lib-spdm-params:
    wrapper-library-path: {wrapper_path}
    network-communication-timeout: ${{LIBSPDM_NETWORK_COMMUNICATION_TIMEOUT:5}}
    library-communication-timeout: ${{LIBSPDM_LIBRARY_COMMUNICATION_TIMEOUT:1}}

service:
    protocol:
        sigma: ${{ENABLE_SIGMA_PROTOCOL:{sigma_default}}}
        spdm: ${{ENABLE_SPDM_PROTOCOL:true}}
"""

    content = f"""spring:
  datasource:
    url: jdbc:postgresql://{cfg.db_host}:{cfg.db_port}/{cfg.db_name}
    username: {cfg.db_user}
    password: {cfg.db_password}
  liquibase:
    enabled: false  # Disabled - schema imported from SQL file
  ssl:
    bundle:
      jks:
        web-server:
          truststore:
            location: {cfg.bkps_dir}/keys/bkps_keystore.p12
            password: {cfg.keystore_password}
            type: PKCS12
          keystore:
            location: {cfg.bkps_dir}/keys/bkps_keystore.p12
            password: {cfg.keystore_password}
            type: PKCS12
          key:
            password: {cfg.keystore_password}
            alias: bkps_server_ssl
server:
  port: {cfg.bkps_server_port}
logging:
  level:
    ROOT: {cfg.log_level}
    com.intel.bkp: {cfg.log_level}
  file:
    name: {cfg.bkps_dir}/logs/bkps_spring.log
only-efuse-uds: false
{spdm_section}"""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w") as f:
        f.write(content)
    print_success(f"BKPS configuration created: {dest}")


# ---------------------------------------------------------------------------
# OpenSSL CNF templates
# ---------------------------------------------------------------------------

# ── OpenSSL CNF templates ─────────────────────────────────────────────────────────────

def _bkps_openssl_cnf(cfg: Config) -> str:
    """Return the OpenSSL .cnf for the BKPS server SSL cert (v3_req, SAN includes localhost)."""
    ip = cfg.bkps_server_ip or "localhost"
    # Build SAN entries — always include localhost and 127.0.0.1
    san_entries = ["DNS.1 = localhost", "IP.1 = 127.0.0.1"]
    is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip))
    current_idx = 1
    if ip not in ("localhost", "127.0.0.1"):
        if is_ip:
            san_entries.append(f"IP.2 = {ip}")
        else:
            san_entries.append(f"DNS.2 = {ip}")
        current_idx = 2
    san_entries.append(f"DNS.{current_idx + 1} = pre1-tsci.dev.altera.com")
    san_entries.append(f"DNS.{current_idx + 2} = tsci.altera.com")
    san_block = "\n".join(san_entries)


    return f"""\
[ req ]
distinguished_name = bkps_server_tag
req_extensions = v3_req
x509_extensions = v3_req
prompt = no

[ bkps_server_tag ]
C = US
ST = California
L = San Jose
O = BKPS Demo
OU = Security
CN = {ip}

[ v3_req ]
basicConstraints = CA:true
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alternate_names

[ alternate_names ]
{san_block}
"""


# ---------------------------------------------------------------------------
# AES Key → BouncyCastle UBER JKS
# ---------------------------------------------------------------------------

# ── AES Key → BouncyCastle UBER JKS ───────────────────────────────────────────────

def import_aes_key_to_bc_keystore(cfg, aes_hex: str, parent_step=None) -> None:
    """Import a 256-bit AES key into the BC UBER JKS as ``qek_encryption_key``.

    Args:
        aes_hex: 64-character hex string for the AES-256 key.
        parent_step: When set, print inner steps as parent.1, parent.2, ...
    """
    print_header("Importing AES Key to BouncyCastle UBER Keystore")

    aes_hex = aes_hex.strip().upper()
    if len(aes_hex) != 64 or not all(c in "0123456789ABCDEF" for c in aes_hex):
        raise ValueError(
            f"Invalid AES hex key: must be exactly 64 hex characters, got {len(aes_hex)}"
        )

    bc_jar = os.path.join(cfg.bkps_dir, "libs-ext", "bcprov-jdk18on-1.78.1.jar")
    if not os.path.isfile(bc_jar):
        raise RuntimeError(
            "BouncyCastle JAR not found. Run 'Setup BouncyCastle' first.\n"
            f"Expected: {bc_jar}"
        )

    bc_keystore = os.path.join(cfg.bkps_dir, "keys", "bc-keystore-bkps-static.jks")
    os.makedirs(os.path.dirname(bc_keystore), exist_ok=True)

    temp_java = os.path.join(cfg.bkps_dir, "keys", "_ImportAesKey.java")
    temp_class = os.path.join(cfg.bkps_dir, "keys", "_ImportAesKey.class")

    # ------------------------------------------------------------------
    print_step(1, "Importing AES key directly into UBER JKS as 'qek_encryption_key'...", parent=parent_step)

    # Pre-escape backslashes in the keystore path for the generated Java
    # string literal.  Done outside the f-string because pre-3.12 Python
    # does not allow backslashes inside f-string expressions.
    keystore_path_java = bc_keystore.replace("\\", "\\\\")

    java_src = f'''import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.Security;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class _ImportAesKey {{
    public static void main(String[] args) throws Exception {{
        Security.addProvider(new BouncyCastleProvider());

        byte[] keyBytes = hexToBytes("{aes_hex}");
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        char[] storePw = "{cfg.bc_keystore_password}".toCharArray();
        String keystorePath = "{keystore_path_java}";

        KeyStore ks = KeyStore.getInstance("UBER", "BC");
        java.io.File file = new java.io.File(keystorePath);
        if (file.exists()) {{
            try (FileInputStream in = new FileInputStream(file)) {{
                ks.load(in, storePw);
            }}
        }} else {{
            ks.load(null, storePw);
        }}

        // Key entry password must be empty - BKPS server uses "".toCharArray() in getKey()
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
        ks.setEntry("qek_encryption_key", skEntry, new KeyStore.PasswordProtection("".toCharArray()));
        try (FileOutputStream out = new FileOutputStream(keystorePath)) {{
            ks.store(out, storePw);
        }}

        System.out.println("AES key imported");
    }}

    private static byte[] hexToBytes(String hex) {{
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {{
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i + 1), 16));
        }}
        return data;
    }}
}}
'''
    with open(temp_java, "w", encoding="utf-8") as f:
        f.write(java_src)

    compile_result = subprocess.run(
        ["javac", "-cp", bc_jar, temp_java],
        capture_output=True, text=True,
    )
    compile_output = compile_result.stdout + compile_result.stderr
    for line in compile_output.splitlines():
        print(line)
    if compile_result.returncode != 0 or not os.path.isfile(temp_class):
        raise RuntimeError(
            "Failed to compile Java helper for BC keystore import.\n"
            "Ensure JDK is installed and 'javac' is in PATH.\n"
            + compile_output
        )

    # ------------------------------------------------------------------
    print_step(2, "Running Java helper to update BC keystore...", parent=parent_step)

    try:
        result2 = subprocess.run([
            "java", "-cp", f"{os.path.dirname(temp_class)}{os.pathsep}{bc_jar}", "_ImportAesKey"
        ], capture_output=True, text=True)
        combined2 = result2.stdout + result2.stderr
        for line in combined2.splitlines():
            print(line)
        if result2.returncode != 0:
            raise RuntimeError(
                f"Java BC keystore import failed (rc={result2.returncode})\n" + combined2
            )
        print_success("Key imported as 'qek_encryption_key'")
    finally:
        try:
            os.remove(temp_java)
        except OSError:
            pass
        try:
            os.remove(temp_class)
        except OSError:
            pass

    # ------------------------------------------------------------------
    print_step(3, "Verifying keystore entry...", parent=parent_step)
    verify = subprocess.run([
        "keytool", "-list",
        "-storetype", "UBER",
        "-keystore",  bc_keystore,
        "-storepass", cfg.bc_keystore_password,
        "-provider",  "org.bouncycastle.jce.provider.BouncyCastleProvider",
        "-providerpath", bc_jar,
    ], capture_output=True, text=True)
    for line in (verify.stdout + verify.stderr).splitlines():
        print(line)
    print_success(f"BC keystore updated: {bc_keystore}")


def _superadmin_openssl_cnf() -> str:
    """Return the OpenSSL .cnf for the super-admin client certificate (v3_req, clientAuth)."""
    return """\
[ req ]
distinguished_name = bkps_super_admin_tag
req_extensions = v3_req
x509_extensions = v3_req
prompt = no

[ bkps_super_admin_tag ]
C = US
ST = California
L = San Jose
O = BKPS Demo
OU = Security Admin
CN = localhost

[ v3_req ]
basicConstraints = CA:false
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = @alternate_names

[ alternate_names ]
DNS.1 = localhost
"""

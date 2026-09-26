#!/usr/bin/env python3
"""Runtime Config dataclass and KEY=VALUE load/save for bkps_demo_config.conf."""
from __future__ import annotations

import os
from pathlib import Path
from dataclasses import dataclass, field
from bkps_printer import print_info, print_success, print_warning, print_error


TOOL_ROOT = str(Path(__file__).resolve().parent)


def _runtime_home() -> str:
    """Return the current account's home directory without a fixed username."""
    return os.path.abspath(os.path.expanduser("~"))


def _default_project_root() -> str:
    """Return the optional environment-selected project root or a user-local default."""
    configured = os.environ.get("BKPS_PROJECT_ROOT", "").strip()
    if configured:
        return os.path.abspath(os.path.expandvars(os.path.expanduser(configured)))
    return os.path.join(_runtime_home(), "bkps")


def is_bkps_source_checkout(path: str | os.PathLike[str]) -> bool:
    """Return True when *path* looks like a device-security-software-services tree.

    The build/install flow expects a checkout that contains the ``bkps`` Java
    project (with Gradle) plus the surrounding repository layout.
    """
    root = Path(path)
    try:
        if not (root / "bkps").is_dir():
            return False
        return (root / "bkps" / "build.gradle").is_file() or (root / "build.gradle").is_file()
    except OSError:
        return False


def detect_embedded_bkps_repo(start: str | None = None) -> str:
    """Return the repo root when ``bkps_ui`` is already inside that checkout.

    Users of ``altera-fpga/device-security-software-services`` clone the repo
    first and run CLI/UI from the in-tree ``bkps_ui`` package. In that case
    ``BKPS_REPO_DIR`` should point at the clone root and ``git clone`` must be
    skipped. Returns an empty string when this tooling is not embedded in such
    a tree.
    """
    tool = Path(start or TOOL_ROOT).resolve()
    if tool.name != "bkps_ui":
        for parent in tool.parents:
            if parent.name == "bkps_ui":
                tool = parent
                break
        else:
            return ""
    repo_root = tool.parent
    try:
        if not (repo_root / "bkps_ui").is_dir():
            return ""
    except OSError:
        return ""
    if is_bkps_source_checkout(repo_root):
        return str(repo_root)
    return ""


def _default_bkps_repo_dir(project_root: str) -> str:
    """Prefer an embedded DSSS checkout; otherwise ``<project>/bkps_repo``."""
    embedded = detect_embedded_bkps_repo()
    if embedded:
        return embedded
    return os.path.join(project_root, "bkps_repo")


def _readable_file(candidate: Path) -> bool:
    """Return True when *candidate* is an existing file this account can stat.

    ``Path.is_file`` re-raises ``PermissionError`` when a parent directory is
    not traversable, so probing system locations must treat an inaccessible
    path as absent rather than as a failure.
    """
    try:
        return candidate.is_file()
    except OSError:
        return False


def detect_system_softhsm_library(
    search_roots: list[Path] | None = None,
) -> str:
    """Return the configured or first known system SoftHSM PKCS#11 provider.

    Debian and Ubuntu install the provider below either ``/usr/lib/softhsm``
    or a multiarch directory such as
    ``/usr/lib/x86_64-linux-gnu/softhsm``.  The dynamic linker cache does not
    necessarily list PKCS#11 modules, so discovery must inspect those paths.
    """
    configured = os.environ.get("SOFTHSM_LIB_PATH", "").strip()
    if configured:
        return os.path.abspath(
            os.path.expandvars(os.path.expanduser(configured))
        )
    if os.name == "nt" and search_roots is None:
        return ""

    roots = search_roots or [
        Path("/usr/lib"),
        Path("/usr/lib64"),
        Path("/usr/local/lib"),
        Path("/lib"),
        Path("/lib64"),
    ]
    patterns = (
        "softhsm/libsofthsm2.so",
        "softhsm/libsofthsm2.so.*",
        "*/softhsm/libsofthsm2.so",
        "*/softhsm/libsofthsm2.so.*",
        "libsofthsm2.so",
        "libsofthsm2.so.*",
    )
    for root in roots:
        for pattern in patterns:
            try:
                candidates = sorted(root.glob(pattern))
            except OSError:
                continue
            for candidate in candidates:
                if not _readable_file(candidate):
                    continue
                try:
                    return str(candidate.resolve())
                except OSError:
                    return str(candidate)
    return ""


def detect_softhsm_config_path(
    candidates: list[Path] | None = None,
) -> str:
    """Return the explicit or first known SoftHSM configuration file.

    ``SOFTHSM_CONF_PATH`` is the Automation Studio configuration name;
    ``SOFTHSM2_CONF`` is the environment variable consumed by SoftHSM.
    Linux checks the per-user file before the system-wide default so an
    existing user token store is not silently replaced by another store.
    """
    for env_name in ("SOFTHSM_CONF_PATH", "SOFTHSM2_CONF"):
        configured = os.environ.get(env_name, "").strip()
        if configured:
            return os.path.abspath(
                os.path.expandvars(os.path.expanduser(configured))
            )

    if candidates is None:
        if os.name == "nt":
            return ""
        candidates = [
            Path("~/.config/softhsm2/softhsm2.conf").expanduser(),
            Path("/etc/softhsm/softhsm2.conf"),
            Path("/usr/local/etc/softhsm2.conf"),
        ]

    for candidate in candidates:
        candidate = Path(candidate).expanduser()
        if not _readable_file(candidate):
            continue
        try:
            return str(candidate.resolve())
        except OSError:
            return str(candidate.absolute())
    return ""


def detect_softhsm_tokens_dir(config_path: str = "") -> str:
    """Return ``directories.tokendir`` from a SoftHSM configuration file."""
    selected = (config_path or detect_softhsm_config_path()).strip()
    if not selected:
        return ""
    config = Path(os.path.expandvars(os.path.expanduser(selected)))
    if not _readable_file(config):
        return ""

    try:
        lines = config.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return ""

    for line in lines:
        content = line.split("#", 1)[0].strip()
        key, separator, value = content.partition("=")
        if not separator or key.strip().lower() != "directories.tokendir":
            continue
        value = os.path.expandvars(os.path.expanduser(value.strip()))
        if not value:
            return ""
        if not os.path.isabs(value):
            value = os.path.join(str(config.parent), value)
        return os.path.abspath(os.path.normpath(value))
    return ""


def configure_system_softhsm_defaults(cfg) -> None:
    """Populate missing SoftHSM config and token-directory paths."""
    configured = (getattr(cfg, "softhsm_conf_path", "") or "").strip()
    if not configured:
        configured = detect_softhsm_config_path()
        if configured:
            cfg.softhsm_conf_path = configured

    tokens_dir = (getattr(cfg, "softhsm_tokens_dir", "") or "").strip()
    if not tokens_dir and configured:
        tokens_dir = detect_softhsm_tokens_dir(configured)
        if tokens_dir:
            cfg.softhsm_tokens_dir = tokens_dir


# ── Device family definitions ───────────────────────────────────────────────

# Device family definitions
# Maps display name -> (profile_name, protocol, build_from_source, configuration template)
DEVICE_FAMILIES = {
    "Agilex 5  (SPDM)":    ("agilex5",   "SPDM",  True,  "sample_AgilexB.json"),
    "Agilex 7  (SIGMA)":   ("agilex",   "SIGMA", False, "sample_Agilex.json"),
    "Easic N5X  (SIGMA)":   ("easic_n5x",   "SIGMA", False, "sample_EasicN5X.json"),
    "Stratix 10  (SIGMA)": ("stratix10", "SIGMA", False, "sample_S10.json"),
}

# Log levels shown in the Config tab's Logging combo box.
LOGGING_TYPES = [
    "INFO",
    "DEBUG",
    "TRACE",
]

# PUF type per device families
PUF_TYPES = {
    "agilex5": {"puf_activate": ["UDS_INTEL"], "set_authority": ["UDS_EFUSE", "UDS_INTEL"]},
    "agilex": {"puf_activate": ["UDS_IID"], "set_authority": ["UDS_EFUSE", "UDS_IID"]},
    "easic_n5x": {"set_authority": ["UDS_EFUSE"]}
}

# AES compact-certificate storage types per device profile.
# Used as the ccert_type option in: quartus_pfg --ccert -o ccert_type=<value> ...
# Each entry maps ccert_type -> [puf_type, key_storage].
# key_storage is EFUSE, BBRAM, or OFFCHIP; AES ccert IV is required for OFFCHIP.
AES_CCERT_TYPES: dict[str, dict[str, list[str]]] = {
    "agilex5": {
        "EFUSE_WRAPPED_AES_KEY": ["INTERNAL", "EFUSE"],
        "EFUSE_UDS_INTEL_PUF_WRAPPED_AES_KEY": ["UDS_INTEL_PUF", "EFUSE"],
        "BBRAM_WRAPPED_AES_KEY": ["INTERNAL", "BBRAM"],
        "BBRAM_UDS_INTEL_PUF_WRAPPED_AES_KEY": ["UDS_INTEL_PUF", "BBRAM"],
        "UDS_EFUSE_WRAPPED_AES_KEY": ["INTERNAL", "OFFCHIP"],
        "UDS_INTEL_PUF_WRAPPED_AES_KEY": ["UDS_INTEL_PUF", "OFFCHIP"]
    },
    "agilex": {
        "EFUSE_WRAPPED_AES_KEY": ["INTERNAL", "EFUSE"],
        "BBRAM_WRAPPED_AES_KEY": ["INTERNAL", "BBRAM"],
        "BBRAM_IID_PUF_WRAPPED_AES_KEY": ["IID_PUF", "BBRAM"],
        "BBRAM_UDS_IID_PUF_WRAPPED_AES_KEY": ["UDS_IID_PUF", "BBRAM"],
        "IID_PUF_WRAPPED_AES_KEY": ["IID_PUF", "OFFCHIP"],
        "UDS_IID_PUF_WRAPPED_AES_KEY": ["UDS_IID_PUF", "OFFCHIP"]
    },
    "easic_n5x": {
        "EFUSE_WRAPPED_AES_KEY": ["INTERNAL", "EFUSE"],
    },
    "stratix10": {
        "EFUSE_WRAPPED_AES_KEY": ["INTERNAL", "EFUSE"],
        "BBRAM_WRAPPED_AES_KEY": ["INTERNAL", "BBRAM"],
        "BBRAM_IID_PUF_WRAPPED_AES_KEY": ["IID_PUF", "BBRAM"],
        "IID_PUF_WRAPPED_AES_KEY": ["IID_PUF", "OFFCHIP"]
    },
}


_DEFAULT_AES_CCERT_TYPES: dict[str, list[str]] = {
    "EFUSE_WRAPPED_AES_KEY": ["INTERNAL", "EFUSE"],
}


def aes_ccert_types_for_profile(profile: str) -> dict[str, list[str]]:
    """Return ``{ccert_type: [puf_type, key_storage]}`` for *profile*."""
    return AES_CCERT_TYPES.get(profile, _DEFAULT_AES_CCERT_TYPES)


def aes_ccert_lookup(profile: str, ccert_type: str) -> tuple[str, str]:
    """Return ``(puf_type, key_storage)`` for *ccert_type* under *profile*.

    Each ``AES_CCERT_TYPES`` entry is ``{ccert_type: [puf_type, key_storage]}``.
    Unknown combinations raise ``ValueError``.
    """
    ccert_type = (ccert_type or "").strip()
    profile_map = aes_ccert_types_for_profile(profile)
    meta = profile_map.get(ccert_type)
    if not meta or len(meta) < 2:
        print_error(f"Unknown AES ccert type: {ccert_type} for profile: {profile}")
        raise ValueError(f"Unknown AES ccert type: {ccert_type} for profile: {profile}")
    return str(meta[0]), str(meta[1])


def aes_ccert_requires_iv(profile: str, ccert_type: str) -> bool:
    """True when quartus_pfg ``--ccert`` needs an IV (OFFCHIP key storage)."""
    _, key_storage = aes_ccert_lookup(profile, ccert_type)
    return key_storage == "OFFCHIP"


# ── Config dataclass ────────────────────────────────────────────────────────────

@dataclass
class Config:
    # Runtime identity only. No account or installation path is embedded.
    home: str = field(default_factory=_runtime_home)
    username: str = field(default_factory=lambda: (
        os.environ.get("USER") or
        os.environ.get("USERNAME") or
        __import__("getpass").getuser()
    ))

    # Directories
    bkps_dir: str = ""
    quartus_keys_dir: str = ""
    cm_provisioning_dir: str = ""
    bkps_repo_dir: str = ""
    # Empty uses the hardcoded altera-fpga default in bkps_build.BKPS_REPO_URL.
    bkps_repo_url: str = ""

    # Config file path
    config_file: str = ""

    # Passwords
    ssl_password: str = "ssl_password"
    pkcs11_password: str = "pkcs11_password"
    keystore_password: str = "keystore_password"
    bc_keystore_password: str = "bc_keystore_password"
    aes_passphrase: str = "aes_passphrase"
    programmer_cert_password: str = "programmer_cert_password"

    # HSM (Luna / nCipher) — only used when security_provider != bouncycastle
    hsm_keystore_password: str = ""   # Luna partition password / nCipher .sworld password
    hsm_keystore_path: str = ""       # Luna: tokenlabel:BKPPartition / nCipher: path to JKS

    # SoftHSM PKCS#11 (Agilex 5 HSM-based AES key generation)
    softhsm_lib_path:    str = field(default_factory=detect_system_softhsm_library)
    softhsm_token_label: str = "AlteraAESToken"
    softhsm_user_pin:    str = "12345678"
    softhsm_so_pin:      str = "12345678"
    softhsm_key_label:   str = "AESKey"
    softhsm_conf_path:   str = field(default_factory=detect_softhsm_config_path)
    softhsm_tokens_dir:  str = field(default_factory=detect_softhsm_tokens_dir)
    softhsm_util_path:   str = ""   # full path to softhsm2-util (leave empty to use PATH)
    pkcs11_tool_path:    str = ""   # full path to pkcs11-tool (leave empty to use PATH)

    # Database
    db_host: str = "localhost"
    db_name: str = "bkps_database"
    db_user: str = "bkps_user"
    db_password: str = "bkps_password"
    db_port: str = "5432"
    sudo_password: str = ""  # sudo password for PostgreSQL admin commands (avoids terminal prompt)
    pg_superuser_password: str = "postgres"  # Windows: password for the postgres superuser account

    # Server
    bkps_server_ip: str = "localhost"
    bkps_server_port: str = "8082"

    # Device
    device_part: str = ""
    jtag_cable_num: str = "1"
    quartus_version: str = "26.3"

    # Optional: path to an operator-supplied Device Owner Root Key public
    # .qky file.  When set, bkps_keys.create_authentication_keys skips the
    # Quartus Owner Root key creation flow and copies this file in as
    # root0.qky.  Also referenced by the "Add Device Owner Root Key"
    # runner.py root-signing-key add flow on the Administration tab.
    owner_root_key_path: str = ""

    # Optional: path to the matching Device Owner Root Key private PEM
    # (paired with owner_root_key_path).  When set, it is copied in as
    # root0_private.pem so that the subsequent Design / AES Cert signing
    # chains can be built on top of the supplied Owner Root Key.
    owner_root_key_private_path: str = ""
    # --cancel value for BKPS signing key (passed to quartus_sign as --cancel=<n>)
    bkps_signing_key_cancel_id: str = "0"

    # BKPS release
    bkps_release: str = "auto"  # "auto" detects the latest available release tag on startup

    # Source-build selection. ``bkp_only`` builds only the BKPS server JAR,
    # Liquibase SQL schema, and SPDM wrapper. ``full`` also builds the
    # repository's auxiliary Java applications and (on Linux) FCS artifacts.
    bkps_build_mode: str = "bkp_only"
    include_bkp_programmer: bool = False

    # Build version (-Pversion / -Dversion passed to Gradle; empty = auto-detect from JAR)
    bkps_version: str = ""

    # Pre-built bundle ZIP (for Agilex 7 / Easic N5X / Stratix 10 — SIGMA protocol)
    bundle_zip: str = ""
    bundle_zip_password: str = ""

    # Pre-built JAR + SQL supplied directly (all profiles — skips both ZIP and source build)
    bkps_jar_path: str = ""
    bkps_sql_path: str = ""
    bkps_admin_tools_dir: str = ""   # if empty, cloned from repo and copied automatically

    # AES key generation
    aes_ccert_type: str = "EFUSE_WRAPPED_AES_KEY"   # ccert_type option for quartus_pfg --ccert
    aes_cancel_id:  str = "1"                        # --cancel value for AES cert signing key
    aes_ccert_iv:   str = "1234567890ABCDEF1234567890ABCDEF"  # IV hex; required when key storage is OFFCHIP

    # Runtime
    security_provider: str = "bouncycastle"
    profile_name: str = "agilex5"

    # SPDM wrapper library path (required for Agilex 5 / Agilex 7 SPDM provisioning)
    libspdm_wrapper_path: str = ""

    # Logging level for BKPS application.yml (INFO or DEBUG)
    log_level: str = "INFO"

    # ── LOCAL-FILE OVERRIDES (TEMP WORKAROUND) ────────────────────────────────
    # Temporary fields that let the operator point at a pre-downloaded local
    # copy of assets that would otherwise be fetched from the internet.
    # All three are OPTIONAL:  when empty the normal download path runs
    # unchanged.  Grep for ``local_override_`` to remove cleanly later.
    local_override_tsci_cert:       str = ""   # .pem file used in place of `openssl s_client … tsci.altera.com`
    local_override_bouncycastle_jar: str = ""  # bcprov-jdk18on-*.jar used in place of the Maven download
    local_override_gradle_zip:      str = ""   # gradle-*-bin.zip used in place of the gradle-wrapper download

    # Verbose flag
    verbose: bool = False

    # Non-interactive auto-confirm flag (set by --yes / -y CLI flag)
    yes: bool = False

    def __post_init__(self):
        """Derive portable CLI defaults from a runtime-selected project root."""
        project_root = _default_project_root()
        if not self.bkps_dir:
            self.bkps_dir = project_root
        if not self.quartus_keys_dir:
            self.quartus_keys_dir = os.path.join(project_root, "quartus_keys")
        if not self.cm_provisioning_dir:
            self.cm_provisioning_dir = os.path.join(project_root, "cm_provisioning")
        if not self.bkps_repo_dir:
            self.bkps_repo_dir = _default_bkps_repo_dir(project_root)
        if not self.config_file:
            configured = os.environ.get("BKPS_CONFIG_FILE", "").strip()
            self.config_file = (
                os.path.abspath(os.path.expandvars(os.path.expanduser(configured)))
                if configured else os.path.join(project_root, "bkps_demo_config.conf")
            )

    # ── Convenience properties ───────────────────────────────────────────────

    @property
    def tool_root(self) -> str:
        """Installation/source directory of Automation Studio itself."""
        return TOOL_ROOT

    @property
    def bkps_url(self) -> str:
        """Full HTTPS base URL for the BKPS REST API (e.g. ``https://localhost:8082``)."""
        return f"https://{self.bkps_server_ip}:{self.bkps_server_port}"

    @property
    def ca_cert(self) -> str:
        """Absolute path to the BKPS SSL CA certificate used to verify the server TLS cert."""
        return os.path.join(self.bkps_dir, "keys", "bkps_ssl_cert", "bkps_ssl_cert.crt")

    @property
    def client_cert(self) -> str:
        """Absolute path to the programmer's mTLS client certificate (signed by BKPS CA)."""
        return os.path.join(self.quartus_keys_dir, "programmer_bkps_signed.crt")

    @property
    def client_key(self) -> str:
        """Absolute path to the programmer's private key (paired with ``client_cert``)."""
        return os.path.join(self.quartus_keys_dir, "programmer_private.pem")

    @property
    def device_family(self) -> str:
        """Return display name for current profile_name, or empty string if unknown."""
        for display, (profile, _, _, _) in DEVICE_FAMILIES.items():
            if self.profile_name == profile:
                return display
        return ""

    @property
    def build_from_source(self) -> bool:
        """True if this device family requires building BKPS from source (SPDM/Agilex 5)."""
        for _, (profile, _, from_src, _) in DEVICE_FAMILIES.items():
            if self.profile_name == profile:
                return from_src
        return True  # safe default


# ── Config-file key map ──────────────────────────────────────────────────────────

# Map config-file key -> Config attribute name
_KEY_MAP = {
    "USERNAME":             "username",
    "BKPS_DIR":             "bkps_dir",
    "QUARTUS_KEYS_DIR":     "quartus_keys_dir",
    "CM_PROVISIONING_DIR":  "cm_provisioning_dir",
    "BKPS_REPO_DIR":        "bkps_repo_dir",
    "BKPS_REPO_URL":        "bkps_repo_url",
    "BKPS_RELEASE":         "bkps_release",
    "BKPS_BUILD_MODE":      "bkps_build_mode",
    "INCLUDE_BKP_PROGRAMMER": "include_bkp_programmer",
    "BKPS_VERSION":         "bkps_version",
    "DB_HOST":              "db_host",
    "DB_NAME":              "db_name",
    "DB_USER":              "db_user",
    "DB_PASSWORD":          "db_password",
    "DB_PORT":              "db_port",
    "SUDO_PASSWORD":        "sudo_password",
    "PG_SUPERUSER_PASSWORD": "pg_superuser_password",
    "SSL_PASSWORD":         "ssl_password",
    "pkcs11_password":      "pkcs11_password",
    "KEYSTORE_PASSWORD":    "keystore_password",
    "BC_KEYSTORE_PASSWORD":  "bc_keystore_password",
    "HSM_KEYSTORE_PASSWORD": "hsm_keystore_password",
    "HSM_KEYSTORE_PATH":     "hsm_keystore_path",
    "AES_PASSPHRASE":        "aes_passphrase",
    "PROGRAMMER_CERT_PASSWORD":  "programmer_cert_password",
    "BKPS_SERVER_IP":       "bkps_server_ip",
    "BKPS_SERVER_PORT":     "bkps_server_port",
    "SECURITY_PROVIDER":    "security_provider",
    "PROFILE_NAME":         "profile_name",
    "DEVICE_PART":          "device_part",
    "JTAG_CABLE_NUM":       "jtag_cable_num",
    "QUARTUS_VERSION":      "quartus_version",
    "OWNER_ROOT_KEY_PATH":          "owner_root_key_path",
    "OWNER_ROOT_KEY_PRIVATE_PATH":  "owner_root_key_private_path",
    "BUNDLE_ZIP":          "bundle_zip",
    "BUNDLE_ZIP_PASSWORD": "bundle_zip_password",
    "BKPS_JAR_PATH":            "bkps_jar_path",
    "BKPS_SQL_PATH":            "bkps_sql_path",
    "BKPS_ADMIN_TOOLS_DIR":     "bkps_admin_tools_dir",
    "AES_CCERT_TYPE":           "aes_ccert_type",
    "AES_CANCEL_ID":            "aes_cancel_id",
    "BKPS_SIGNING_KEY_CANCEL_ID": "bkps_signing_key_cancel_id",
    "AES_CCERT_IV":             "aes_ccert_iv",
    "SOFTHSM_LIB_PATH":         "softhsm_lib_path",
    "SOFTHSM_TOKEN_LABEL":      "softhsm_token_label",
    "SOFTHSM_USER_PIN":         "softhsm_user_pin",
    "SOFTHSM_SO_PIN":           "softhsm_so_pin",
    "SOFTHSM_KEY_LABEL":        "softhsm_key_label",
    "SOFTHSM_CONF_PATH":        "softhsm_conf_path",
    "SOFTHSM_TOKENS_DIR":       "softhsm_tokens_dir",
    "SOFTHSM_UTIL_PATH":        "softhsm_util_path",
    "PKCS11_TOOL_PATH":         "pkcs11_tool_path",
    "LIBSPDM_WRAPPER_PATH":     "libspdm_wrapper_path",
    "LOG_LEVEL":                "log_level",
    # ── LOCAL-FILE OVERRIDES (TEMP WORKAROUND) — grep-remove `LOCAL_OVERRIDE_` ─
    "LOCAL_OVERRIDE_TSCI_CERT":        "local_override_tsci_cert",
    "LOCAL_OVERRIDE_BOUNCYCASTLE_JAR": "local_override_bouncycastle_jar",
    "LOCAL_OVERRIDE_GRADLE_ZIP":       "local_override_gradle_zip",
}

# ── Config I/O ────────────────────────────────────────────────────────────────

_PATH_CONFIG_ATTRS = {
    "bkps_dir", "quartus_keys_dir", "cm_provisioning_dir", "bkps_repo_dir",
    "owner_root_key_path", "owner_root_key_private_path", "hsm_keystore_path",
    "softhsm_lib_path", "softhsm_conf_path", "softhsm_tokens_dir",
    "softhsm_util_path", "pkcs11_tool_path", "bundle_zip", "bkps_jar_path",
    "bkps_sql_path", "bkps_admin_tools_dir", "libspdm_wrapper_path",
    "local_override_tsci_cert", "local_override_bouncycastle_jar",
    "local_override_gradle_zip",
}

_AUTO_DETECT_PATH_ATTRS = {
    "softhsm_lib_path",
    "softhsm_conf_path",
    "softhsm_tokens_dir",
    "bkps_repo_dir",
}

_BOOL_CONFIG_ATTRS = {"include_bkp_programmer"}


def _resolve_config_path(value: str, config_dir: str) -> str:
    """Expand a configured path and anchor relative values to the config file."""
    expanded = os.path.expandvars(os.path.expanduser(value))
    if not os.path.isabs(expanded):
        expanded = os.path.join(config_dir, expanded)
    return os.path.abspath(os.path.normpath(expanded))


def normalize_project_paths(cfg: Config, *, require_project: bool = False) -> tuple[str, str]:
    """Normalize the independent project and source-checkout directories.

    ``BKPS_REPO_DIR`` is optional. When empty, prefer an embedded
    ``device-security-software-services`` checkout that already contains
    ``bkps_ui``; otherwise derive ``<BKPS_DIR>/bkps_repo``. Relative paths are
    anchored to the selected config file's directory, or to the current
    working directory when no config file is selected.
    """
    project_value = str(getattr(cfg, "bkps_dir", "") or "").strip()
    if not project_value:
        if require_project:
            raise ValueError(
                "BKPS Project Dir is empty. Load a project configuration or "
                "set BKPS Project Dir on the Configuration tab, then Apply it."
            )
        return "", ""

    config_file = str(getattr(cfg, "config_file", "") or "").strip()
    config_dir = (
        os.path.dirname(os.path.abspath(config_file))
        if config_file else os.getcwd()
    )
    project_dir = _resolve_config_path(project_value, config_dir)

    repo_value = str(getattr(cfg, "bkps_repo_dir", "") or "").strip()
    if repo_value:
        repo_dir = _resolve_config_path(repo_value, config_dir)
    else:
        repo_dir = _default_bkps_repo_dir(project_dir)

    cfg.bkps_dir = project_dir
    cfg.bkps_repo_dir = os.path.abspath(os.path.normpath(repo_dir))
    return cfg.bkps_dir, cfg.bkps_repo_dir


def load_config(cfg: Config) -> None:
    """Load KEY=VALUE settings from ``cfg.config_file`` into ``cfg``."""
    if not os.path.isfile(cfg.config_file):
        print_warning("Configuration file not found. Using defaults.")
        print_info("Run with --create-config to create a configuration file.")
        return

    print_info(f"Loading configuration from {cfg.config_file}")
    config_dir = os.path.dirname(os.path.abspath(cfg.config_file))
    with open(cfg.config_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue  # skip blank lines and full-line comments
            if "=" not in line:
                continue  # skip malformed lines that lack an '=' separator
            key, _, value = line.partition("=")
            key = key.strip()
            # Strip inline comments and surrounding quotes
            value = value.split("#")[0].strip().strip('"').strip("'")
            attr = _KEY_MAP.get(key)
            if attr:
                if not value and attr in _AUTO_DETECT_PATH_ATTRS:
                    continue
                if attr in _BOOL_CONFIG_ATTRS:
                    normalized = value.strip().lower()
                    if normalized not in {"1", "0", "true", "false", "yes", "no", "on", "off"}:
                        print_warning(
                            f"Ignoring invalid boolean value for {key}: {value!r}"
                        )
                        continue
                    value = normalized in {"1", "true", "yes", "on"}
                if value and attr in _PATH_CONFIG_ATTRS:
                    value = _resolve_config_path(value, config_dir)
                setattr(cfg, attr, value)

    repo_was_empty = not str(getattr(cfg, "bkps_repo_dir", "") or "").strip()
    project_dir, repo_dir = normalize_project_paths(cfg)
    if project_dir and repo_was_empty:
        embedded = detect_embedded_bkps_repo()
        if embedded and os.path.abspath(repo_dir) == os.path.abspath(embedded):
            print_info(
                f"BKPS_REPO_DIR not set; using embedded source tree "
                f"(bkps_ui already in repo): {repo_dir}"
            )
        else:
            print_info(f"BKPS_REPO_DIR not set; using project checkout: {repo_dir}")

    valid_ccert_types = list(aes_ccert_types_for_profile(cfg.profile_name).keys())
    if valid_ccert_types and cfg.aes_ccert_type not in valid_ccert_types:
        print_warning(
            f"AES_CCERT_TYPE '{cfg.aes_ccert_type}' is not valid for profile "
            f"'{cfg.profile_name}'. Valid values: {', '.join(valid_ccert_types)}"
        )

    print_success("Configuration loaded")


def create_config(cfg: Config) -> None:
    """Write current ``cfg`` values to ``cfg.config_file`` as KEY=VALUE text."""
    config_dir = os.path.dirname(cfg.config_file)
    if config_dir:
        os.makedirs(config_dir, exist_ok=True)

    content = f"""# BKPS Demo Configuration
# Edit this file to customize your setup

# ── User & Directories ────────────────────────────────────────────────────────
# Paths may be absolute, or relative to this configuration file.
# The Automation Studio installation directory is independent of BKPS_DIR.
USERNAME={cfg.username}
BKPS_DIR={cfg.bkps_dir}
QUARTUS_KEYS_DIR={cfg.quartus_keys_dir}
CM_PROVISIONING_DIR={cfg.cm_provisioning_dir}

# ── Device ────────────────────────────────────────────────────────────────────
PROFILE_NAME={cfg.profile_name}
DEVICE_PART={cfg.device_part}
JTAG_CABLE_NUM={cfg.jtag_cable_num}
QUARTUS_VERSION={cfg.quartus_version}
# Optional: pre-existing Device Owner Root public .qky file.
# When set, copied in as root0.qky (Quartus root key creation is skipped).
OWNER_ROOT_KEY_PATH={cfg.owner_root_key_path}
# Optional: matching Device Owner Root private-key PEM (secp384r1).
# Required alongside OWNER_ROOT_KEY_PATH when building Design / AES
# signing chains on top of the supplied Owner Root Key.
OWNER_ROOT_KEY_PRIVATE_PATH={cfg.owner_root_key_private_path}

# ── Server & Database ─────────────────────────────────────────────────────────
BKPS_SERVER_IP={cfg.bkps_server_ip}
BKPS_SERVER_PORT={cfg.bkps_server_port}
DB_HOST={cfg.db_host}
DB_NAME={cfg.db_name}
DB_USER={cfg.db_user}
DB_PASSWORD={cfg.db_password}
DB_PORT={cfg.db_port}
SUDO_PASSWORD={cfg.sudo_password}       # leave empty if sudo needs no password
PG_SUPERUSER_PASSWORD={cfg.pg_superuser_password}  # Windows postgres superuser (default: postgres)

# ── Passwords  (CHANGE IN PRODUCTION!) ───────────────────────────────────────
SSL_PASSWORD={cfg.ssl_password}
pkcs11_password={cfg.pkcs11_password}
KEYSTORE_PASSWORD={cfg.keystore_password}
AES_PASSPHRASE={cfg.aes_passphrase}
PROGRAMMER_CERT_PASSWORD={cfg.programmer_cert_password}

# ── Security Provider ─────────────────────────────────────────────────────────
SECURITY_PROVIDER={cfg.security_provider}  # bouncycastle | luna | ncipher
# BouncyCastle (software):
BC_KEYSTORE_PASSWORD={cfg.bc_keystore_password}
# HSM (Luna / nCipher) — only used when SECURITY_PROVIDER != bouncycastle:
HSM_KEYSTORE_PASSWORD={cfg.hsm_keystore_password}
HSM_KEYSTORE_PATH={cfg.hsm_keystore_path}

# ── AES Key Generation ────────────────────────────────────────────────────────
AES_CCERT_TYPE={cfg.aes_ccert_type}  # ccert_type passed to quartus_pfg --ccert
AES_CANCEL_ID={cfg.aes_cancel_id}    # --cancel value for AES cert signing key (append_key)
BKPS_SIGNING_KEY_CANCEL_ID={cfg.bkps_signing_key_cancel_id}  # --cancel value for BKPS signing key (append_key)
AES_CCERT_IV={cfg.aes_ccert_iv}      # IV hex; required only when key storage is OFFCHIP

# ── SoftHSM PKCS#11 (Agilex 5) ───────────────────────────────────────────────
SOFTHSM_LIB_PATH={cfg.softhsm_lib_path}
SOFTHSM_TOKEN_LABEL={cfg.softhsm_token_label}
SOFTHSM_USER_PIN={cfg.softhsm_user_pin}
SOFTHSM_SO_PIN={cfg.softhsm_so_pin}
SOFTHSM_KEY_LABEL={cfg.softhsm_key_label}
SOFTHSM_CONF_PATH={cfg.softhsm_conf_path}
SOFTHSM_TOKENS_DIR={cfg.softhsm_tokens_dir}
SOFTHSM_UTIL_PATH={cfg.softhsm_util_path}
PKCS11_TOOL_PATH={cfg.pkcs11_tool_path}

# ── BKPS Installation: Build from Source (Agilex 5 — SPDM) ──────────────────
# Used when BKPS_JAR_PATH and BKPS_SQL_PATH are both empty.
# Leave empty to auto-detect when bkps_ui is already inside a cloned
# device-security-software-services tree (skips git clone). Otherwise set
# an explicit checkout path; missing paths are cloned and built with Gradle.
BKPS_REPO_DIR={cfg.bkps_repo_dir}
BKPS_REPO_URL={cfg.bkps_repo_url}  # empty = https://github.com/altera-fpga/device-security-software-services.git
BKPS_RELEASE={cfg.bkps_release}  # "auto" detects latest, or e.g. "release/BKPS_25.1-2"
BKPS_BUILD_MODE={cfg.bkps_build_mode}  # bkp_only | full
INCLUDE_BKP_PROGRAMMER={'true' if cfg.include_bkp_programmer else 'false'}
BKPS_VERSION={cfg.bkps_version}  # explicit version string; leave empty for auto-detect

# ── BKPS Installation: ZIP Bundle (Agilex 7 / Stratix 10 — SIGMA) ────────────
# Used when BKPS_JAR_PATH is empty and a ZIP bundle is provided.
BUNDLE_ZIP={cfg.bundle_zip}
BUNDLE_ZIP_PASSWORD={cfg.bundle_zip_password}

# ── BKPS Installation: Pre-built Files (all profiles) ────────────────────────
# When BKPS_JAR_PATH and BKPS_SQL_PATH are both set, skips source build and ZIP
# entirely — JAR, SQL, libspdm wrapper, and admin-tools are copied from these paths.
BKPS_JAR_PATH={cfg.bkps_jar_path}
BKPS_SQL_PATH={cfg.bkps_sql_path}
BKPS_ADMIN_TOOLS_DIR={cfg.bkps_admin_tools_dir}  # leave empty to clone repo automatically
LIBSPDM_WRAPPER_PATH={cfg.libspdm_wrapper_path}  # leave empty to build automatically

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL={cfg.log_level}  # INFO or DEBUG

# ── LOCAL-FILE OVERRIDES (TEMP WORKAROUND) ───────────────────────────────────
# Optional local file paths used in place of online downloads.  Leave any of
# these EMPTY to fall back to the normal download path.  Grep-remove the
# LOCAL_OVERRIDE_ prefix to drop this feature cleanly later.
LOCAL_OVERRIDE_TSCI_CERT={cfg.local_override_tsci_cert}
LOCAL_OVERRIDE_BOUNCYCASTLE_JAR={cfg.local_override_bouncycastle_jar}
LOCAL_OVERRIDE_GRADLE_ZIP={cfg.local_override_gradle_zip}
"""
    with open(cfg.config_file, "w", encoding="utf-8") as f:
        f.write(content)

    print_success(f"Configuration file created: {cfg.config_file}")
    print_warning(f"IMPORTANT: Edit {cfg.config_file} to change default passwords before running in production!")

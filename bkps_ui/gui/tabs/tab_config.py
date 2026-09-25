#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path
from PySide6.QtCore import Qt, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QGroupBox, QLineEdit, QPushButton, QFileDialog,
    QScrollArea, QFrame, QLabel, QComboBox, QRadioButton,
    QButtonGroup, QCheckBox,
)
import glob
from tabs import BaseTab
from config_store import ConfigStore
from stdout_capture import StdoutCapture
from bkps_config import (
    DEVICE_FAMILIES,
    AES_CCERT_TYPES,
    aes_ccert_requires_iv,
    aes_ccert_types_for_profile,
    detect_embedded_bkps_repo,
    detect_softhsm_tokens_dir,
    LOGGING_TYPES,
    normalize_project_paths,
)
from bkps_build import (
    BKPS_REPO_URL,
    _find_libspdm_wrapper_candidates,
    fetch_bkps_releases,
    install_from_files,
    install_bundle_zip,
)
from utils.bkps_utils import *
from utils.ui_helpers import (
    DEFAULT_SECRET_FIELDS,
    default_secret_warnings,
    find_softhsm_tools,
)


class _FetchReleasesWorker(QThread):
    """Fetch BKPS release branch names from GitHub in a background thread."""
    done = Signal(list)

    def run(self):
        try:
            releases = fetch_bkps_releases(timeout=10)
        except Exception:
            releases = []
        self.done.emit(releases)


class _DetectSofthsmWorker(QThread):
    """Search for all SoftHSM and PKCS#11 runtime paths in a worker thread."""
    done = Signal(dict)

    def __init__(self, bkps_dir: str, parent=None):
        super().__init__(parent)
        self._bkps_dir = bkps_dir

    def run(self):
        self.done.emit(find_softhsm_tools(self._bkps_dir))


class ConfigTab(BaseTab):
    # Emitted whenever the operator successfully applies the config form
    # (Apply Changes → no validation errors).  AppWindow listens for this
    # to unlock the Setup / BKP / Utility tabs; before the first emit,
    # every downstream tab's buttons stay disabled.
    config_applied = Signal()
    # AppWindow rebuilds project-specific pipeline state after this signal.
    project_loaded = Signal()

    """Configuration tab (Tab 1).

    Provides a scrollable form for editing every ConfigStore field.
    Supports loading from / saving to .conf files, and applies changes to the
    in-memory config via the *Apply Changes* toolbar button.

    Attributes:
        _fields: Mapping of ConfigStore attribute name → QLineEdit widget.
        _softhsm_worker: Background thread for SoftHSM library detection.
        _release_worker: Background thread for GitHub release branch fetch.
    """

    def __init__(self, store: ConfigStore, capture: StdoutCapture, parent=None):
        self._fields: dict[str, QLineEdit] = {}
        self._section_forms: list[QFormLayout] = []
        self._release_worker = None
        self._softhsm_worker = None
        self._libspdm_row_label = None
        self._libspdm_row_widget = None
        self._softhsm_lib_row_label = None
        self._softhsm_lib_row_widget = None
        # Widgets needing show/hide based on device family (populated in build_controls)
        self._repo_row_label = None
        self._repo_row_widget = None
        self._release_row_label = None
        self._release_row_widget = None
        self._release_status_label = None
        # Section header labels (show/hide with device family)
        self._section_softhsm_label = None
        self._section_source_label = None
        self._section_zip_label = None
        # Security provider show/hide references
        self._bc_row_label = None
        self._bc_row_widget = None
        self._hsm_pwd_row_label = None
        self._hsm_pwd_row_widget = None
        self._hsm_path_row_label = None
        self._hsm_path_row_widget = None
        super().__init__(store, capture, log_title="Config Log", parent=parent)

    def build_controls(self) -> QWidget:
        """Construct all configuration form widgets and connect signals.

        Returns:
            QWidget: A container widget holding the load/save toolbar and a
            scrollable form of all editable ConfigStore fields grouped by category.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(4, 4, 4, 4)

        # --- Toolbar ---
        toolbar = QHBoxLayout()
        self._btn_load = _btn("Load Config File…", tip=(
            "Load settings from a .conf file into the current session.\n"
            "Opens a file browser to select the config file."
        ))
        self._btn_save = _btn("Save Config File…", tip=(
            "Save the current settings to a .conf file on disk.\n"
            "Apply Changes is called automatically before saving."
        ))
        self._btn_apply = _btn("Apply Changes", primary=True, tip=(
            "Apply the field values above to the in-memory config.\n"
            "Changes are not written to disk until you click 'Save Config File…'."
        ))
        for btn in (self._btn_load, self._btn_save, self._btn_apply):
            toolbar.addWidget(btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        self._btn_load.clicked.connect(self._load)
        self._btn_save.clicked.connect(self._save)
        self._btn_apply.clicked.connect(self._apply)

        # --- Scrollable, group-boxed form ---
        # Each section is its own QGroupBox with its own inner QFormLayout,
        # mirroring the section-box style used on the other tabs.  The
        # ``form`` name is reassigned on every _new_section() call so the
        # existing form.addRow(...) statements land in the current section.
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        sections_widget = QWidget()
        sections_layout = QVBoxLayout(sections_widget)
        sections_layout.setContentsMargins(0, 0, 0, 0)
        sections_layout.setSpacing(8)

        def _new_section(title: str) -> QFormLayout:
            """Add a new QGroupBox section and return its inner QFormLayout."""
            gb = QGroupBox(title)
            inner = QFormLayout(gb)
            inner.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
            # Keep value fields aligned on a single column even when labels
            # vary in width by giving all rows the same field-growth policy.
            inner.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
            inner.setSpacing(6)
            sections_layout.addWidget(gb)
            # Attach the group box to the layout so callers can hide the
            # whole section by hiding the returned label / stored ref.
            inner._group_box = gb  # type: ignore[attr-defined]
            self._section_forms.append(inner)
            return inner

        # Initial section - Paths & Directories
        form = _new_section("Paths && Directories")

        # ── Paths & Directories ────────────────────────────────────────────
        self._le_bkps_dir = _le(
            "/path/to/project",
            tip=(
                "Operator-selected BKPS project directory where generated files "
                "are stored. It may be on a different drive or filesystem from "
                "the Automation Studio installation."
            ),
            attr="bkps_dir",
            fields=self._fields
        )
        form.addRow("BKPS Project Dir:", _file_row(self._le_bkps_dir, self._browse_bkps_dir, widget=True))
        self._le_bkps_dir.textChanged.connect(self._on_bkps_dir_changed)

        self._le_quartus_keys_dir = _le(
            "/path/to/quartus/keys",
            tip="Directory holding the Quartus signing keys used by the BKPS keys flow.",
            attr="quartus_keys_dir",
            fields=self._fields
        )
        form.addRow("Quartus Keys Dir:", _file_row(self._le_quartus_keys_dir, self._browse_quartus_keys_dir, widget=True))

        self._le_cm_provisioning_dir = _le(
            "/path/to/cm_provisioning",
            tip="Directory holding user credentials used for device onboarding or black key provisioning(BKP).",
            attr="cm_provisioning_dir",
            fields=self._fields
        )
        form.addRow("CM Provisioning Dir:", _file_row(self._le_cm_provisioning_dir, self._browse_cm_provisioning_dir, widget=True))

        # ── Device ────────────────────────────────────────────────────────
        form = _new_section("Device")

        family_row = QHBoxLayout()
        self._combo_device = _combo(minimum_width=200)
        for display_name in DEVICE_FAMILIES:
            self._combo_device.addItem(display_name)
        part_lbl = QLabel("Part:")
        part_lbl.setStyleSheet("margin-left: 8px;")
        self._le_device_part = _le(
            "e.g. A5ED013BB32AE4SCS", max_width=200,
            tip="Device part number used by Quartus signing / programming "
                "commands.  Required — enter the OPN for your device.",
            attr="device_part",
            fields=self._fields,
        )
        family_row.addWidget(self._combo_device, stretch=1)
        family_row.addWidget(part_lbl)
        family_row.addWidget(self._le_device_part)
        family_widget = QWidget()
        family_widget.setLayout(family_row)
        form.addRow("Device Family:", family_widget)
        self._combo_device.currentTextChanged.connect(self._on_device_family_changed)

        self._le_jtag_cable_num = _le(
                                      "JTAG cable ID",
                                      text="1",
                                      tip="JTAG cable index passed to quartus_pgm as -c<ID>.",
                                      attr="jtag_cable_num",
                                      fields=self._fields
                                  )
        form.addRow("JTAG Cable #:", self._le_jtag_cable_num)
        self._le_quartus_version = _le(
                                       "Quartus Version",
                                       tip="Installed Quartus version string.",
                                       attr="quartus_version",
                                       fields=self._fields
                                   )
        form.addRow("Quartus Version:", self._le_quartus_version)

        # Device Owner Root Key — optional operator-supplied .qky file.
        # When set, Full Installation skips the Quartus Owner Root Key
        # creation flow and reuses the supplied .qky directly.
        self._le_owner_root_key = _le(
            "Leave empty and a new root key (.qky) is created instead",
            tip=(
                "Optional path to an existing Device Owner Root Key (.qky) file.\n"
                "When set, Full Installation skips the Quartus root key creation "
                "flow\nand reuses this root qky directly."
            ),
            attr="owner_root_key_path",
            fields=self._fields
        )
        form.addRow(
            "Device Owner Root Key (.qky):",
            _file_row(self._le_owner_root_key, self._browse_owner_root_key, widget=True),
        )

        # Matching private-key PEM for the supplied Owner Root .qky.
        # Required when the supplied .qky is used to build Design / AES Cert
        # signing chains on top of the Owner Root Key.
        self._le_owner_root_key_pem = _le(
            "Matching private PEM for the supplied .qky (paired root keypair)",
            tip=(
                "Path to the private key PEM that pairs with the supplied Owner "
                "Root Key (.qky) above.\nCopied in as root0_private.pem so the Design "
                "and AES Cert signing chains\ncan be built on top of the "
                "supplied Owner Root Key."
            ),
            attr="owner_root_key_private_path",
            fields=self._fields
        )
        form.addRow(
            "Device Owner Root Key (.pem):",
            _file_row(self._le_owner_root_key_pem, self._browse_owner_root_key_pem, widget=True),
        )
        self._le_bkps_signing_key_cancel_id = _le(
            "e.g. 1",
            max_width=160,
            attr="bkps_signing_key_cancel_id",
            fields=self._fields
        )
        form.addRow("BKPS Signing Key Cancellation ID:", self._le_bkps_signing_key_cancel_id)

        # ── Server & Database ─────────────────────────────────────────────
        form = _new_section("Server && Database")

        form.addRow("Server IP:", _le(
            "BKPS Server IP",
            text="localhost",
            tip="BKPS server IP/host that admin-tools runner.py connects to.",
            attr="bkps_server_ip",
            fields=self._fields
        ))
        form.addRow("Server Port:", _le(
            "BKPS Server Port",
            text="8082",
            tip="BKPS server HTTPS port (default 8082).",
            attr="bkps_server_port",
            fields=self._fields
        ))
        form.addRow("DB Host:", _le(
            "DB host",
            text="localhost",
            tip="PostgreSQL host for the BKPS database.",
            attr="db_host",
            fields=self._fields
        ))
        form.addRow("DB Name:", _le(
            "BKPS database name",
            tip="PostgreSQL database name used by BKPS.",
            attr="db_name",
            fields=self._fields
        ))
        form.addRow("DB User:", _le(
            "BKPS database user",
            tip="PostgreSQL user account for the BKPS database.",
            attr="db_user",
            fields=self._fields
        ))
        form.addRow("DB Password:", _le(
            "DB password",
            password=True,
            tip="Password for the BKPS PostgreSQL user.",
            attr="db_password",
            fields=self._fields
        ))
        form.addRow("DB Port:", _le(
            "DB Port",
            text="5432",
            tip="PostgreSQL server port (default 5432).",
            attr="db_port",
            fields=self._fields
        ))
        form.addRow("Sudo Password:", _le(
            "leave empty if passwordless sudo",
            tip="Sudo password for privileged operations (installing dependencies, database setup). Leave empty if sudo is passwordless.",
            attr="sudo_password",
            password=True,
            fields=self._fields
        ))
        form.addRow("PG Superuser Password:", _le(
            "PostgreSQL Superuser Password",
            text="postgres",
            tip="PostgreSQL superuser (postgres) password used for database create / reset.",
            attr="pg_superuser_password",
            password=True,
            fields=self._fields
        ))

        # ── Passwords ─────────────────────────────────────────────────────
        # BKPS Passwords subsection: SSL / PKCS12 / server keystore passwords.
        form = _new_section("BKPS Passwords  (change before production use)")
        form.addRow("SSL Password:", _le(
            "SSL Password",
            tip="Password protecting the BKPS SSL private key. Change before production use.",
            attr="ssl_password",
            password=True,
            fields=self._fields
        ))
        form.addRow("PKCS11 Password:", _le(
            "PKCS11 Password",
            tip="Password for the BKPS PKCS11 file. Change before production use.",
            attr="pkcs11_password",
            password=True,
            fields=self._fields
        ))
        form.addRow("Keystore Password:", _le(
            "KeyStore Password",
            tip="Password for the BKPS server keystore. Change before production use.",
            attr="keystore_password",
            password=True,
            fields=self._fields
        ))

        # AES Encryption Password subsection: passphrase used by SIGMA
        # protocol supported devices (Agilex 7 / Stratix 10 / Easic N5X) openssl-based AES compact-cert
        # flow.  Agilex 5 uses SoftHSM so the passphrase is not consulted;
        # the field is greyed out in that case.
        form = _new_section("AES Encryption Password")
        self._section_aes_passphrase = form._group_box  # entire section shown/hidden as one
        self._le_aes_passphrase = _le("AES encryption passphrase", attr="aes_passphrase", password=True, fields=self._fields)
        form.addRow("AES Passphrase:", self._le_aes_passphrase)

        if sys.platform.startswith("win"):
            # Client Certificate subsection: PFX password used by the Windows
            # programmer client certificate.  Greyed out on non-Windows hosts.
            form = _new_section("Client Certificate")
            self._le_programmer_cert_password = _le(
                "Programmer User Password",
                tip="Password for the Windows programmer client certificate PFX.",
                attr="programmer_cert_password",
                password=True,
                fields=self._fields
            )
            form.addRow("Programmer PFX Password:", self._le_programmer_cert_password)

        # ── Security Provider ──────────────────────────────────────────────
        form = _new_section("Security Provider")

        self._combo_provider = QComboBox()
        self._combo_provider.addItems(["bouncycastle", "luna", "ncipher"])
        self._combo_provider.setMinimumWidth(180)
        self._combo_provider.setToolTip(
            "bouncycastle — software provider (default)\n"
            "luna        — Gemalto SafeNet Luna SA HSM\n"
            "ncipher     — Entrust nShield HSM"
        )
        form.addRow("Security Provider:", self._combo_provider)
        self._combo_provider.currentTextChanged.connect(self._on_provider_changed)

        self._bc_row_label = QLabel("BC Keystore Password:")
        le_bc = _le(
            "BouncyCastle keystore password",
            tip="Password for the BouncyCastle UBER keystore that stores qek_encryption_key.",
            attr="bc_keystore_password",
            password=True,
            fields=self._fields
        )
        self._bc_row_widget = le_bc
        form.addRow(self._bc_row_label, le_bc)

        self._hsm_pwd_row_label = QLabel("HSM Password:")
        le_hsm_pwd = _le("HSM keystore / partition password", tip=(
            "Luna: partition password\n"
            "nCipher: Security World (.sworld) keystore password"
        ),
            attr="hsm_keystore_password",
            password=True,
            fields=self._fields)
        self._hsm_pwd_row_widget = le_hsm_pwd
        form.addRow(self._hsm_pwd_row_label, le_hsm_pwd)

        self._hsm_path_row_label = QLabel("HSM Keystore Path:")
        le_hsm_path = _le(
            "HSM Keystore Path",
            tip=(
                "Bouncycastle: path to JKS file\n"
                "Luna: partition label, e.g. tokenlabel:BKPPartition\n"
                "nCipher: path to JKS file (leave empty for module-protection mode)"
            ),
            attr="hsm_keystore_path",
            fields=self._fields
        )
        self._hsm_path_row_widget = le_hsm_path
        form.addRow(self._hsm_path_row_label, le_hsm_path)

        # ── AES Key Generation ────────────────────────────────────────────
        form = _new_section("AES Key Generation")

        self._combo_aes_ccert = QComboBox()
        self._combo_aes_ccert.setMinimumWidth(300)
        form.addRow("AES Storage:", self._combo_aes_ccert)
        self._combo_aes_ccert.currentTextChanged.connect(self._on_aes_ccert_changed)

        self._le_aes_cancel_id = _le(
            "e.g. 1",
            max_width=160,
            tip="AES key cancellation ID (e.g. 1).",
            attr="aes_cancel_id",
            fields=self._fields
        )
        form.addRow("AES Cancellation ID:", self._le_aes_cancel_id)

        # IV is only required when key storage is OFFCHIP.
        # Both label and field are hidden by _on_aes_ccert_changed when not needed.
        self._lbl_aes_ccert_iv = QLabel("AES ccert IV (hex):")
        self._le_aes_ccert_iv = _le(
            max_width=360,
            tip="Initialization Vector (IV) hex; required only when key storage is OFFCHIP",
            attr="aes_ccert_iv",
            fields=self._fields,
        )
        form.addRow(self._lbl_aes_ccert_iv, self._le_aes_ccert_iv)

        # ── SoftHSM PKCS#11 (Agilex 5) ────────────────────────────────────
        form = _new_section("SoftHSM PKCS\u266f11  (Agilex 5)")
        self._section_softhsm_label = form._group_box  # entire section shown/hidden as one
        self._softhsm_rows: list = []

        self._softhsm_detect_row_label = QLabel("Tool Discovery:")
        self._btn_detect_softhsm = _btn("Auto-Detect Tools", width=140, tip=(
            "Search PATH, managed BKPS runtime paths, common system locations,\n"
            "and BKPS paths for the SoftHSM library, softhsm2-util, and pkcs11-tool."
        ))
        self._btn_detect_softhsm.clicked.connect(self._detect_softhsm)
        _softhsm_detect_row = QWidget()
        _softhsm_detect_layout = QHBoxLayout(_softhsm_detect_row)
        _softhsm_detect_layout.setContentsMargins(0, 0, 0, 0)
        _softhsm_detect_layout.addWidget(self._btn_detect_softhsm)
        _softhsm_detect_layout.addStretch()
        form.addRow(self._softhsm_detect_row_label, _softhsm_detect_row)
        self._softhsm_rows.append(
            (self._softhsm_detect_row_label, _softhsm_detect_row)
        )

        self._softhsm_lib_row_label = QLabel("SoftHSM Library:")
        self._le_softhsm_lib = _le(
            "Auto-detected SoftHSM provider path",
            tip="Path to the SoftHSM PKCS#11 shared library (libsofthsm2.so on Linux, softhsm2.dll on Windows).",
            attr="softhsm_lib_path",
            fields=self._fields
        )
        self._softhsm_lib_row_widget = _file_row(
            self._le_softhsm_lib, self._browse_softhsm, widget=True)
        form.addRow(self._softhsm_lib_row_label, self._softhsm_lib_row_widget)
        self._softhsm_rows.append((self._softhsm_lib_row_label, self._softhsm_lib_row_widget))

        self._softhsm_conf_row_label = QLabel("SoftHSM Configuration:")
        self._le_softhsm_conf = _le(
            "Auto-detected softhsm2.conf path",
            tip=(
                "Exact softhsm2.conf passed to SoftHSM and Quartus through "
                "SOFTHSM2_CONF."
            ),
            attr="softhsm_conf_path",
            fields=self._fields,
        )
        self._softhsm_conf_row_widget = _file_row(
            self._le_softhsm_conf, self._browse_softhsm_conf, widget=True
        )
        form.addRow(
            self._softhsm_conf_row_label,
            self._softhsm_conf_row_widget,
        )
        self._softhsm_rows.append(
            (self._softhsm_conf_row_label, self._softhsm_conf_row_widget)
        )

        self._softhsm_tokens_row_label = QLabel("SoftHSM Token Store:")
        self._le_softhsm_tokens = _le(
            "Token directory from directories.tokendir",
            tip=(
                "Token storage directory selected by the SoftHSM "
                "configuration file."
            ),
            attr="softhsm_tokens_dir",
            fields=self._fields,
        )
        self._softhsm_tokens_row_widget = _file_row(
            self._le_softhsm_tokens, self._browse_softhsm_tokens, widget=True
        )
        form.addRow(
            self._softhsm_tokens_row_label,
            self._softhsm_tokens_row_widget,
        )
        self._softhsm_rows.append(
            (self._softhsm_tokens_row_label, self._softhsm_tokens_row_widget)
        )

        self._le_softhsm_token_label = _le("SoftHSM Token Label", attr="softhsm_token_label", text=self.cfg.softhsm_token_label, tip="Label of the SoftHSM token used for AES key operations (Agilex 5).", fields=self._fields)
        lbl = QLabel("Token Label:")
        form.addRow(lbl, self._le_softhsm_token_label)
        self._softhsm_rows.append((lbl, self._le_softhsm_token_label))
        self._le_softhsm_so_pin = _le("Security Officer PIN for the SoftHSM token", attr="softhsm_so_pin", text=self.cfg.softhsm_so_pin, password=True, tip="Security Officer PIN for the SoftHSM token (used when initializing the token).", fields=self._fields)
        lbl = QLabel("SO PIN:")
        form.addRow(lbl, self._le_softhsm_so_pin)
        self._softhsm_rows.append((lbl, self._le_softhsm_so_pin))
        self._le_softhsm_user_pin = _le("User PIN for the SoftHSM token", attr="softhsm_user_pin", text=self.cfg.softhsm_user_pin, password=True, tip="User PIN for the SoftHSM token — used for AES key generate / import / delete operations.", fields=self._fields)
        lbl = QLabel("User PIN:")
        form.addRow(lbl, self._le_softhsm_user_pin)
        self._softhsm_rows.append((lbl, self._le_softhsm_user_pin))
        self._le_softhsm_key_label = _le("SoftHSM Token Key Label", attr="softhsm_key_label", text=self.cfg.softhsm_key_label, tip="Label of the AES key object inside the SoftHSM token.", fields=self._fields)
        lbl = QLabel("Key Label:")
        form.addRow(lbl, self._le_softhsm_key_label)
        self._softhsm_rows.append((lbl, self._le_softhsm_key_label))

        # SoftHSM util binary path — used by the AES compact-cert tab so
        # operators can point at a specific softhsm2-util installation.
        self._softhsm_util_row_label = QLabel("SoftHSM Util (softhsm2-util):")
        self._le_softhsm_util = _le(
            "Full path to softhsm2-util (leave empty to use PATH)",
            tip=(
                "Full filesystem path to the softhsm2-util executable.\n"
                "Used by the AES compact certificate tab (Agilex 5) for all\n"
                "SoftHSM token operations.  Leave empty to fall back to PATH."
            ),
            attr="softhsm_util_path",
            fields=self._fields
        )
        _softhsm_util_row = _file_row(self._le_softhsm_util, self._browse_softhsm_util, widget=True)
        form.addRow(self._softhsm_util_row_label, _softhsm_util_row)
        self._softhsm_rows.append((self._softhsm_util_row_label, _softhsm_util_row))

        # PKCS#11 tool binary path — used by the AES compact-cert tab for
        # AES key generation / import operations against the SoftHSM token.
        self._pkcs11_tool_row_label = QLabel("PKCS#11 Tool (pkcs11-tool):")
        self._le_pkcs11_tool = _le(
            "Full path to pkcs11-tool (leave empty to use PATH)",
            tip=(
                "Full filesystem path to the pkcs11-tool executable (from OpenSC).\n"
                "Used by the AES compact certificate tab (Agilex 5) for AES key\n"
                "generation and import via SoftHSM.  Leave empty to fall back to PATH."
            ),
            attr="pkcs11_tool_path",
            fields=self._fields
        )
        _pkcs11_tool_row = _file_row(self._le_pkcs11_tool, self._browse_pkcs11_tool, widget=True)
        form.addRow(self._pkcs11_tool_row_label, _pkcs11_tool_row)
        self._softhsm_rows.append((self._pkcs11_tool_row_label, _pkcs11_tool_row))

        # ── BKPS Installation — Build from Source (Agilex 5) ─────────────
        form = _new_section(
            "BKPS Installation — Build from Source  (Agilex 5, SPDM protocol)"
        )
        self._section_source_label = form._group_box

        # str.removesuffix requires Python 3.9+; use conditional slice for 3.8.
        _repo_url_display = BKPS_REPO_URL[:-4] if BKPS_REPO_URL.endswith(".git") else BKPS_REPO_URL
        _lbl_repo_url = _le(
            text=_repo_url_display,
            read_only=True,
            style="color: #888; background: transparent; border: none;",
            tip="URL of the BKPS git repository (read-only).",
        )
        form.addRow("BKPS Repo URL:", _lbl_repo_url)

        self._repo_row_label = QLabel("BKPS Repo Dir:")
        self._le_bkps_repo_dir = _le(
            "/path/to/device-security-software-services",
            tip=(
                "Local BKPS repository (device-security-software-services).\n\n"
                "  • When bkps_ui is already inside a cloned DSSS tree, this\n"
                "    is auto-detected and clone is skipped.\n"
                "  • If the path already contains a BKPS source checkout\n"
                "    (a 'bkps/' sub-folder with build.gradle), it is reused\n"
                "    in place — no git clone / fetch / checkout is performed.\n"
                "  • Otherwise the repository shown above is cloned into\n"
                "    this directory and the selected release is checked out.\n"
                "  • Leave empty to auto-detect / use <BKPS_DIR>/bkps_repo."
            ),
            attr="bkps_repo_dir",
            fields=self._fields
        )
        self._repo_row_widget = _file_row(self._le_bkps_repo_dir, self._browse_bkps_repo_dir, widget=True)
        form.addRow(self._repo_row_label, self._repo_row_widget)

        self._release_row_label = QLabel("BKPS Release:")
        release_row = QHBoxLayout()
        self._combo_release = QComboBox()
        self._combo_release.setEditable(True)
        self._combo_release.setMinimumWidth(260)
        self._btn_fetch_release = _btn("Fetch Releases", width=110, tip=(
            "Fetch available BKPS release branches from GitHub\n"
            "to populate the release dropdown. Requires internet access."
        ))
        self._btn_fetch_release.clicked.connect(self._fetch_releases)
        release_row.addWidget(self._combo_release, stretch=1)
        release_row.addWidget(self._btn_fetch_release)
        self._release_row_widget = QWidget()
        self._release_row_widget.setLayout(release_row)
        form.addRow(self._release_row_label, self._release_row_widget)

        self._lbl_release_status = QLabel("")
        self._lbl_release_status.setStyleSheet("color: #888; font-size: 8pt;")
        self._release_status_label = self._lbl_release_status
        form.addRow("", self._lbl_release_status)

        self._build_mode_row_label = QLabel("Build Selection:")
        build_mode_row = QHBoxLayout()
        self._radio_build_full = QRadioButton("Full")
        self._radio_build_full.setToolTip(
            "Also build the repository's auxiliary applications and artifacts."
        )
        self._radio_build_bkp_only = QRadioButton("BKP only")
        self._radio_build_bkp_only.setToolTip(
            "Build only the BKPS server JAR, SQL schema, and SPDM wrapper."
        )
        self._radio_build_bkp_programmer = QRadioButton("BKP with BKPProgrammer")
        self._radio_build_bkp_programmer.setToolTip(
            "Build the BKPS server JAR, SQL schema, and SPDM wrapper, plus "
            "BKPProgrammer."
        )
        self._build_mode_group = QButtonGroup(self)
        self._build_mode_group.setExclusive(True)
        for radio in (
            self._radio_build_full,
            self._radio_build_bkp_only,
            self._radio_build_bkp_programmer,
        ):
            self._build_mode_group.addButton(radio)
            build_mode_row.addWidget(radio)
        build_mode_row.addStretch(1)
        self._build_mode_row_widget = QWidget()
        self._build_mode_row_widget.setLayout(build_mode_row)
        form.addRow(self._build_mode_row_label, self._build_mode_row_widget)

        form.addRow("BKPS Version:", _le(
            "leave empty to auto-detect",
            tip="Specific BKPS release version to check out (leave empty to auto-detect from the repo).",
            attr="bkps_version",
            fields=self._fields
        ))

        # ── BKPS Installation — ZIP Bundle (SIGMA) ────────────────────────
        form = _new_section(
            "BKPS Installation — ZIP Bundle  (Agilex 7 / Stratix 10, SIGMA protocol)"
        )
        self._section_zip_label = form._group_box

        self._zip_row_label = QLabel("bundle ZIP:")
        self._le_bundle_zip = _le(
            "/path/to/bkps-bundle.zip",
            tip="Path to the BKPS bundle ZIP (used for SIGMA devices: Agilex 7 / Stratix 10).",
            attr="bundle_zip",
            fields=self._fields
        )
        self._zip_row_widget = QWidget()
        self._zip_row_widget.setLayout(_file_row(self._le_bundle_zip, self._browse_zip))
        form.addRow(self._zip_row_label, self._zip_row_widget)

        self._zip_pwd_row_label = QLabel("Bundle Password:")
        self._le_bundle_zip_password = _le(
            "ZIP password (if encrypted)",
            password=True,
            tip="Password to unzip an encrypted BKPS bundle ZIP (leave empty if unencrypted).",
            attr="bundle_zip_password",
            fields=self._fields
        )
        form.addRow(self._zip_pwd_row_label, self._le_bundle_zip_password)

        # Install Bundle button — extracts the configured ZIP into cfg.bkps_dir.
        # Enabled only for SIGMA devices when a ZIP path is present.
        self._install_bundle_row_label = QLabel("")
        self._btn_install_bundle = _btn("Install Bundle", primary=True, width=160, tip=(
            "Extract the bundle ZIP above into the BKPS directory.\n"
            "Used for Agilex 7 / Stratix 10 (SIGMA flow). Enabled only when\n"
            "a ZIP path is configured for a SIGMA device family."
        ))
        self._btn_install_bundle.clicked.connect(self._install_bundle_zip)
        install_row_layout = QHBoxLayout()
        install_row_layout.setContentsMargins(0, 0, 0, 0)
        install_row_layout.addWidget(self._btn_install_bundle)
        install_row_layout.addStretch()
        self._install_bundle_row_widget = QWidget()
        self._install_bundle_row_widget.setLayout(install_row_layout)
        form.addRow(self._install_bundle_row_label, self._install_bundle_row_widget)
        # Refresh install-bundle enable state whenever the ZIP path changes.
        self._le_bundle_zip.textChanged.connect(self._refresh_install_bundle_state)

        # ── BKPS Installation — Pre-built Files (all profiles) ───────────
        form = _new_section(
            "BKPS Installation — Pre-built Files  (all profiles, skips build and ZIP)"
        )

        self._le_bkps_jar = _le(
            "Leave empty to build/extract automatically",
            tip="Optional pre-built BKPS server JAR. Leave empty to build from source (Agilex 5) or extract from the bundle ZIP (SIGMA).",
            attr="bkps_jar_path",
            fields=self._fields
        )
        form.addRow("BKPS JAR File:", _file_row(self._le_bkps_jar, self._browse_jar, widget=True))

        self._le_bkps_sql = _le(
            "Leave empty to build/extract automatically",
            tip="Optional pre-built BKPS database schema (.sql). Leave empty to generate via Gradle or extract from the bundle.",
            attr="bkps_sql_path",
            fields=self._fields
        )
        form.addRow("BKPS SQL Schema:", _file_row(self._le_bkps_sql, self._browse_sql, widget=True))

        self._le_bkps_admin_tools = _le(
            "Leave empty to clone repo and copy automatically",
            tip="Optional pre-existing admin-tools directory (containing runner.py). Leave empty to clone / copy automatically.",
            attr="bkps_admin_tools_dir",
            fields=self._fields
        )
        form.addRow("Admin Tools Dir:", _file_row(self._le_bkps_admin_tools,
                                                    self._browse_admin_tools_cfg))

        self._libspdm_row_label = QLabel("libspdm Wrapper Path:")
        self._le_libspdm = _le(
            "Leave empty to build automatically (Agilex 5)",
            tip="Path to the libspdm_wrapper shared library (Agilex 5). Leave empty to auto-build during installation.",
            attr="libspdm_wrapper_path",
            fields=self._fields
        )
        # The per-field libspdm Auto-Detect button was removed in favour
        # of the bulk "Auto-Detect" button next to "Install Pre-built
        # Files" (see below), which fills JAR / SQL / Admin Tools /
        # libspdm from ``bkps_repo_dir`` in one shot.
        self._libspdm_row_widget = _file_row(
            self._le_libspdm, self._browse_libspdm, widget=True)
        form.addRow(self._libspdm_row_label, self._libspdm_row_widget)

        # Install Pre-built Files button — copies JAR/SQL/admin-tools/libspdm into cfg.bkps_dir.
        # Enabled only when all four paths (JAR, SQL, Admin Tools Dir, libspdm Wrapper) are set.
        self._btn_install_prebuilt = _btn(
            "Install Pre-built Files",
            primary=True,
            width=180,
            tip=(
                "Copy the four pre-built artefacts (JAR, SQL, admin-tools, libspdm)\n"
                "into the BKPS directory — skips the build and ZIP-extract steps.\n"
                "Enabled only when all four paths above are set."
            ),
        )
        self._btn_install_prebuilt.clicked.connect(self._install_prebuilt_files)
        # Bulk auto-detect: scans ``bkps_repo_dir`` and fills all four
        # pre-built fields (JAR / SQL / Admin Tools / libspdm) at once
        # so the operator doesn't have to Browse each one individually.
        self._btn_detect_prebuilt = _btn(
            "Auto-Detect",
            width=110,
            tip=(
                "Scan the BKPS Repo Directory and fill all four fields\n"
                "(JAR, SQL, Admin Tools, libspdm) at once.\n"
                "Searches:\n"
                "  JAR      → <bkps_repo_dir>/bkps/build/libs/\n"
                "  SQL      → <bkps_repo_dir>/bkps/**/*.sql\n"
                "  libspdm  → <bkps_repo_dir>/spdm_wrapper/build/Release/wrapper/\n"
                "  Admin    → <bkps_repo_dir>/admin-tools/"
            ),
        )
        self._btn_detect_prebuilt.clicked.connect(self._detect_prebuilt_all)
        prebuilt_row_layout = QHBoxLayout()
        prebuilt_row_layout.setContentsMargins(0, 0, 0, 0)
        prebuilt_row_layout.addWidget(self._btn_install_prebuilt)
        prebuilt_row_layout.addSpacing(8)
        prebuilt_row_layout.addWidget(self._btn_detect_prebuilt)
        prebuilt_row_layout.addStretch()
        prebuilt_row_widget = QWidget()
        prebuilt_row_widget.setLayout(prebuilt_row_layout)
        form.addRow("", prebuilt_row_widget)
        # Refresh enable state whenever any of the four required path fields changes.
        for _le_field in (
            self._le_bkps_jar,
            self._le_bkps_sql,
            self._le_bkps_admin_tools,
            self._le_libspdm,
        ):
            _le_field.textChanged.connect(self._refresh_install_prebuilt_state)
        self._refresh_install_prebuilt_state()

        # ── LOCAL FILE OVERRIDES (TEMP WORKAROUND) ────────────────────────
        # Temporary section that lets the operator provide pre-downloaded
        # copies of assets that would otherwise be fetched from the
        # internet.  Leave any field EMPTY to use the normal download path.
        # Grep for `local_override_` to remove this feature cleanly.
        form = _new_section(
            "Local File Overrides  (temporary workaround — leave empty for online download)"
        )

        self._le_local_override_tsci_cert = _le(
            "Optional: /path/to/tsci_altera_com.pem",
            tip=(
                "TEMP WORKAROUND\n\n"
                "If set, this .pem file is copied in place of the openssl\n"
                "s_client fetch from tsci.altera.com:443.  Leave empty to\n"
                "download normally."
            ),
            attr="local_override_tsci_cert",
            fields=self._fields
        )
        form.addRow(
            "TSCI Cert (.pem):",
            _file_row(
                self._le_local_override_tsci_cert,
                self._browse_local_override_tsci_cert,
                widget=True
            ),
        )

        self._le_local_override_bouncycastle_jar = _le(
            "Optional: /path/to/bcprov-jdk18on-1.78.1.jar",
            tip=(
                "TEMP WORKAROUND\n\n"
                "If set, this JAR is copied into <bkps_dir>/libs-ext/ in\n"
                "place of the wget/curl download from Maven Central.  Leave\n"
                "empty to download normally."
            ),
            attr="local_override_bouncycastle_jar",
            fields=self._fields
        )
        form.addRow(
            "BouncyCastle JAR:",
            _file_row(
                self._le_local_override_bouncycastle_jar,
                self._browse_local_override_bouncycastle_jar,
                widget=True
            ),
        )

        self._le_local_override_gradle_zip = _le(
            "Optional: /path/to/gradle-8.0.1-bin.zip",
            tip=(
                "TEMP WORKAROUND\n\n"
                "If set, the gradle-wrapper.properties inside the BKPS repo\n"
                "is rewritten to point distributionUrl at this local ZIP\n"
                "(file:///…) before invoking gradlew.  Leave empty to let\n"
                "the wrapper download Gradle normally."
            ),
            attr="local_override_gradle_zip",
            fields=self._fields
        )
        form.addRow(
            "Gradle Distribution ZIP:",
            _file_row(
                self._le_local_override_gradle_zip,
                self._browse_local_override_gradle_zip,
                widget=True
            ),
        )

        # ── Logging ───────────────────────────────────────────────────────
        form = _new_section("Logging")
        self._combo_logging = QComboBox()
        self._combo_logging.setMinimumWidth(200)
        for level in LOGGING_TYPES:
            self._combo_logging.addItem(level)
        form.addRow("Log Level:", self._combo_logging)

        # Normalize every section's label-column width so all controls line up
        # to the same x-position across the full Config tab.
        self._align_form_label_columns()

        # Push all group boxes to the top of the scroll area.
        sections_layout.addStretch()
        scroll.setWidget(sections_widget)
        layout.addWidget(scroll)

        self.refresh_fields()
        return container

    # ------------------------------------------------------------------

    def _align_form_label_columns(self) -> None:
        """Use a shared fixed label-column width across all section forms."""
        max_label_width = 0
        for form in self._section_forms:
            for row in range(form.rowCount()):
                item = form.itemAt(row, QFormLayout.ItemRole.LabelRole)
                if item is None:
                    continue
                widget = item.widget()
                if widget is None:
                    continue
                max_label_width = max(max_label_width, widget.sizeHint().width())

        if max_label_width <= 0:
            return

        # Add a little padding so labels do not crowd the field column.
        target_width = max_label_width + 8
        for form in self._section_forms:
            form.setHorizontalSpacing(10)
            for row in range(form.rowCount()):
                item = form.itemAt(row, QFormLayout.ItemRole.LabelRole)
                if item is None:
                    continue
                widget = item.widget()
                if widget is None:
                    continue
                widget.setFixedWidth(target_width)

    # ------------------------------------------------------------------

    def refresh_fields(self) -> None:
        """Populate line-edits from the current Config object."""
        cfg = self.cfg
        for attr, le in self._fields.items():
            val = getattr(cfg, attr, None)
            le.setText(str(val) if val is not None else "")

        # Device family combo — block signals so changing the index during
        # refresh does not fire _on_device_family_changed.
        profile = getattr(cfg, "profile_name", "agilex5") or "agilex5"
        self._combo_device.blockSignals(True)
        matched = False
        for display, (pname, _, _, _) in DEVICE_FAMILIES.items():
            if pname == profile:
                idx = self._combo_device.findText(display)
                if idx >= 0:
                    self._combo_device.setCurrentIndex(idx)
                matched = True
                break
        if not matched:
            self._combo_device.setCurrentIndex(0)
        self._combo_device.blockSignals(False)

        # BKPS Signing Key Cancellation ID
        saved_bkps_signing_key_cancel_id = str(getattr(cfg, "bkps_signing_key_cancel_id", ""))
        self._le_bkps_signing_key_cancel_id.setText(saved_bkps_signing_key_cancel_id)

        # AES Storage — repopulate options for current family, then restore saved value
        self._combo_aes_ccert.blockSignals(True)
        self._combo_aes_ccert.clear()
        for key_name in aes_ccert_types_for_profile(profile).keys():
            self._combo_aes_ccert.addItem(key_name)
        saved_ccert = str(getattr(cfg, "aes_ccert_type", ""))
        idx = self._combo_aes_ccert.findText(saved_ccert)
        self._combo_aes_ccert.setCurrentIndex(max(idx, 0))
        self._combo_aes_ccert.blockSignals(False)

        # AES Cancellation ID
        saved_cancel = str(getattr(cfg, "aes_cancel_id", ""))
        self._le_aes_cancel_id.setText(saved_cancel)

        # AES ccert IV
        self._le_aes_ccert_iv.setText(str(getattr(cfg, "aes_ccert_iv", "")))
        self._on_aes_ccert_changed(saved_ccert)

        # Log level combo
        saved_log = str(getattr(cfg, "log_level", ""))
        idx = self._combo_logging.findText(saved_log)
        self._combo_logging.setCurrentIndex(idx if idx >= 0 else 0)

        # Security provider combo
        provider = getattr(cfg, "security_provider", "")
        self._combo_provider.blockSignals(True)
        idx = self._combo_provider.findText(provider)
        self._combo_provider.setCurrentIndex(idx if idx >= 0 else 0)
        self._combo_provider.blockSignals(False)
        self._refresh_provider_fields(provider)

        # Bundle ZIP
        self._le_bundle_zip.setText(str(getattr(cfg, "bundle_zip", "")))
        self._le_bundle_zip_password.setText(str(getattr(cfg, "bundle_zip_password", "")))

        # BKPS Release combo
        val = getattr(cfg, "bkps_release", "")
        idx = self._combo_release.findText(val)
        if idx >= 0:
            self._combo_release.setCurrentIndex(idx)
        elif val:
            self._combo_release.setEditText(str(val))

        build_mode = str(getattr(cfg, "bkps_build_mode", "bkp_only") or "bkp_only")
        with_programmer = bool(getattr(cfg, "include_bkp_programmer", False))
        self._radio_build_full.setChecked(build_mode == "full")
        self._radio_build_bkp_programmer.setChecked(
            build_mode != "full" and with_programmer
        )
        self._radio_build_bkp_only.setChecked(
            build_mode != "full" and not with_programmer
        )

        self._refresh_device_fields()

    def _validate_fields(self) -> tuple:
        """Return (errors, warnings) lists based on current UI field values."""
        errors = []
        warnings = []

        # Required non-empty fields
        for attr, label in [
            ("bkps_dir",         "BKPS Project Dir"),
            ("quartus_keys_dir", "Quartus Keys Dir"),
            ("cm_provisioning_dir", "CM Provisioning Dir"),
            ("db_host",          "DB Host"),
            ("db_name",          "DB Name"),
            ("db_user",          "DB User"),
            ("db_password",      "DB Password"),
            ("db_port",          "DB Port"),
            ("device_part",      "Device Part"),
        ]:
            if not self._fields[attr].text().strip():
                errors.append(f"{label} cannot be empty")

        # The project may not exist yet because Setup creates it. Require an
        # absolute path whose nearest existing parent is writable; never derive
        # it from the Automation Studio installation directory or process CWD.
        bkps_dir = self._fields["bkps_dir"].text().strip()
        if bkps_dir:
            project_path = Path(os.path.expandvars(os.path.expanduser(bkps_dir)))
            if not project_path.is_absolute():
                errors.append(
                    f"BKPS Project Dir must be an absolute path: {bkps_dir}"
                )
            else:
                existing_parent = project_path
                while not existing_parent.exists() and existing_parent.parent != existing_parent:
                    existing_parent = existing_parent.parent
                if not existing_parent.is_dir() or not os.access(existing_parent, os.W_OK):
                    errors.append(
                        f"BKPS Project Dir cannot be created or written: {bkps_dir}\n"
                        f"    Nearest existing parent: {existing_parent}"
                    )

        # Hexadecimal only fields
        for attr, label, max_size in [
            ("aes_ccert_iv",     "AES ccert IV", 32)
        ]:
            family = DEVICE_FAMILIES.get(self._combo_device.currentText())
            profile = family[0]
            ccert_type = self._combo_aes_ccert.currentText().strip()
            if not aes_ccert_requires_iv(profile, ccert_type):
                continue
            if not self._fields[attr].text().strip():
                errors.append(f"{label} cannot be empty")
            else:
                try:
                    value = self._fields[attr].text().strip()
                    if len(value) > max_size:
                        errors.append(f"{label} must be {max_size} characters or less (got {len(value)})")
                    elif not all(c.lower() in '0123456789abcdef' for c in value):
                        errors.append(f"{label} must contain only hexadecimal characters (got '{value}')")
                    else:
                        int(value, 16)
                except ValueError:
                    errors.append(f"{label} must be a hexadecimal number (got '{self._fields[attr].text().strip()}')")

        # Integer only fields
        for attr, label in [
            ("jtag_cable_num",   "JTAG cable ID"),
            ("bkps_server_port", "BKPS Server Port"),
            ("db_port",          "DB Port")
        ]:
            try:
                int(self._fields[attr].text().strip())
            except ValueError:
                errors.append(f"{label} must be a number (got '{self._fields[attr].text().strip()}')")

        # Port must be a valid number
        for attr, label in [
            ("bkps_server_port", "BKPS Server Port"),
            ("db_port",          "DB Port"),
        ]:
            port_text = self._fields[attr].text().strip()
            try:
                p = int(port_text)
                if not (1 <= p <= 65535):
                    errors.append(f"{label} must be 1–65535 (got {p})")
            except ValueError:
                errors.append(f"{label} must be a number (got '{port_text}')")

        # SIGMA devices require a bundle ZIP
        display = self._combo_device.currentText()
        entry = DEVICE_FAMILIES.get(display)
        jar_provided = bool(self._le_bkps_jar.text().strip() and self._le_bkps_sql.text().strip() and self._le_bkps_admin_tools.text().strip() and self._le_libspdm.text().strip())
        if entry and not entry[2] and not self._le_bundle_zip.text().strip() and not jar_provided:
            errors.append(
                "bundle ZIP is required for SIGMA devices (Agilex 7 / Easic N5X / Stratix 10) "
                "unless a pre-built bundle (JAR, SQL, Admin Tools, libspdm) is provided."
            )

        # Warn about unchanged default credentials without printing values.
        provider = self._combo_provider.currentText()
        secret_values = {
            attr: self._fields[attr].text()
            for attr in set(DEFAULT_SECRET_FIELDS) | {"bc_keystore_password"}
            if attr in self._fields
        }
        warnings.extend(default_secret_warnings(secret_values, provider))

        return errors, warnings

    def _apply(self) -> None:
        """Write field values back into the Config object (in memory)."""
        errors, warnings = self._validate_fields()
        if errors:
            self.log.append_error("Config NOT applied — fix the following issues first:")
            for msg in errors:
                self.log.append_warning(f"  \u2717 {msg}")
            return

        cfg = self.cfg
        for attr, le in self._fields.items():
            val = le.text().strip()
            if hasattr(cfg, attr):
                current = getattr(cfg, attr)
                if isinstance(current, int):
                    try:
                        setattr(cfg, attr, int(val))
                    except ValueError:
                        pass
                else:
                    setattr(cfg, attr, val)

        # Device family → profile_name
        display = self._combo_device.currentText()
        if display in DEVICE_FAMILIES:
            cfg.profile_name = DEVICE_FAMILIES[display][0]
        # BKPS_REPO_DIR is optional. If blank, keep the checkout beneath the
        # selected project root, independent of the Automation Studio path.
        normalize_project_paths(cfg, require_project=True)
        self._le_bkps_dir.setText(cfg.bkps_dir)
        self._le_bkps_repo_dir.setText(cfg.bkps_repo_dir)
        cfg.bkps_signing_key_cancel_id = self._le_bkps_signing_key_cancel_id.text().strip()

        # AES Storage + Cancellation ID + IV
        cfg.aes_ccert_type = self._combo_aes_ccert.currentText()
        cfg.aes_cancel_id  = self._le_aes_cancel_id.text().strip()
        cfg.aes_ccert_iv   = self._le_aes_ccert_iv.text().strip()

        # Logging
        cfg.log_level = self._combo_logging.currentText()

        # Bundle ZIP
        cfg.bundle_zip = self._le_bundle_zip.text().strip()
        cfg.bundle_zip_password = self._le_bundle_zip_password.text()

        # BKPS Release
        cfg.bkps_release = self._combo_release.currentText().strip()
        full_build = self._radio_build_full.isChecked()
        cfg.bkps_build_mode = "full" if full_build else "bkp_only"
        cfg.include_bkp_programmer = (
            full_build or self._radio_build_bkp_programmer.isChecked()
        )

        # Security provider
        cfg.security_provider = self._combo_provider.currentText()

        for msg in warnings:
            self.log.append_warning(f"  \u26a0 {msg}")
        self.log.append_success("Config applied in memory.")
        # Notify AppWindow → unlocks downstream tabs.
        self.config_applied.emit()

    # ------------------------------------------------------------------

    def _on_provider_changed(self, provider: str) -> None:
        """Slot: Security Provider combo changed — refresh visible HSM/BC rows.

        Args:
            provider: New provider string (``"bouncycastle"``, ``"luna"``,
                or ``"ncipher"``).
        """
        self._refresh_provider_fields(provider)

    def _refresh_provider_fields(self, provider: str) -> None:
        """Show BouncyCastle or HSM fields based on selected security provider."""
        is_bc = (provider == "bouncycastle")
        is_hsm = (provider in ("luna", "ncipher"))

        for widget in (self._bc_row_label, self._bc_row_widget):
            if widget:
                widget.setVisible(is_bc)
        for widget in (self._hsm_pwd_row_label, self._hsm_pwd_row_widget,
                       self._hsm_path_row_label, self._hsm_path_row_widget):
            if widget:
                widget.setVisible(is_hsm)

    def _on_device_family_changed(self, display_name: str) -> None:
        """Slot: Device Family combo changed — update profile fields and row visibility.

        Repopulates the AES Storage combo with family-specific options and
        updates the default AES Cancellation ID.  Device Part is left to
        the operator (no family default is applied).  Then calls
        :meth:`_refresh_device_fields` to show/hide SPDM / SIGMA rows.

        Args:
            display_name: Human-readable family string as shown in the combo
                (e.g. ``"Agilex 5 (SPDM)"``, ``"Agilex 7 (SIGMA)"``).
        """
        entry = DEVICE_FAMILIES.get(display_name)
        if entry:
            profile = entry[0]
            # Repopulate AES storage options for this family.
            self._combo_aes_ccert.blockSignals(True)
            self._combo_aes_ccert.clear()
            for key_name in aes_ccert_types_for_profile(profile).keys():
                self._combo_aes_ccert.addItem(key_name)
            self._combo_aes_ccert.setCurrentIndex(0)
            self._combo_aes_ccert.blockSignals(False)
            self._on_aes_ccert_changed(self._combo_aes_ccert.currentText())
        self._refresh_device_fields()

    def _refresh_device_fields(self) -> None:
        """Show/hide ZIP and repo/release fields based on selected device family."""
        display = self._combo_device.currentText()
        entry = DEVICE_FAMILIES.get(display)
        from_src = entry[2] if entry else True

        # Section headers follow the same visibility as their group
        if self._section_zip_label:
            self._section_zip_label.setVisible(not from_src)
        if self._section_source_label:
            self._section_source_label.setVisible(from_src)

        # ZIP picker + password: visible only for non-SPDM devices
        if self._zip_row_label:
            self._zip_row_label.setVisible(not from_src)
        if self._zip_row_widget:
            self._zip_row_widget.setVisible(not from_src)
        self._zip_pwd_row_label.setVisible(not from_src)
        self._le_bundle_zip_password.setVisible(not from_src)

        # Install Bundle button row: visible for SIGMA devices only.
        if getattr(self, "_install_bundle_row_label", None):
            self._install_bundle_row_label.setVisible(not from_src)
        if getattr(self, "_install_bundle_row_widget", None):
            self._install_bundle_row_widget.setVisible(not from_src)
        self._refresh_install_bundle_state()

        # Repo dir + release: visible only for SPDM (Agilex 5)
        if self._repo_row_label:
            self._repo_row_label.setVisible(from_src)
        if self._repo_row_widget:
            self._repo_row_widget.setVisible(from_src)
        if self._release_row_label:
            self._release_row_label.setVisible(from_src)
        if self._release_row_widget:
            self._release_row_widget.setVisible(from_src)
        if self._release_status_label:
            self._release_status_label.setVisible(from_src)
        for widget in (
            getattr(self, "_build_mode_row_label", None),
            getattr(self, "_build_mode_row_widget", None),
        ):
            if widget:
                widget.setVisible(from_src)

        # SoftHSM section and fields: visible only for Agilex 5
        profile = entry[0] if entry else ""
        is_agilex5 = (profile == "agilex5")
        if self._section_softhsm_label:
            self._section_softhsm_label.setVisible(is_agilex5)
        for lbl, le in getattr(self, "_softhsm_rows", []):
            lbl.setVisible(is_agilex5)
            le.setVisible(is_agilex5)

        # AES Passphrase: always visible.  Consumed by every AES QEK
        # creation path — SIGMA (bkps_keys.create_aes_key Step 1) and
        # Agilex 5 (bkps_softhsm.softhsm_create_qek_and_ccert Step 5)
        # both feed it to ``quartus_encrypt --operation=make_aes_key``
        # to produce the AES QEK used by BKPS provisioning.  JIC generation
        # does not consume this passphrase or alter bitstream protection.
        if getattr(self, "_section_aes_passphrase", None) is not None:
            self._section_aes_passphrase.setVisible(True)

    def _on_aes_ccert_changed(self, display_name: str) -> None:
        """Slot: AES ccert type combo changed.

        display_name is the ccert key name shown in the combo box
        (e.g. "EFUSE_WRAPPED_AES_KEY").  Look up its key storage in
        AES_CCERT_TYPES[profile] and show the IV field only when storage
        is OFFCHIP.
        """
        display = self._combo_device.currentText()
        family_entry = DEVICE_FAMILIES.get(display)
        profile = family_entry[0] if family_entry else ""

        show_iv = aes_ccert_requires_iv(profile, display_name)
        self._lbl_aes_ccert_iv.setVisible(show_iv)
        self._le_aes_ccert_iv.setVisible(show_iv)
        self._le_aes_ccert_iv.setEnabled(show_iv)
        if show_iv:
            self._le_aes_ccert_iv.setToolTip(
                "Initialization Vector (IV) hex; required when key storage is OFFCHIP"
            )
        else:
            self._le_aes_ccert_iv.setToolTip(
                "AES IV is only required when AES key storage is OFFCHIP"
            )


    # ── Directory browse helpers ──────────────────────────────────────

    def _browse_dir(self, title: str, target_le: QLineEdit) -> None:
        """Open a directory picker dialog and write the chosen path into *target_le*.

        Args:
            title: Dialog window title.
            target_le: Line-edit widget to receive the chosen directory path.
        """
        start = target_le.text().strip() or os.path.expanduser("~")
        path = _pick_dir(self, title, start)
        if path:
            target_le.setText(path)

    def _browse_bkps_dir(self) -> None:
        """Open a directory picker and set the independent BKPS project root."""
        self._browse_dir("Select BKPS Project Directory", self._le_bkps_dir)

    def _browse_quartus_keys_dir(self) -> None:
        """Open a directory picker and set the Quartus Keys Dir field."""
        self._browse_dir("Select Quartus Keys Directory", self._le_quartus_keys_dir)

    def _browse_cm_provisioning_dir(self) -> None:
        """Open a directory picker and set the CM Provisioning Dir field."""
        self._browse_dir("Select CM Provisioning Directory", self._le_cm_provisioning_dir)

    def _browse_bkps_repo_dir(self) -> None:
        """Open a directory picker and set the BKPS Repo Dir field."""
        self._browse_dir("Select BKPS Repo Directory", self._le_bkps_repo_dir)

    # ── Auto-fill logic ───────────────────────────────────────────────

    def _on_bkps_dir_changed(self, bkps_dir: str) -> None:
        """When BKPS Dir changes, auto-fill dependent dirs if they are still at
        their defaults (empty, placeholder, or previously derived from bkps_dir)."""
        bkps_dir = bkps_dir.strip()
        if not bkps_dir:
            return

        def _should_autofill(le: QLineEdit, default_suffix: str) -> bool:
            """Return True if the field is empty or still holds the auto-derived default."""
            current = le.text().strip()
            if not current:
                return True
            # Already points to the expected sub-directory of some bkps_dir
            return current.endswith(os.sep + default_suffix) or current.endswith("/" + default_suffix)

        if _should_autofill(self._le_quartus_keys_dir, "quartus_keys"):
            self._le_quartus_keys_dir.setText(os.path.join(bkps_dir, "quartus_keys"))
        if _should_autofill(self._le_cm_provisioning_dir, "cm_provisioning"):
            self._le_cm_provisioning_dir.setText(os.path.join(bkps_dir, "cm_provisioning"))
        if _should_autofill(self._le_bkps_repo_dir, "bkps_repo"):
            embedded = detect_embedded_bkps_repo()
            self._le_bkps_repo_dir.setText(
                embedded or os.path.join(bkps_dir, "bkps_repo")
            )

    def _browse_jar(self) -> None:
        """Open a file picker and set the BKPS JAR path field."""
        path = _pick_file(self, "Select BKPS JAR File", "JAR files (*.jar);;All files (*)")
        if path:
            self._le_bkps_jar.setText(path)

    def _browse_sql(self) -> None:
        """Open a file picker and set the BKPS SQL schema path field."""
        path = _pick_file(self, "Select BKPS SQL Schema", "SQL files (*.sql);;All files (*)")
        if path:
            self._le_bkps_sql.setText(path)

    def _browse_admin_tools_cfg(self) -> None:
        """Open a directory picker and set the Admin Tools Dir field."""
        path = _pick_dir(self, "Select Admin Tools Directory")
        if path:
            self._le_bkps_admin_tools.setText(path)

    # ── LOCAL-FILE OVERRIDES (TEMP WORKAROUND) browse handlers ─────────────
    # Each one opens a file picker and populates the corresponding local-
    # override line-edit.  Grep for `local_override_` to remove cleanly.
    def _browse_local_override_tsci_cert(self) -> None:
        path = _pick_file(
            self, "Select local TSCI certificate (.pem)",
            "PEM files (*.pem *.crt *.cer);;All files (*)",
        )
        if path:
            self._le_local_override_tsci_cert.setText(path)

    def _browse_local_override_bouncycastle_jar(self) -> None:
        path = _pick_file(
            self, "Select local BouncyCastle JAR (bcprov-jdk18on-*.jar)",
            "JAR files (*.jar);;All files (*)",
        )
        if path:
            self._le_local_override_bouncycastle_jar.setText(path)

    def _browse_local_override_gradle_zip(self) -> None:
        path = _pick_file(
            self, "Select local Gradle distribution ZIP (gradle-*-bin.zip)",
            "ZIP files (*.zip);;All files (*)",
        )
        if path:
            self._le_local_override_gradle_zip.setText(path)

    def _refresh_install_bundle_state(self) -> None:
        """Enable the 'Install Bundle' button only for SIGMA devices with a ZIP path."""
        if not getattr(self, "_btn_install_bundle", None):
            return
        display = self._combo_device.currentText()
        entry = DEVICE_FAMILIES.get(display)
        # SIGMA devices have build_from_source == False.
        is_sigma = bool(entry) and not entry[2]
        has_zip = bool(self._le_bundle_zip.text().strip())
        self._btn_install_bundle.setEnabled(is_sigma and has_zip)
        if not is_sigma:
            self._btn_install_bundle.setToolTip(
                "Only available for SIGMA device families (Agilex 7 / Easic N5X / Stratix 10)."
            )
        elif not has_zip:
            self._btn_install_bundle.setToolTip(
                "Provide a Bundle ZIP path above to enable this button."
            )
        else:
            self._btn_install_bundle.setToolTip(
                "Extract the Bundle ZIP above into the BKPS directory."
            )

    def _refresh_install_prebuilt_state(self) -> None:
        """Enable 'Install Pre-built Files' only when all four required paths are set.

        Required: BKPS JAR file, BKPS SQL schema, Admin Tools Dir, and
        libspdm Wrapper Path.  Missing entries are listed in the tooltip.
        """
        if not getattr(self, "_btn_install_prebuilt", None):
            return
        checks = [
            ("BKPS JAR File",       self._le_bkps_jar),
            ("BKPS SQL Schema",     self._le_bkps_sql),
            ("Admin Tools Dir",     self._le_bkps_admin_tools),
            ("libspdm Wrapper Path", self._le_libspdm),
        ]
        missing = [label for label, le in checks if not le.text().strip()]
        self._btn_install_prebuilt.setEnabled(not missing)
        if missing:
            self._btn_install_prebuilt.setToolTip(
                "Missing required path(s):\n  • "
                + "\n  • ".join(missing)
                + "\nAll four fields above must be set to enable this button."
            )
        else:
            self._btn_install_prebuilt.setToolTip(
                "Copy the JAR, SQL schema, admin-tools, and libspdm wrapper above\n"
                "into the BKPS directory.  Skips the source build and ZIP extraction\n"
                "steps. Works for all device profiles."
            )

    def _install_prebuilt_files(self) -> None:
        """Copy the configured pre-built artifacts into cfg.bkps_dir.

        Requires JAR, SQL, Admin Tools Dir, and libspdm Wrapper Path to all
        be set.  Reads the current paths directly from the UI so the user
        does not have to click Apply Changes first, then dispatches
        ``install_from_files`` on a background worker.
        """
        jar     = self._le_bkps_jar.text().strip()
        sql     = self._le_bkps_sql.text().strip()
        admin   = self._le_bkps_admin_tools.text().strip()
        libspdm = self._le_libspdm.text().strip()
        missing = [
            label for label, val in (
                ("BKPS JAR File",       jar),
                ("BKPS SQL Schema",     sql),
                ("Admin Tools Dir",     admin),
                ("libspdm Wrapper Path", libspdm),
            ) if not val
        ]
        if missing:
            self.log.append_error(
                "Missing required path(s) for Install Pre-built Files:\n  • "
                + "\n  • ".join(missing)
            )
            return
        # Persist current UI values into the in-memory Config so the worker
        # sees them even if Apply Changes was not clicked.
        self.cfg.bkps_jar_path = jar
        self.cfg.bkps_sql_path = sql
        self.cfg.bkps_admin_tools_dir = admin
        self.cfg.libspdm_wrapper_path = libspdm

        self.run_worker(
            install_from_files, self.cfg,
            _buttons=[self._btn_install_prebuilt],
        )

    def _install_bundle_zip(self) -> None:
        """Extract the configured bundle ZIP into cfg.bkps_dir.

        Reads the current ZIP path + password directly from the UI so the user
        does not have to click Apply Changes first, then dispatches
        ``install_bundle_zip`` on a background worker.
        """
        zip_path = self._le_bundle_zip.text().strip()
        if not zip_path:
            self.log.append_error(
                "No ZIP file selected. Set 'bundle ZIP' above first."
            )
            return
        # Persist current UI values into the in-memory Config so the worker
        # sees the password even if Apply Changes was not clicked.
        self.cfg.bundle_zip = zip_path
        self.cfg.bundle_zip_password = self._le_bundle_zip_password.text()

        self.run_worker(
            install_bundle_zip, self.cfg,
            _buttons=[self._btn_install_bundle],
        )

    def _browse_zip(self) -> None:
        """Open a file picker and set the bundle ZIP path field."""
        path = _pick_file(self, "Select bundle ZIP", "ZIP files (*.zip);;All files (*)")
        if path:
            self._le_bundle_zip.setText(path)

    def _browse_owner_root_key(self) -> None:
        """Open a file picker and set the Device Owner Root Key path field."""
        path = _pick_file(
            self, "Select Device Owner Root Key (.qky)",
            "QKY files (*.qky);;All files (*)",
        )
        if path:
            self._le_owner_root_key.setText(path)

    def _browse_owner_root_key_pem(self) -> None:
        """Open a file picker and set the Device Owner Root Key private PEM path."""
        path = _pick_file(
            self, "Select Device Owner Root Key private PEM",
            "PEM files (*.pem);;All files (*)",
        )
        if path:
            self._le_owner_root_key_pem.setText(path)

    def _browse_libspdm(self) -> None:
        """Open a platform-aware file picker and set the libspdm Wrapper Path field.

        On Windows the filter targets .dll; on Linux/macOS it targets .so / .dylib.
        """
        ext_filter = "DLL files (*.dll);;All files (*)" if sys.platform.startswith("win") \
            else "Shared libraries (*.so *.so.*);;All files (*)"
        path = _pick_file(self, "Select libspdm_wrapper Library", ext_filter)
        if path:
            self._le_libspdm.setText(path)

    def _browse_softhsm(self) -> None:
        """Open a platform-aware file picker and set the SoftHSM Library path field.

        On Windows the filter targets .dll; on macOS .dylib / .so; on Linux .so.
        """
        if sys.platform.startswith("win"):
            ext_filter = "DLL files (*.dll);;All files (*)"
        elif sys.platform == "darwin":
            ext_filter = "Shared libraries (*.dylib *.so *.so.*);;All files (*)"
        else:
            ext_filter = "Shared libraries (*.so *.so.*);;All files (*)"
        path = _pick_file(self, "Select SoftHSM Library", ext_filter)
        if path:
            self._le_softhsm_lib.setText(path)

    def _browse_softhsm_conf(self) -> None:
        """Open a file picker to select the SoftHSM configuration file."""
        path = _pick_file(
            self,
            "Select SoftHSM Configuration",
            "SoftHSM configuration (softhsm2.conf);;All files (*)",
        )
        if path:
            self._le_softhsm_conf.setText(path)
            tokens_dir = detect_softhsm_tokens_dir(path)
            if tokens_dir:
                self._le_softhsm_tokens.setText(tokens_dir)

    def _browse_softhsm_tokens(self) -> None:
        """Open a directory picker to select the SoftHSM token store."""
        self._browse_dir(
            "Select SoftHSM Token Store",
            self._le_softhsm_tokens,
        )

    def _browse_softhsm_util(self) -> None:
        """Open a file picker to select the softhsm2-util executable path."""
        if sys.platform.startswith("win"):
            ext_filter = "Executables (*.exe);;All files (*)"
        else:
            ext_filter = "All files (*)"
        path = _pick_file(self, "Select softhsm2-util Executable", ext_filter)
        if path:
            self._le_softhsm_util.setText(path)

    def _browse_pkcs11_tool(self) -> None:
        """Open a file picker to select the pkcs11-tool executable path."""
        if sys.platform.startswith("win"):
            ext_filter = "Executables (*.exe);;All files (*)"
        else:
            ext_filter = "All files (*)"
        path = _pick_file(self, "Select pkcs11-tool Executable", ext_filter)
        if path:
            self._le_pkcs11_tool.setText(path)

    def _detect_prebuilt_all(self) -> None:
        """Auto-fill JAR / SQL / Admin Tools / libspdm from ``bkps_repo_dir``.

        Search paths (relative to the BKPS Repo Directory field):

          * BKPS JAR      -- ``bkps/build/libs/*.jar``
          * SQL schema    -- ``bkps/**/*.sql`` (recursive under the
                             ``bkps`` subdir so both generated and
                             checked-in schemas match)
          * libspdm       -- repository build outputs, including
                             ``out_windows/spdm_wrapper/libspdm_wrapper.dll``
          * Admin Tools   -- ``admin-tools/`` (dir containing ``runner.py``)

        Fields that already have a value are left untouched; the button
        never overwrites a hand-picked path.  Every field is filled
        with the first matching path per glob (fastest, most predictable
        behavior — the operator can Browse for a different match if the
        first hit is wrong).
        """
        repo = self._fields.get(
            "bkps_repo_dir", self._le_bkps_jar
        ).text().strip()
        if not repo or not os.path.isdir(repo):
            self.log.append_warning(
                "Auto-Detect skipped — BKPS Repo Directory is empty or "
                "not a directory. Set 'BKPS Repo Dir' above first."
            )
            return

        lib_ext = ".dll" if sys.platform.startswith("win") else ".so"
        results: dict[str, str] = {}

        jars = sorted(glob.glob(os.path.join(
            repo, "bkps", "build", "libs", "*.jar"
        )))
        if jars:
            results["JAR"] = jars[0]

        sqls = sorted(
            glob.iglob(os.path.join(repo, "bkps", "**", "*.sql"),
                       recursive=True)
        )
        if sqls:
            results["SQL"] = sqls[0]

        libs = sorted(
            path for path in _find_libspdm_wrapper_candidates(
                os.path.join(repo, "bkps")
            )
            if path.lower().endswith(lib_ext)
        )
        if libs:
            results["libspdm"] = libs[0]

        admin_dir = os.path.join(repo, "admintools", "bkps", "bkps")
        if os.path.isfile(os.path.join(admin_dir, "runner.py")):
            results["Admin Tools"] = admin_dir

        targets = {
            "JAR":         self._le_bkps_jar,
            "SQL":         self._le_bkps_sql,
            "Admin Tools": self._le_bkps_admin_tools,
            "libspdm":     self._le_libspdm,
        }

        filled: list[str] = []
        skipped_existing: list[str] = []
        not_found: list[str] = []
        for name, edit in targets.items():
            current = edit.text().strip()
            if current:
                skipped_existing.append(name)
                continue
            path = results.get(name)
            if path:
                edit.setText(path)
                filled.append(f"{name}: {path}")
            else:
                not_found.append(name)

        if filled:
            self.log.append_success(
                "Auto-Detect filled from BKPS Repo Dir:\n  " +
                "\n  ".join(filled)
            )
        if skipped_existing:
            self.log.append_info(
                "Auto-Detect left these fields unchanged (already set): " +
                ", ".join(skipped_existing)
            )
        if not_found:
            self.log.append_warning(
                "Auto-Detect could not find: " + ", ".join(not_found) +
                ". Build the missing artefacts under bkps_repo_dir or "
                "use Browse to point at them manually."
            )

    def _detect_softhsm(self) -> None:
        """Auto-detect all SoftHSM and PKCS#11 runtime paths.

        Guards against concurrent runs — silently returns if a search is already
        in progress. Disables the unified button until the worker finishes.
        """
        if self._softhsm_worker and self._softhsm_worker.isRunning():
            return
        self._btn_detect_softhsm.setEnabled(False)
        self._btn_detect_softhsm.setText("Searching…")
        bkps_dir = self._fields.get("bkps_dir", self._le_softhsm_lib).text().strip()
        self._softhsm_worker = _DetectSofthsmWorker(
            bkps_dir=bkps_dir,
            parent=self,
        )
        self._softhsm_worker.done.connect(self._on_softhsm_detected)
        self._softhsm_worker.start()

    @Slot(dict)
    def _on_softhsm_detected(self, paths: dict[str, str]) -> None:
        """Fill all SoftHSM/PKCS#11 path fields found by the worker.

        A missing result does not clear an existing operator-selected path.

        Args:
            paths: Absolute paths keyed by library, softhsm_util, and pkcs11_tool.
        """
        self._btn_detect_softhsm.setEnabled(True)
        self._btn_detect_softhsm.setText("Auto-Detect Tools")

        targets = {
            "SoftHSM library": ("library", self._le_softhsm_lib),
            "SoftHSM configuration": ("softhsm_conf", self._le_softhsm_conf),
            "SoftHSM token store": ("softhsm_tokens", self._le_softhsm_tokens),
            "softhsm2-util": ("softhsm_util", self._le_softhsm_util),
            "pkcs11-tool": ("pkcs11_tool", self._le_pkcs11_tool),
        }
        found: list[str] = []
        missing: list[str] = []
        for label, (key, edit) in targets.items():
            path = paths.get(key, "")
            if path:
                edit.setText(path)
                found.append(f"{label}: {path}")
            else:
                missing.append(label)

        if found:
            self.log.append_success(
                "Auto-Detect Tools found:\n  " + "\n  ".join(found)
            )
        if missing:
            self.log.append_warning(
                "Auto-Detect Tools could not find: " + ", ".join(missing) + ".\n"
                "Searched PATH, the managed BKPS SoftHSM runtime, common system "
                "and OpenSC locations, BKPS Dir, and the user tools directory.\n"
                "Use the corresponding Browse button to locate missing tools manually."
            )

    def _fetch_releases(self) -> None:
        """Kick off the background worker to fetch BKPS GitHub release branches.

        Silently returns if a fetch is already in progress.  Updates the status
        label while in-flight and populates the release combo on success.
        """
        if self._release_worker and self._release_worker.isRunning():
            return
        self._btn_fetch_release.setEnabled(False)
        self._lbl_release_status.setText("Fetching releases from GitHub…")
        self._release_worker = _FetchReleasesWorker(self)
        self._release_worker.done.connect(self._on_releases_fetched)
        self._release_worker.start()

    @Slot(list)
    def _on_releases_fetched(self, releases: list) -> None:
        """Slot: populate the release combo with branches from _FetchReleasesWorker.

        Preserves the user's current selection / typed text across the repopulation.

        Args:
            releases: List of release branch name strings (may be empty on failure).
        """
        self._btn_fetch_release.setEnabled(True)
        current = self._combo_release.currentText()
        self._combo_release.blockSignals(True)
        self._combo_release.clear()
        if releases:
            self._combo_release.addItems(releases)
            self._lbl_release_status.setText(f"{len(releases)} branch option(s) loaded from GitHub.")
        else:
            self._lbl_release_status.setText("Could not reach GitHub — enter release manually.")
        # Restore whatever the user had already typed / selected
        idx = self._combo_release.findText(current)
        if idx >= 0:
            self._combo_release.setCurrentIndex(idx)
        elif current:
            self._combo_release.setCurrentText(current)
        self._combo_release.blockSignals(False)

    def _load(self) -> None:
        """Load a .conf file from disk and refresh all form fields.

        Opens a file-picker dialog; if the user selects a file it is parsed by
        ConfigStore and every QLineEdit is updated via :meth:`refresh_fields`.
        """
        path = _pick_file(
            self, "Load Config",
            "Config files (*.conf *.cfg);;All files (*)",
        )
        if path:
            try:
                self._store.load(path)
                self.refresh_fields()
                self.log.append_success(f"Config loaded: {path}")
                self.project_loaded.emit()
            except Exception as e:
                self.log.append_error(f"Failed to load: {e}")

    def _save(self) -> None:
        """Validate fields, apply changes in memory, then save the config to disk.

        Aborts with error messages in the log panel if validation fails.  Calls
        :meth:`_apply` implicitly so the in-memory ConfigStore is always current
        before the file is written.

        Note:
            A default filename (bkps_demo_config.conf) is injected so native
            GTK/KDE save dialogs don't grey-out the Save button.
        """
        errors, _ = self._validate_fields()
        if errors:
            self.log.append_error("Cannot save — fix the following issues first:")
            for msg in errors:
                self.log.append_warning(f"  \u2717 {msg}")
            return
        self._apply()  # ensure in-memory values are up to date

        # Ensure a non-empty default filename so the native dialog Save button
        # is not grayed out (GTK/KDE gray it when the filename field is blank).
        default_path = self.cfg.config_file or ""
        if not os.path.basename(default_path):
            default_path = os.path.join(
                os.path.dirname(default_path) or os.path.expanduser("~"),
                "bkps_demo_config.conf"
            )

        path = _pick_save_file(
            self, "Save Config",
            "Config files (*.conf);;All files (*)",
            default_path,
        )
        if path:
            try:
                self._store.save(path)
                self.log.append_success(f"Config saved: {path}")
            except Exception as e:
                self.log.append_error(f"Failed to save: {e}")

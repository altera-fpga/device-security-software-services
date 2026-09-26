#!/usr/bin/env python3
"""
utility_widgets.py - Manual-operation QGroupBox factories.

The pipeline flows moved into ``pipeline_widgets``; every non-pipeline
button (Reload From Template, View Slots, Get Configuration, Add Device
Owner Root Key, ...) lives here so ``tab_server_utilities`` /
``tab_aes_utilities`` / ``tab_configuration_utilities`` can compose them
without dragging the pipeline UI along.

Each ``build_*_utilities(host)`` factory returns a single ``QWidget``
containing every relevant QGroupBox, wires the button signals to the
host tab, and stores button references on ``host._util_buttons`` so the
Config-applied gate can flip them en-masse.
"""

from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLineEdit, QLabel,
    QComboBox, QMessageBox, QInputDialog, QPushButton,
)
from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices

from utils.bkps_utils import _btn, _le, _hrow, _pick_file

# ── backend imports ------------------------------------------------------
from bkps_users import list_users, delete_user, create_user, unset_user_role
from bkps_runner import run_runner_tool as _runner
from bkps_printer import print_header, print_success, print_info
from bkps_keys import register_bkps_signing_key
from bkps_key_mgmt import (
    list_signing_keys,
    create_sealing_key, list_sealing_keys, rotate_sealing_key,
    create_import_key, get_import_pubkey, delete_import_key,
    rotate_context_key,
)
from bkps_configure import (
    USER_ROLES, get_configuration, delete_configuration,
    configure_bkps_service, update_configuration_file, read_config_id,
)
from bkps_server_setup import create_bkps_config, import_aes_key_to_bc_keystore
from bkps_certs import delete_trusted_cert, import_root_cert
from bkps_database import (
    check_sql_connection, reset_database_password, show_db_stats,
    setup_database, reset_database,
)
from bkps_softhsm import (
    softhsm_show_slots, softhsm_delete_token, softhsm_list_objects,
    softhsm_import_aes_key, softhsm_delete_key,
)


# ── Helper --------------------------------------------------------------
def _register_util(host, btn):
    """Track a utility button.

    Utility buttons are always enabled — they're intentionally
    independent of the pipeline gating and the Config-applied gate so
    the operator can trigger any manual action at any time.
    """
    host._util_buttons.append(btn)
    btn.setEnabled(True)
    return btn


# ── Server utilities -----------------------------------------------------
def build_server_utilities(host) -> QWidget:
    """Service Configuration + BKPS Administration groups."""
    container = QWidget()
    v = QVBoxLayout(container)
    v.setContentsMargins(4, 4, 4, 4); v.setSpacing(6)

    # ── Service Configuration ────────────────────────────────────
    svc = QGroupBox("Service Configuration")
    sv = QVBoxLayout(svc); sv.setContentsMargins(8, 8, 8, 8)

    host._btn_configure_svc = _register_util(host, _btn(
        "Configure BKPS Service", primary=True, tip=(
            "Write runner-config.json and application-{profile}.yml from the "
            "current settings."
        )))
    host._combo_svc_client_cert = QComboBox()
    host._combo_svc_client_cert.setToolTip(
        "Client identity written to runner-config.json.  Only roles with an "
        "existing cert + private key are listed."
    )
    _orig_show = host._combo_svc_client_cert.showPopup
    def _show():
        _refresh_client_cert_combo(host)
        _orig_show()
    host._combo_svc_client_cert.showPopup = _show

    sv.addLayout(_hrow(QLabel("Client cert:"),
                       host._combo_svc_client_cert,
                       host._btn_configure_svc))
    host._btn_configure_svc.clicked.connect(lambda: _configure_svc(host))
    _refresh_client_cert_combo(host)
    v.addWidget(svc)

    # ── BKPS Administration ─────────────────────────────────────
    admin = QGroupBox("BKPS Administration")
    ao = QVBoxLayout(admin); ao.setContentsMargins(8, 8, 8, 8); ao.setSpacing(6)
    ao.addWidget(_build_users(host))
    ao.addWidget(_build_keymgmt(host))
    ao.addWidget(_build_cfg_mgmt(host))
    ao.addWidget(_build_certs(host))
    ao.addWidget(_build_db(host))
    v.addWidget(admin)
    v.addStretch()
    return container


def _refresh_client_cert_combo(host):
    cfg = host.cfg
    combo = host._combo_svc_client_cert
    prev = combo.currentData() if combo.count() else None
    prev_role = prev.get("role", "") if isinstance(prev, dict) else ""
    combo.blockSignals(True)
    combo.clear()
    candidates = []
    dirs = {
        "super_admin": (os.path.join(cfg.bkps_dir, "keys"), cfg.quartus_keys_dir),
        "admin":       (cfg.quartus_keys_dir, os.path.join(cfg.bkps_dir, "keys")),
        "programmer":  (cfg.quartus_keys_dir, os.path.join(cfg.bkps_dir, "keys")),
    }
    for role, search in dirs.items():
        for d in search:
            if not d or not os.path.isdir(d):
                continue
            cert = os.path.join(d, f"{role}_bkps_signed.crt")
            key  = os.path.join(d, f"{role}_private.pem")
            if os.path.isfile(cert) and os.path.isfile(key):
                candidates.append({"role": role, "cert": cert, "key": key,
                                   "label": f"{role} — {os.path.basename(d)}/"})
                break
    if not candidates:
        combo.addItem("(no client certs on disk)", None)
        combo.setEnabled(False)
    else:
        combo.setEnabled(True)
        for c in candidates:
            combo.addItem(c["label"], c)
        for i in range(combo.count()):
            d = combo.itemData(i)
            if isinstance(d, dict) and d.get("role") == prev_role:
                combo.setCurrentIndex(i); break
    combo.blockSignals(False)


def _configure_svc(host):
    _refresh_client_cert_combo(host)
    cert_over = host._combo_svc_client_cert.currentData() or {}
    cert_path = cert_over.get("cert", "")
    key_path  = cert_over.get("key", "")
    role      = cert_over.get("role", "auto")

    def _both(cfg, cert=cert_path, key=key_path, role=role):
        create_bkps_config(cfg)
        print(f"[client-cert] using {role} identity  cert={cert or '(auto)'}  key={key or '(auto)'}")
        configure_bkps_service(cfg, cert_override=cert, key_override=key)

    host.run_worker(_both, host.cfg, _buttons=[host._btn_configure_svc])


def _build_users(host) -> QGroupBox:
    box = QGroupBox("Users"); layout = QVBoxLayout(box); layout.setContentsMargins(8, 8, 8, 8)

    host._btn_list_users = _register_util(host, _btn(
        "List Users", tip="Retrieve and display all registered BKPS users"))
    layout.addLayout(_hrow(host._btn_list_users))

    row = QHBoxLayout()
    row.addWidget(QLabel("User ID:"))
    host._del_uid = _le("User ID", tip="Numeric ID of the user to delete.")
    row.addWidget(host._del_uid)
    host._btn_delete_user = _register_util(host, _btn(
        "Delete User", danger=True, tip="Permanently delete the user."))
    row.addWidget(host._btn_delete_user); row.addStretch(); layout.addLayout(row)

    r2 = QHBoxLayout(); r2.addWidget(QLabel("Role:"))
    host._combo_role = QComboBox(); host._combo_role.setMinimumWidth(200)
    for r in USER_ROLES: host._combo_role.addItem(r)
    r2.addWidget(host._combo_role)
    host._btn_create_user = _register_util(host, _btn(
        "Create User", tip="Create + assign the specified role."))
    r2.addWidget(host._btn_create_user); r2.addStretch(); layout.addLayout(r2)

    r3 = QHBoxLayout(); r3.addWidget(QLabel("User ID:"))
    host._unset_role_uid = _le("User ID", tip="ID of the user whose role you want to revoke.")
    r3.addWidget(host._unset_role_uid); r3.addWidget(QLabel("Role:"))
    host._unset_combo_role = QComboBox(); host._unset_combo_role.setMinimumWidth(200)
    for r in USER_ROLES: host._unset_combo_role.addItem(r)
    r3.addWidget(host._unset_combo_role)
    host._btn_unset_role = _register_util(host, _btn(
        "Unset Role", tip="Revoke the specified role."))
    r3.addWidget(host._btn_unset_role); r3.addStretch(); layout.addLayout(r3)

    host._btn_list_users.clicked.connect(
        lambda: host.run_worker(list_users, host.cfg, _buttons=[host._btn_list_users]))

    def _do_delete_user():
        uid = host._del_uid.text().strip()
        if not uid: host.log.append_warning("Enter a user ID first."); return
        host.run_worker(delete_user, host.cfg, uid, _buttons=[host._btn_delete_user])
    host._btn_delete_user.clicked.connect(_do_delete_user)

    def _do_create_user():
        role = host._combo_role.currentText().strip()
        if not role: host.log.append_warning("Enter User Role."); return
        host.run_worker(create_user, host.cfg, role, _buttons=[host._btn_create_user])
    host._btn_create_user.clicked.connect(_do_create_user)

    def _do_unset_role():
        uid = host._unset_role_uid.text().strip()
        role = host._unset_combo_role.currentText().strip()
        if not uid or not role: host.log.append_warning("Enter both User ID and Role."); return
        host.run_worker(unset_user_role, host.cfg, uid, role, _buttons=[host._btn_unset_role])
    host._btn_unset_role.clicked.connect(_do_unset_role)
    return box


def _build_keymgmt(host) -> QGroupBox:
    box = QGroupBox("Key Management"); km = QVBoxLayout(box); km.setContentsMargins(8, 8, 8, 8)

    # Owner root key
    own = QGroupBox("Device Owner Root Key"); ol = QVBoxLayout(own)
    host._btn_add_owner_root_key = _register_util(host, _btn(
        "Add Device Owner Root Key",
        tip="Runs: runner.py root-signing-key add --input <file>"))
    ol.addLayout(_hrow(host._btn_add_owner_root_key)); km.addWidget(own)

    def _do_add_owner():
        p = host.cfg.owner_root_key_path or os.path.join(host.cfg.quartus_keys_dir, "root0.qky")
        if not os.path.isfile(p):
            host.log.append_error(f"Owner Root .qky not found: {p}")
            return
        def _do(cfg, path):
            print_header("Add Device Owner Root Key")
            _runner(cfg, "root-signing-key", "add", "--input", path)
            print_success(f"root-signing-key add completed for: {path}")
        host.run_worker(_do, host.cfg, p, _buttons=[host._btn_add_owner_root_key])
    host._btn_add_owner_root_key.clicked.connect(_do_add_owner)

    # Signing keys
    sk = QGroupBox("Signing Keys"); skl = QVBoxLayout(sk)
    host._btn_create_auth_keys  = _register_util(host, _btn("Create Authentication Keys",
        tip="Register the BKPS signing key with the server via runner.py."))
    host._btn_list_sign_keys    = _register_util(host, _btn("List Signing Keys"))
    skl.addLayout(_hrow(host._btn_create_auth_keys, host._btn_list_sign_keys))
    km.addWidget(sk)

    def _do_ak():
        def _do(cfg):
            print_header("Create Authentication Keys")
            register_bkps_signing_key(cfg)
            print_info("Signing-key sequence complete.")
        host.run_worker(_do, host.cfg, _buttons=[host._btn_create_auth_keys])
    host._btn_create_auth_keys.clicked.connect(_do_ak)
    host._btn_list_sign_keys.clicked.connect(
        lambda: host.run_worker(list_signing_keys, host.cfg, _buttons=[host._btn_list_sign_keys]))

    # Sealing keys
    se = QGroupBox("Sealing Key"); sel = QVBoxLayout(se)
    host._btn_create_seal = _register_util(host, _btn("Create Sealing Key"))
    host._btn_list_seal   = _register_util(host, _btn("List Sealing Keys"))
    host._btn_rotate_seal = _register_util(host, _btn("Rotate Sealing Key"))
    sel.addLayout(_hrow(host._btn_create_seal, host._btn_list_seal, host._btn_rotate_seal))
    km.addWidget(se)
    host._btn_create_seal.clicked.connect(lambda: host.run_worker(create_sealing_key, host.cfg, _buttons=[host._btn_create_seal]))
    host._btn_list_seal.clicked.connect(lambda: host.run_worker(list_sealing_keys, host.cfg, _buttons=[host._btn_list_seal]))
    host._btn_rotate_seal.clicked.connect(lambda: host.run_worker(rotate_sealing_key, host.cfg, _buttons=[host._btn_rotate_seal]))

    # Import key
    ik = QGroupBox("Import Key"); ikl = QVBoxLayout(ik)
    host._btn_create_imp = _register_util(host, _btn("Create Import Key"))
    host._btn_get_pub    = _register_util(host, _btn("Get Import Public Key"))
    host._btn_delete_imp = _register_util(host, _btn("Delete Import Key", danger=True))
    ikl.addLayout(_hrow(host._btn_create_imp, host._btn_get_pub, host._btn_delete_imp))
    km.addWidget(ik)
    host._btn_create_imp.clicked.connect(lambda: host.run_worker(create_import_key, host.cfg, _buttons=[host._btn_create_imp]))
    host._btn_get_pub.clicked.connect(lambda: host.run_worker(get_import_pubkey, host.cfg, _buttons=[host._btn_get_pub]))
    host._btn_delete_imp.clicked.connect(lambda: host.run_worker(delete_import_key, host.cfg, _buttons=[host._btn_delete_imp]))

    # Context key
    cx = QGroupBox("Context Key"); cxl = QVBoxLayout(cx)
    host._btn_rotate_ctx = _register_util(host, _btn("Rotate Context Key"))
    cxl.addLayout(_hrow(host._btn_rotate_ctx))
    km.addWidget(cx)
    host._btn_rotate_ctx.clicked.connect(lambda: host.run_worker(rotate_context_key, host.cfg, _buttons=[host._btn_rotate_ctx]))
    return box


def _build_cfg_mgmt(host) -> QGroupBox:
    box = QGroupBox("Configuration Management")
    l = QVBoxLayout(box); l.setContentsMargins(8, 8, 8, 8)
    r = QHBoxLayout(); r.addWidget(QLabel("Configuration ID:"))
    host._cfg_mgmt_id = _le("Numeric configuration ID",
                            tip="Numeric configuration ID to fetch or delete.")
    host._cfg_mgmt_id.setFixedWidth(180); r.addWidget(host._cfg_mgmt_id)
    host._btn_cfg_get = _register_util(host, _btn("Get Configuration"))
    host._btn_cfg_delete = _register_util(host, _btn("Delete Configuration", danger=True))
    r.addWidget(host._btn_cfg_get); r.addWidget(host._btn_cfg_delete); r.addStretch()
    l.addLayout(r)

    def _do_get():
        cid = host._cfg_mgmt_id.text().strip()
        if not cid.isdigit(): host.log.append_warning("Configuration ID must be numeric."); return
        host.run_worker(get_configuration, host.cfg, cid, _buttons=[host._btn_cfg_get])
    host._btn_cfg_get.clicked.connect(_do_get)

    def _do_del():
        cid = host._cfg_mgmt_id.text().strip()
        if not cid.isdigit(): host.log.append_warning("Configuration ID must be numeric."); return
        if QMessageBox.question(host, "Confirm Delete",
                f"Permanently delete configuration {cid}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                ) != QMessageBox.StandardButton.Yes:
            return
        host.run_worker(delete_configuration, host.cfg, cid, _buttons=[host._btn_cfg_delete])
    host._btn_cfg_delete.clicked.connect(_do_del)
    return box


def _build_certs(host) -> QGroupBox:
    box = QGroupBox("Trusted Certificates")
    l = QVBoxLayout(box); l.setContentsMargins(8, 8, 8, 8)
    r = QHBoxLayout(); r.addWidget(QLabel("Cert ID:"))
    host._del_cert_id = _le("Numeric certificate ID",
                            tip="ID of a certificate in the BKPS trusted store to remove.")
    r.addWidget(host._del_cert_id)
    host._btn_delete_cert = _register_util(host, _btn("Delete Cert"))
    r.addWidget(host._btn_delete_cert); r.addStretch(); l.addLayout(r)

    host._btn_import_root = _register_util(host, _btn("Import Root Certificate"))
    l.addLayout(_hrow(host._btn_import_root))

    def _do_del_cert():
        cid = host._del_cert_id.text().strip()
        if not cid: host.log.append_warning("Enter a cert ID first."); return
        host.run_worker(delete_trusted_cert, host.cfg, cid, _buttons=[host._btn_delete_cert])
    host._btn_delete_cert.clicked.connect(_do_del_cert)

    def _do_import_root():
        f = _pick_file(host, "Select Root Certificate", "Certificate files (*.crt *.pem *.cer);;All files (*)")
        if not f: return
        host.run_worker(import_root_cert, host.cfg, f, _buttons=[host._btn_import_root])
    host._btn_import_root.clicked.connect(_do_import_root)
    return box


def _build_db(host) -> QGroupBox:
    box = QGroupBox("Database"); l = QVBoxLayout(box); l.setContentsMargins(8, 8, 8, 8)
    host._btn_db_check = _register_util(host, _btn("Check Connection"))
    host._btn_db_stats = _register_util(host, _btn("Show Stats"))
    host._btn_db_setup = _register_util(host, _btn("Setup Database"))
    host._btn_db_pwd   = _register_util(host, _btn("Reset Password"))
    host._btn_db_reset = _register_util(host, _btn("Reset Database", danger=True))
    l.addLayout(_hrow(host._btn_db_check, host._btn_db_stats))
    l.addLayout(_hrow(host._btn_db_setup, host._btn_db_pwd, host._btn_db_reset))
    host._btn_db_check.clicked.connect(lambda: host.run_worker(check_sql_connection, host.cfg, _buttons=[host._btn_db_check]))
    host._btn_db_pwd.clicked.connect(lambda: host.run_worker(reset_database_password, host.cfg, _buttons=[host._btn_db_pwd]))
    host._btn_db_stats.clicked.connect(lambda: host.run_worker(show_db_stats, host.cfg, _buttons=[host._btn_db_stats]))
    host._btn_db_setup.clicked.connect(lambda: host.run_worker(setup_database, host.cfg, _buttons=[host._btn_db_setup]))
    host._btn_db_reset.clicked.connect(lambda: host.run_worker(reset_database, host.cfg, _buttons=[host._btn_db_reset]))
    return box


# ── AES utilities --------------------------------------------------------
def build_aes_utilities(host) -> QWidget:
    """SoftHSM / BouncyCastle manual buttons (Agilex 5).  SIGMA hides these.

    Layout:
      Row 1 (HBox): [AES key hex line-edit] [Import AES Key button]
      Below (vertical stack): every other utility button, one per row.
    """
    container = QWidget()
    v = QVBoxLayout(container); v.setContentsMargins(4, 4, 4, 4); v.setSpacing(6)

    host._aes_util_box = QGroupBox("SoftHSM / BouncyCastle Utilities")
    box_lay = QVBoxLayout(host._aes_util_box)
    box_lay.setContentsMargins(8, 8, 8, 8); box_lay.setSpacing(6)

    # Row 1 — AES key hex + Import AES Key button (hex on the LEFT).
    host._aes_util_hex = _le(
        "64-char hex AES-256 key",
        tip="64-char hex AES-256 key used by 'Import AES Key' and 'Import Key to BC JKS'.",
    )
    host._aes_util_hex.setMaxLength(64)
    host._btn_import_key = _register_util(host, _btn("Import AES Key"))
    hex_row = QHBoxLayout()
    hex_row.addWidget(QLabel("AES Key Hex:"))
    hex_row.addWidget(host._aes_util_hex, stretch=1)
    hex_row.addWidget(host._btn_import_key)
    box_lay.addLayout(hex_row)

    # Row 2 — every other utility button in a single horizontal row,
    # each button at its natural size (no stretching).
    host._btn_view_slots   = _register_util(host, _btn("View Slots"))
    host._btn_delete_token = _register_util(host, _btn("Delete Token", danger=True))
    host._btn_view_keys    = _register_util(host, _btn("View Keys"))
    host._btn_delete_key   = _register_util(host, _btn("Delete AES Key", danger=True))
    host._btn_import_bc    = _register_util(host, _btn("Import Key to BC JKS"))
    box_lay.addLayout(_hrow(
        host._btn_view_slots, host._btn_delete_token,
        host._btn_view_keys, host._btn_delete_key,
        host._btn_import_bc,
    ))

    v.addWidget(host._aes_util_box)
    v.addStretch()

    # ── Signals ──────────────────────────────────────────────────
    host._btn_view_slots.clicked.connect(
        lambda: host.run_worker(softhsm_show_slots, host.cfg, _buttons=[host._btn_view_slots]))
    host._btn_view_keys.clicked.connect(
        lambda: host.run_worker(softhsm_list_objects, host.cfg, _buttons=[host._btn_view_keys]))

    def _do_del_tok():
        if QMessageBox.warning(host, "Delete Token",
            f"Delete token '{host.cfg.softhsm_token_label}' and ALL keys inside?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
            ) != QMessageBox.StandardButton.Yes: return
        host.run_worker(softhsm_delete_token, host.cfg, _buttons=[host._btn_delete_token])
    host._btn_delete_token.clicked.connect(_do_del_tok)

    def _do_del_key():
        if QMessageBox.warning(host, "Delete AES Key",
            f"Delete key '{host.cfg.softhsm_key_label}' from token?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
            ) != QMessageBox.StandardButton.Yes: return
        host.run_worker(softhsm_delete_key, host.cfg, _buttons=[host._btn_delete_key])
    host._btn_delete_key.clicked.connect(_do_del_key)

    def _do_imp_key():
        h = host._aes_util_hex.text().strip()
        if not h: host.log.append_warning("Enter the 64-char AES key hex above."); return
        host.run_worker(softhsm_import_aes_key, host.cfg, h, _buttons=[host._btn_import_key])
    host._btn_import_key.clicked.connect(_do_imp_key)

    def _do_bc():
        h = host._aes_util_hex.text().strip()
        if not h: host.log.append_warning("Enter the 64-char AES key hex above."); return
        host.run_worker(import_aes_key_to_bc_keystore, host.cfg, h, _buttons=[host._btn_import_bc])
    host._btn_import_bc.clicked.connect(_do_bc)
    return container


def refresh_aes_utility_visibility(host):
    """SIGMA hides the SoftHSM/BouncyCastle utility groupbox entirely."""
    profile = getattr(host.cfg, "profile_name", "") or ""
    show = (profile == "agilex5")
    box = getattr(host, "_aes_util_box", None)
    if box is not None:
        box.setVisible(show)


# ── Configuration utilities ---------------------------------------------
def build_configuration_utilities(host) -> QWidget:
    """Duplicate configuration table + Reload / Update / View buttons.

    Hosts its OWN copy of the AES-configuration table + settings widget
    via :func:`pipeline_widgets.build_configuration_settings_box`, so
    the operator can inspect / edit the JSON directly on the utilities
    tab without switching to the BKP Config tab.  Both tables read /
    write the same working file (``bkps_configs/aes_config_<family>.json``)
    so edits on either tab converge — call
    ``host._config_reload_family()`` on tab show to pick up cross-tab
    changes.
    """
    from pipeline_widgets import build_configuration_settings_box

    container = QWidget()
    v = QVBoxLayout(container); v.setContentsMargins(4, 4, 4, 4); v.setSpacing(6)

    # Independent duplicate of the BKP-Config table so the operator can
    # view / edit the JSON in-place on the utilities tab.  Every
    # ``_config_*`` helper below (reload / save / load / working-file
    # path / template path) is populated on ``host`` by this call.
    # ``include_config_id=False`` — the Config ID field only drives the
    # ``generate_bkp_options`` pipeline step, which lives on the BKP
    # Config tab; the utilities tab has no use for it.
    v.addWidget(build_configuration_settings_box(host, include_config_id=False))

    box = QGroupBox("Configuration Manual Operations")
    l = QVBoxLayout(box); l.setContentsMargins(8, 8, 8, 8)

    host._btn_reload_template = _register_util(host, _btn(
        "Reload From Template",
        tip="Overwrite the working file from the family template and reload the table above."))
    host._btn_update_config   = _register_util(host, _btn(
        "Update Configuration",
        tip="Save the table above and PUT it to an existing BKPS configuration by ID."))
    host._btn_view_bkp_opts   = _register_util(host, _btn(
        "View bkp_options.txt", tip="Open bkp_options.txt in the default text editor"))
    l.addLayout(_hrow(host._btn_reload_template, host._btn_update_config, host._btn_view_bkp_opts))
    v.addWidget(box); v.addStretch()

    def _do_reload():
        template = host._config_template_path()
        if not template or not os.path.isfile(template):
            host.log.append_error("Sample template not found for this family.")
            return
        working = host._config_refresh_working_file(force=True)
        if not working:
            return
        host.log.append_success(
            f"Reloaded {os.path.basename(working)} from the complete "
            f"{os.path.basename(template)} reference flow."
        )
        host._config_load_table_from_file(working)
    host._btn_reload_template.clicked.connect(_do_reload)

    def _do_update():
        default_id = read_config_id(host.cfg) or ""
        cid, ok = QInputDialog.getText(host, "Update Configuration",
            "Enter the BKPS configuration ID to update:",
            QLineEdit.EchoMode.Normal, default_id)
        if not ok or not cid.strip().isdigit():
            host.log.append_warning("Update aborted — a numeric ID is required.")
            return
        working = host._config_working_file_path()
        if not host._config_save_table_to_file(working):
            return
        host.run_worker(update_configuration_file, host.cfg, cid.strip(), working,
                        _buttons=[host._btn_update_config])
    host._btn_update_config.clicked.connect(_do_update)

    def _do_view():
        path = os.path.join(host.cfg.cm_provisioning_dir, "bkp_options.txt")
        if not os.path.isfile(path):
            host.log.append_warning(f"bkp_options.txt not found: {path}")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))
    host._btn_view_bkp_opts.clicked.connect(_do_view)
    return container

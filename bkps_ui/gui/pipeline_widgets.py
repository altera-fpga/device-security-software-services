#!/usr/bin/env python3
"""
pipeline_widgets.py - QGroupBox factories, one per pipeline flow.

Each ``build_<flow>_pipeline_box(host)`` returns a ``QGroupBox`` and
populates::

    host._pipe_buttons[group_id][step_id] = QPushButton
    host._step_dispatch[(group_id, step_id)] = callable(cfg, *args) -> Any

The first button in each flow chain-runs from itself; all others run only
that single step (chain resumes on later successes automatically because
the mixin auto-enables the next button).

The factories intentionally reuse only *existing* backend functions —
no new server-side logic is introduced here.
"""

from __future__ import annotations

import os
import glob

from PySide6.QtCore import Qt, QObject, QThread, QCoreApplication, Signal, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QGroupBox, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QSpinBox, QPushButton, QMessageBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QWidget, QCheckBox, QPlainTextEdit,
    QScrollArea, QFrame, QSizePolicy,
)

from pipeline import PIPELINE_STEPS
from utils.bkps_utils import _btn, _le, _hrow, _pick_file, _pick_dir, _file_row
from utils.pipeline_spec import visible_pipeline_labels
from utils.ui_helpers import apply_server_env_vars, resolve_jic_output_dir


def read_server_launch_settings(host) -> tuple[str, str]:
    """Return ``(extra_jvm_flags, env_text)`` from the Setup pipeline Settings.

    Both the Database bootstrap Start Server step and the Server Control Panel
    Start button reuse these widgets — they are not duplicated on other tabs.
    """
    flags_edit = getattr(host, "_server_extra_flags_edit", None)
    env_edit = getattr(host, "_server_env_vars_edit", None)
    extra = flags_edit.text().strip() if flags_edit is not None else ""
    env_text = env_edit.toPlainText() if env_edit is not None else ""
    return extra, env_text


def start_bkps_with_launch_settings(
    cfg,
    extra_flags: str = "",
    env_text: str = "",
):
    """Apply shared pipeline launch settings, then start the BKPS server."""
    apply_server_env_vars(env_text)
    return start_bkps_server(cfg, extra_flags)
# ── GUI-thread invoker for widget reads/writes from worker threads ────────
#
# The programming-pipeline dispatchers (``_pipe_generate_jic`` &c) run on
# a ``BkpsWorker`` background thread but need to read (and occasionally
# write) values on ``QLineEdit`` / ``QComboBox`` / ``QSpinBox`` widgets
# that live on the GUI thread.  Qt widgets are strictly single-threaded:
# a worker-thread ``.text()`` races with GUI-thread paint / stylesheet
# / relayout work, and when the widget's private ``d`` pointer is being
# reallocated at the same instant the worker dereferences it — that's
# the ``libQt6Gui.so.6 +0x10`` NULL-d-ptr SIGSEGV we kept seeing (most
# reliably in manual mode after a failed step, when every button in the
# flow is being re-styled + re-enabled and the traceback repaint is in
# flight).
#
# ``run_on_gui`` marshals a zero-arg callable onto the GUI thread via a
# queued signal and blocks the worker until it finishes, returning its
# result.  We use a signal-based invoker (rather than
# ``QMetaObject.invokeMethod`` + ``Q_ARG``) because PySide6's Python
# binding for ``Q_ARG`` with return values is awkward — a plain
# ``Signal(object)`` + ``QueuedConnection`` gives us the same guarantee
# (the slot always runs on the invoker's thread affinity, which we
# force to the main thread) with less ceremony.
import threading


class _GuiInvoker(QObject):
    """Singleton that runs an arbitrary callable on the GUI thread.

    Emit ``_invoke(fn)`` from any thread; ``_run`` fires on the GUI thread
    because the invoker's thread affinity is the main thread (see
    ``_get_invoker``) and the connection is queued.
    """

    _invoke = Signal(object)

    def __init__(self) -> None:
        super().__init__()
        self._invoke.connect(self._run, Qt.ConnectionType.QueuedConnection)

    @Slot(object)
    def _run(self, fn) -> None:
        try:
            fn()
        except Exception:  # pragma: no cover - defensive
            # A getter that raises shouldn't take the whole invoker down;
            # ``run_on_gui`` re-raises the captured exception on the
            # worker side so the traceback still surfaces normally.
            pass


_gui_invoker: _GuiInvoker | None = None


def _get_invoker() -> _GuiInvoker:
    """Lazy-init the module-level GUI invoker on the main thread."""
    global _gui_invoker
    if _gui_invoker is None:
        _gui_invoker = _GuiInvoker()
        app = QCoreApplication.instance()
        if app is not None:
            _gui_invoker.moveToThread(app.thread())
    return _gui_invoker


def run_on_gui(getter):
    """Run ``getter()`` on the GUI thread and return its result.

    Safe to call from either the GUI thread (in which case ``getter`` is
    invoked inline) or a worker thread (in which case we queue it onto
    the invoker's main-thread affinity and block until it finishes).

    Exceptions raised inside ``getter`` propagate to the caller so the
    normal traceback path is unchanged.
    """
    app = QCoreApplication.instance()
    if app is None or QThread.currentThread() is app.thread():
        return getter()
    box: dict = {}
    ev = threading.Event()

    def _wrap():
        try:
            box["value"] = getter()
        except BaseException as exc:  # noqa: BLE001 — re-raised below
            box["error"] = exc
        finally:
            ev.set()

    _get_invoker()._invoke.emit(_wrap)
    ev.wait()
    if "error" in box:
        raise box["error"]
    return box.get("value")

# Backend imports for each pipeline flow.
from bkps_deps import ensure_dependencies
from bkps_build import build_all, install_bundle_zip, install_from_files
from bkps_server_setup import (
    setup_bouncycastle, setup_luna_config, setup_ncipher_config,
    create_ssl_certificates, create_bkps_keystore, create_bkps_config,
)
from bkps_server import start_bkps_server, stop_bkps_server
from bkps_database import check_sql_connection, reset_database
from bkps_autosetup import (
    extract_token_from_logs, _wait_for_token, _wait_for_authenticated_ready,
)
from bkps_configure import (
    create_super_admin, configure_bkps_keys,
    upload_aes_configuration_file, create_bkp_config, read_config_id,
    materialize_reference_configuration,
)
from bkps_keys import create_authentication_keys, create_aes_key
from bkps_users import create_user
from bkps_softhsm import (
    softhsm_init_token, softhsm_generate_aes_key, softhsm_import_aes_key,
    softhsm_create_qek_and_ccert
)
from bkps_device import (
    generate_jic, program_helper_image, program_jic, provision_rkh_virtual,
    bkp_prefetch, bkp_puf_activate, bkp_set_authority, run_bkp,
    extract_and_save_corim_url_from_provision_helper, read_saved_corim_url,
)
from bkps_config import (
    DEVICE_FAMILIES, PUF_TYPES, AES_CCERT_TYPES, aes_ccert_lookup,
    normalize_project_paths,
)
from bkps_printer import print_warning, print_info


# ── Filesystem cleanup helpers ───────────────────────────────────────────
def _rm_paths(paths) -> None:
    """Delete every path in ``paths``; missing paths are ignored.

    Handles both files and directories, and logs one line per deletion so
    the operator can see exactly which stale artifacts were removed
    before a step re-created them.
    """
    import glob as _glob
    import shutil as _shutil
    seen: set[str] = set()
    for pat in paths:
        if not pat:
            continue
        # Expand globs so callers can pass patterns like "libspdm*.so".
        matches = _glob.glob(pat) if any(ch in pat for ch in "*?[") else [pat]
        for p in matches:
            if p in seen or not os.path.exists(p):
                continue
            seen.add(p)
            try:
                if os.path.isdir(p) and not os.path.islink(p):
                    _shutil.rmtree(p, ignore_errors=True)
                else:
                    os.remove(p)
                print(f"  cleaned: {p}")
            except OSError as exc:
                print(f"  clean skipped ({exc}): {p}")


def _clean_install_bundle_outputs(cfg) -> None:
    """Wipe every artifact the ``repo_setup`` step will re-create.

    Covers JARs (root + build/libs), BKPS SQL scripts, libspdm/SPDM
    wrapper libs (all platforms), the admin-tools drop, any Liquibase
    changelog directory, and stale bundle-extraction leftovers under
    ``build/``.
    """
    bd = getattr(cfg, "bkps_dir", "") or ""
    if not bd:
        return
    print("Cleaning previous Installation bundle artifacts...")
    _rm_paths([
        os.path.join(bd, "*.jar"),
        os.path.join(bd, "build"),
        os.path.join(bd, "bkps*.sql"),
        os.path.join(bd, "libspdm*.dll"),
        os.path.join(bd, "libspdm*.so"),
        os.path.join(bd, "libspdm*.dylib"),
        os.path.join(bd, "spdm_wrapper*.dll"),
        os.path.join(bd, "spdm_wrapper*.so"),
        os.path.join(bd, "spdm_wrapper*.dylib"),
        os.path.join(bd, "libspdm_wrapper*"),
        os.path.join(bd, "liquibase"),
        os.path.join(bd, "bkps"),  # admin-tools subdir
        os.path.join(bd, "admintools"),
    ])


def _clean_security_provider_outputs(cfg) -> None:
    """Wipe every application-*.yml + provider-specific artefact."""
    bd = getattr(cfg, "bkps_dir", "") or ""
    if not bd:
        return
    print("Cleaning previous Security Provider artifacts...")
    _rm_paths([
        os.path.join(bd, "config", "application-bouncycastle.yml"),
        os.path.join(bd, "config", "application-bc.yml"),
        os.path.join(bd, "config", "application-luna.yml"),
        os.path.join(bd, "config", "application-ncipher.yml"),
        os.path.join(bd, "libs-ext", "bcprov-jdk18on-*.jar"),
        os.path.join(bd, "libs-ext", "LunaProvider*.jar"),
        os.path.join(bd, "keys", "bc-keystore-bkps-static.jks"),
    ])


def _clean_ssl_certs_outputs(cfg) -> None:
    """Wipe every file ``create_ssl_certificates`` produces.

    That is: the BKPS SSL cert dir, the super-admin cert + key, the
    Intel TSCI cert dir, every keystore/truststore variant under
    ``keys/``, and the two OpenSSL config stubs under ``config/``.
    """
    bd = getattr(cfg, "bkps_dir", "") or ""
    if not bd:
        return
    print("Cleaning previous SSL Certificate artifacts...")
    keys_dir = os.path.join(bd, "keys")
    _rm_paths([
        os.path.join(bd, "keys", "bkps_ssl_cert"),
        os.path.join(bd, "keys", "tsci_cert"),
        os.path.join(bd, "keys", "super_admin_cert.crt"),
        os.path.join(bd, "keys", "super_admin_private.pem"),
        os.path.join(keys_dir, "*.jks"),
        os.path.join(keys_dir, "*.p12"),
        os.path.join(keys_dir, "*.pfx"),
        os.path.join(keys_dir, "*.bcfks"),
        os.path.join(keys_dir, "*.truststore"),
        os.path.join(bd, "config", "openssl.cnf"),
        os.path.join(bd, "config", "superadmin_openssl.cnf"),
    ])


def _clean_bkps_keystore_outputs(cfg) -> None:
    """Wipe every top-level keystore / truststore under ``cfg.bkps_dir/keys``.

    IMPORTANT: this must NOT touch anything inside
    ``keys/bkps_ssl_cert/`` because ``bkps_ssl.p12`` there is the INPUT
    that ``create_bkps_keystore`` imports from — wiping it would leave
    keytool with nothing to read.  Only the top-level ``*.p12`` / etc.
    files (which this step is about to re-create) are removed.
    """
    bd = getattr(cfg, "bkps_dir", "") or ""
    if not bd:
        return
    print("Cleaning previous BKPS Keystore / Truststore artifacts...")
    keys_dir = os.path.join(bd, "keys")
    _rm_paths([
        os.path.join(keys_dir, "*.jks"),
        os.path.join(keys_dir, "*.p12"),
        os.path.join(keys_dir, "*.pfx"),
        os.path.join(keys_dir, "*.bcfks"),
        os.path.join(keys_dir, "*.truststore"),
    ])


def _clean_bkps_config_outputs(cfg) -> None:
    """Wipe every application-*.yml that could shadow a fresh Spring config.

    We remove BOTH the profile-specific file the step re-creates AND
    every other ``application-*.yml`` under ``config/`` so a stale
    profile can't accidentally take over on the next server start.
    """
    bd = getattr(cfg, "bkps_dir", "") or ""
    if not bd:
        return
    print("Cleaning previous BKPS Config artifacts...")
    _rm_paths([
        os.path.join(bd, "config", "application-*.yml"),
        os.path.join(bd, "config", "application-*.yaml"),
    ])


def _clean_installation_all_outputs(cfg) -> None:
    """Full-slate wipe: everything the whole Installation pipeline creates.

    Invoked at the start of ``repo_setup`` so re-running the chain
    always begins from a deterministic empty state, regardless of what
    a previous partial run may have left behind.
    """
    print("Full Installation cleanup — removing artifacts from every step...")
    _clean_install_bundle_outputs(cfg)
    _clean_security_provider_outputs(cfg)
    _clean_ssl_certs_outputs(cfg)
    _clean_bkps_keystore_outputs(cfg)
    _clean_bkps_config_outputs(cfg)


# ── helpers ---------------------------------------------------------------
def _step_arrow(parent=None) -> QLabel:
    """Return a small chevron used between pipeline step buttons."""
    lbl = QLabel("▶", parent)
    lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    f = lbl.font()
    f.setBold(True); f.setPointSizeF(f.pointSizeF() + 3)
    lbl.setFont(f)
    lbl.setStyleSheet("color:#f5c26b; padding:0 4px;")
    lbl.setFixedWidth(20)
    return lbl


def make_flow_link(text: str) -> QWidget:
    """A large arrow + caption widget used *between* two pipeline boxes.

    Renders as a chunky orange downward chevron with a short label so
    the operator sees the flows as a single continuous guided path
    rather than two independent groups sitting on top of each other.
    """
    w = QWidget()
    v = QVBoxLayout(w)
    v.setContentsMargins(0, 4, 0, 4); v.setSpacing(0)
    arrow = QLabel("▼")
    arrow.setAlignment(Qt.AlignmentFlag.AlignCenter)
    f = arrow.font(); f.setBold(True); f.setPointSizeF(f.pointSizeF() + 10)
    arrow.setFont(f)
    arrow.setStyleSheet("color:#f5c26b;")
    v.addWidget(arrow)
    cap = QLabel(text)
    cap.setAlignment(Qt.AlignmentFlag.AlignCenter)
    cap.setStyleSheet("color:#f5c26b; font-size:9pt; font-weight:bold;")
    v.addWidget(cap)
    return w


def _add_row_with_arrows(layout, buttons: list, host=None, group: str = "") -> None:
    """Add ``buttons`` to ``layout`` (a QVBoxLayout) with ▶ separators.

    The button row is wrapped in a horizontal ``QScrollArea`` so long
    flows (e.g. programming in non-INTERNAL mode) stay usable instead of
    clipping off the window edge.

    When ``host`` + ``group`` are supplied the leading arrow of each
    button is registered on ``host._pipe_arrows[group][sid]`` so
    downstream visibility refreshers (see
    :func:`_refresh_step_arrows`) can hide the arrow whenever its
    trailing button is hidden.  The first button in a flow never has a
    leading arrow.
    """
    row_widget = QWidget()
    row = QHBoxLayout(row_widget)
    row.setContentsMargins(0, 2, 0, 2)
    row.setSpacing(4)
    arrows_by_sid: dict = {}
    steps = PIPELINE_STEPS.get(group, []) if group else []
    for i, btn in enumerate(buttons):
        if i > 0:
            arrow = _step_arrow()
            row.addWidget(arrow)
            if steps and i < len(steps):
                arrows_by_sid[steps[i][0]] = arrow
        row.addWidget(btn)
    # No trailing stretch — content width drives the scrollbar.

    scroll = QScrollArea()
    scroll.setWidget(row_widget)
    scroll.setWidgetResizable(False)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    scroll.setSizePolicy(
        QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
    )
    # Leave room for the horizontal scrollbar when it appears.
    hint_h = max(row_widget.sizeHint().height(), 36)
    scroll.setFixedHeight(hint_h + 18)
    layout.addWidget(scroll)

    if host is not None and group:
        if not hasattr(host, "_pipe_arrows"):
            host._pipe_arrows: dict = {}
        host._pipe_arrows[group] = arrows_by_sid
        if not hasattr(host, "_pipe_step_scrolls"):
            host._pipe_step_scrolls: dict = {}
        host._pipe_step_scrolls[group] = scroll
        host._pipe_step_scrolls[f"{group}__inner"] = row_widget


def _refresh_step_arrows(host, group: str) -> None:
    """Hide the ▶ arrow that leads into any hidden step in *group*.

    Walks the buttons in declared order; an arrow is visible iff BOTH
    the button it leads into AND at least one earlier button in the
    flow are visible.  Guarantees no dangling arrow appears at the
    start of the row when the leading step(s) are hidden.
    """
    arrows = getattr(host, "_pipe_arrows", {}).get(group, {})
    btns   = host._pipe_buttons.get(group, {})
    steps  = [sid for sid, _ in PIPELINE_STEPS.get(group, [])]
    any_prev_visible = False
    for sid in steps:
        btn = btns.get(sid)
        visible = bool(btn is not None and btn.isVisible())
        arrow = arrows.get(sid)
        if arrow is not None:
            arrow.setVisible(visible and any_prev_visible)
        if visible:
            any_prev_visible = True

    # Recompute scroll content size after show/hide so the horizontal
    # scrollbar only appears when the visible steps overflow.
    scrolls = getattr(host, "_pipe_step_scrolls", {})
    inner = scrolls.get(f"{group}__inner")
    scroll = scrolls.get(group)
    if inner is not None:
        inner.adjustSize()
        if scroll is not None:
            hint_h = max(inner.sizeHint().height(), 36)
            scroll.setFixedHeight(hint_h + 18)


_MANUAL_MODE_SETTINGS_KEY = "pipeline/manual_mode/{group}"


def _load_persisted_manual_mode(group: str) -> bool:
    """Return the last-saved manual-mode flag for *group* (False if none)."""
    try:
        from PySide6.QtCore import QSettings
        s = QSettings("Intel", "BKPS-Studio")
        return s.value(_MANUAL_MODE_SETTINGS_KEY.format(group=group),
                       False, type=bool)
    except Exception:
        return False


def _persist_manual_mode(group: str, on: bool) -> None:
    """Persist *on* as the manual-mode flag for *group* across app restarts."""
    try:
        from PySide6.QtCore import QSettings
        s = QSettings("Intel", "BKPS-Studio")
        s.setValue(_MANUAL_MODE_SETTINGS_KEY.format(group=group), bool(on))
    except Exception:
        pass


def _manual_mode_row(host, group: str, tip: str | None = None) -> QHBoxLayout:
    """Return a row containing the per-flow "manual mode" checkbox.

    When checked, ``host._run_pipeline_chain_from(group, ...)`` runs
    exactly one step (the clicked one) instead of auto-chaining the
    remaining steps of the flow.  The checkbox is stashed on
    ``host._manual_checkboxes[group]`` so ``refresh_pipeline_gating``
    can lock it while a worker is in flight.

    The state is persisted to :class:`QSettings` under
    ``pipeline/manual_mode/<group>`` so a user's choice sticks across
    app restarts — the flag only ever flips when the user toggles the
    checkbox again.
    """
    if not hasattr(host, "_manual_checkboxes"):
        host._manual_checkboxes = {}

    # Prefer the persisted value; fall back to whatever the host may
    # already have in memory (e.g. programmatic set_manual before build).
    persisted = _load_persisted_manual_mode(group)
    if hasattr(host, "_manual_mode"):
        host._manual_mode[group] = persisted

    cb = QCheckBox("Manual mode")
    # Force a visible white border around the tick box so the checkbox
    # stands out against the dark tab background.  Checked state fills
    # with a warm accent that matches the guided-flow arrows.
    cb.setStyleSheet(
        "QCheckBox { color:#ddd; spacing:6px; }"
        "QCheckBox:disabled { color:#ddd; }"
        "QCheckBox::indicator {"
        "  width:14px; height:14px;"
        "  border:1px solid #ffffff;"
        "  border-radius:2px;"
        "  background:#1e1e1e;"
        "}"
        "QCheckBox::indicator:hover { border:1px solid #f5c26b; }"
        "QCheckBox::indicator:checked {"
        "  background:#f5c26b;"
        "  border:1px solid #ffffff;"
        "}"
        # Preserve the CHECKED look while disabled (running-lockout):
        # same white border, same warm fill — just slightly dimmer so
        # the operator can still tell the box is temporarily read-only.
        "QCheckBox::indicator:disabled {"
        "  border:1px solid #ffffff;"
        "  background:#1e1e1e;"
        "}"
        "QCheckBox::indicator:checked:disabled {"
        "  border:1px solid #ffffff;"
        "  background:#c39447;"
        "}"
    )
    cb.setChecked(persisted)
    cb.setToolTip(tip or (
        "Off (default): clicking any step chains the rest of THIS "
        "pipeline automatically.\n"
        "On: clicking a step runs ONLY that step; the next button "
        "stays enabled after success but you have to click it "
        "yourself.\n\n"
        "This setting is remembered across app restarts — it only "
        "changes when you toggle this checkbox again."
    ))

    def _on_toggle(checked, g=group):
        host.set_manual(g, checked)
        _persist_manual_mode(g, checked)

    cb.toggled.connect(_on_toggle)
    host._manual_checkboxes[group] = cb
    row = QHBoxLayout()
    row.addWidget(cb)
    row.addStretch()
    return row


def _settings_box(title: str = "Settings") -> tuple[QGroupBox, QVBoxLayout]:
    """Return a compact QGroupBox intended for per-pipeline settings.

    Rendered slightly dimmer than the outer pipeline box so the pipeline
    buttons remain the visual focus.
    """
    gb = QGroupBox(title)
    gb.setStyleSheet(
        "QGroupBox { font-weight: bold; color:#f0c060; }"
        "QGroupBox::title { subcontrol-origin: margin; left: 8px; padding:0 4px; }"
    )
    lay = QVBoxLayout(gb)
    lay.setContentsMargins(8, 8, 8, 8)
    lay.setSpacing(4)
    return gb, lay


def _register_buttons(host, group: str, specs: list[tuple[str, str]]):
    """Create pipeline buttons, wire clicks, and return them in order.

    Args:
        host:  The combined-tab PipelineHost instance owning ``_pipe_buttons``.
        group: PIPELINE_STEPS group id (``"installation"`` etc.).
        specs: ``[(step_id, tooltip), ...]`` in the intended left-to-right
               visual order (must be a subset of the group's PIPELINE_STEPS).

    Returns:
        Dict mapping ``step_id`` → ``QPushButton``.
    """
    label_by_sid = dict(PIPELINE_STEPS[group])
    buttons: dict[str, QPushButton] = {}
    host._pipe_buttons.setdefault(group, {})
    for sid, tip in specs:
        btn = _btn(label_by_sid[sid], tip=tip)
        btn.setEnabled(False)  # gating mixin flips this appropriately
        # Every pipeline button chain-runs from itself.  For the first
        # button this starts the whole flow; for a later button this
        # lets the operator retry from a red / failed step and resume
        # the chain automatically on success.
        btn.clicked.connect(
            lambda _c=False, g=group, s=sid: host._run_pipeline_chain_from(g, s)
        )
        host._pipe_buttons[group][sid] = btn
        buttons[sid] = btn
    return buttons


def _renumber_visible_pipeline_buttons(
    host,
    group: str,
    visible_step_ids: set[str] | None = None,
) -> None:
    """Give visible buttons consecutive numbers without changing step IDs.

    Some device/PUF configurations hide optional programming steps.  The
    persistent pipeline order and state keys remain unchanged, but operators
    should not see gaps such as 1, 2, 3, 4, 5, 9, 10.
    """
    buttons = host._pipe_buttons.get(group, {})
    visible_step_ids = visible_step_ids or {
        sid for sid, _ in PIPELINE_STEPS[group]
    }
    for sid, label in visible_pipeline_labels(group, visible_step_ids):
        button = buttons.get(sid)
        if button is None:
            continue
        button.setText(label)


def _dispatch_dependency_setup(cfg) -> None:
    """Validate/install machine dependencies without touching project files."""
    if not ensure_dependencies(cfg):
        raise RuntimeError("Dependency setup failed — see log.")


def _dispatch_bkps_repo_setup(cfg) -> None:
    """Install or build BKPS repository artifacts in the selected project."""
    # Validate the operator-selected project before cleanup or repository work.
    # This prevents an empty checkout path from reaching ``git clone`` and
    # keeps project output independent of Studio's path.
    try:
        project_dir, repo_dir = normalize_project_paths(
            cfg, require_project=True
        )
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    print_info(f"BKPS project directory: {project_dir}")
    if getattr(cfg, "build_from_source", False):
        print_info(f"BKPS source checkout: {repo_dir}")

    # Full-slate wipe begins here, after dependencies have passed. It clears
    # artifacts that this step and the remaining Installation steps recreate.
    _clean_installation_all_outputs(cfg)

    jar     = getattr(cfg, "bkps_jar_path",        "") or ""
    sql     = getattr(cfg, "bkps_sql_path",        "") or ""
    libspdm = getattr(cfg, "libspdm_wrapper_path", "") or ""
    admin   = getattr(cfg, "bkps_admin_tools_dir", "") or ""
    is_agilex5 = (getattr(cfg, "profile_name", "") == "agilex5")

    # Report one line per pre-built artifact so the operator can see exactly
    # which source is going to feed the repository setup step.
    provided = {
        "BKPS JAR":         jar,
        "BKPS SQL script":  sql,
        "libspdm wrapper":  libspdm,
        "BKPS admin-tools": admin,
    }
    any_provided = any(bool(v) for v in provided.values())
    if any_provided:
        print("Pre-built artifacts detected on the Config tab:")
        for label, path in provided.items():
            mark = "\u2713" if path else "\u2717"
            print(f"  {mark} {label}: {path or '(not set)'}")
    else:
        print("No pre-built artifacts provided on the Config tab — "
              "falling back to build-from-source / bundle-ZIP.")

    # Detect an existing installation at the destination for clear logging.
    dest_jars = (glob.glob(os.path.join(cfg.bkps_dir, "*.jar"))
                 + glob.glob(os.path.join(cfg.bkps_dir, "build", "libs", "*.jar")))
    if dest_jars:
        print(f"Existing bundle already installed at {cfg.bkps_dir}: "
              f"{[os.path.basename(p) for p in dest_jars]}")

    if jar and sql and libspdm and admin:
        print("Installing user-provided pre-built artifacts "
              "(install_from_files)...")
        install_from_files(cfg)
    elif is_agilex5 and cfg.build_from_source:
        print("No complete pre-built set — Agilex 5 build-from-source enabled.")
        build_all(cfg)
    elif not is_agilex5:
        print("No complete pre-built set — extracting configured bundle ZIP.")
        install_bundle_zip(cfg)
    else:
        raise RuntimeError(
            "Cannot install bundle for Agilex 5: no pre-built JAR/SQL/"
            "admin-tools/libspdm set on Config, and 'Build BKPS from source' "
            "is disabled."
        )

    # Verify that the destination received a JAR before declaring success.
    final_jars = (glob.glob(os.path.join(cfg.bkps_dir, "*.jar"))
                  + glob.glob(os.path.join(cfg.bkps_dir, "build", "libs", "*.jar")))
    if not final_jars:
        raise RuntimeError(
            f"BKPS Repo Setup completed but no JAR was found at {cfg.bkps_dir} — "
            "check the log above and retry."
        )
    print(f"Bundle installed at destination: "
          f"{[os.path.basename(p) for p in final_jars]}")


# ── Installation pipeline --------------------------------------------------
def build_installation_pipeline_box(host) -> QGroupBox:
    box = QGroupBox("Installation Pipeline")
    layout = QVBoxLayout(box)
    layout.setContentsMargins(8, 8, 8, 8)
    layout.setSpacing(4)

    def _dispatch_security_provider(cfg):
        provider = getattr(cfg, "security_provider", "") or ""
        if provider == "luna":
            setup_luna_config(cfg)
        elif provider == "ncipher":
            setup_ncipher_config(cfg)
        else:
            setup_bouncycastle(cfg)

    # NOTE: no per-step cleanup here — the full-slate wipe runs once at
    # the start of ``_dispatch_bkps_repo_setup``.
    # Individual re-runs of a later step will therefore build on top of
    # whatever is already on disk, which is what the operator asked for.
    host._step_dispatch[("installation", "dependency_setup")]  = _dispatch_dependency_setup
    host._step_dispatch[("installation", "repo_setup")]        = _dispatch_bkps_repo_setup
    host._step_dispatch[("installation", "security_provider")] = _dispatch_security_provider
    host._step_dispatch[("installation", "ssl_certs")]         = create_ssl_certificates
    host._step_dispatch[("installation", "bkps_keystore")]     = create_bkps_keystore
    host._step_dispatch[("installation", "bkps_config")]       = create_bkps_config

    specs = [
        ("dependency_setup",  "Checks required machine tools and Python packages, installs "
                              "supported missing dependencies, then verifies them again. "
                              "Does not clean or modify BKPS project artifacts."),
        ("repo_setup",        "Cleans generated BKPS installation artifacts, then installs "
                              "pre-built files, builds the configured Agilex 5 repository, "
                              "or extracts the configured bundle ZIP."),
        ("security_provider", "Runs the setup_* helper for the selected Security Provider "
                              "(BouncyCastle / Luna / nCipher) from the Config tab."),
        ("ssl_certs",         "Runs bkps_server_setup.create_ssl_certificates."),
        ("bkps_keystore",     "Runs bkps_server_setup.create_bkps_keystore."),
        ("bkps_config",       "Runs bkps_server_setup.create_bkps_config."),
    ]
    btns = _register_buttons(host, "installation", specs)
    layout.addLayout(_manual_mode_row(host, "installation"))
    _add_row_with_arrows(layout, [btns[sid] for sid, _ in specs],
                         host=host, group="installation")
    return box


# ── Server pipeline --------------------------------------------------------
def build_server_pipeline_box(host) -> QGroupBox:
    box = QGroupBox("Database + BKP Service Initialization")
    layout = QVBoxLayout(box)
    layout.setContentsMargins(8, 8, 8, 8)
    layout.setSpacing(4)

    # ── Settings ────────────────────────────────────────────────────
    sbox, slay = _settings_box("Settings")

    # Extra JVM flags — used only by Start Server.
    flags_row = QHBoxLayout()
    flags_row.addWidget(QLabel("Extra JVM Flags:"))
    host._server_extra_flags_edit = _le(
        "Optional extra flags appended to java command",
        tip="Extra command-line flags appended verbatim to the java command "
            "used by Start Server here and by Server Control Panel → Start Server "
            "(e.g. -Xmx4g). Not duplicated on other tabs.",
    )
    flags_row.addWidget(host._server_extra_flags_edit, stretch=1)
    slay.addLayout(flags_row)

    # Extra environment variables — exported into the process env just
    # before Start Server spawns the JVM.  Format: one ``KEY=VALUE`` per
    # line.  Blank lines and lines starting with ``#`` are ignored.  The
    # spawned java process inherits these via os.environ; nothing is
    # persisted outside the running app.
    env_label_row = QHBoxLayout()
    env_label_row.addWidget(QLabel("Extra Env Vars (KEY=VALUE per line):"))
    env_label_row.addStretch()
    slay.addLayout(env_label_row)
    host._server_env_vars_edit = QPlainTextEdit()
    host._server_env_vars_edit.setPlaceholderText(
        "# One KEY=VALUE per line, e.g.\n"
        "# JAVA_HOME=/opt/jdk-21\n"
        "# BKPS_DEBUG=1"
    )
    host._server_env_vars_edit.setToolTip(
        "Environment variables exported into the process env immediately "
        "before Start Server launches the JVM (Setup pipeline and Server "
        "Control Panel share these settings). Format: KEY=VALUE, one per "
        "line. Lines starting with '#' are treated as comments and ignored. "
        "Not persisted across app restarts."
    )
    # Keep the field compact — 4 lines is enough for the common case
    # without eating vertical space from the step-button row below.
    fm = host._server_env_vars_edit.fontMetrics()
    host._server_env_vars_edit.setFixedHeight(fm.lineSpacing() * 4 + 18)
    slay.addWidget(host._server_env_vars_edit)

    layout.addWidget(sbox)

    def _pipe_db_reset(cfg):
        print_info("Preparing database bootstrap: stopping BKPS server if running...")
        stop_bkps_server(cfg)

        # reset_database globs ``bkps*.sql`` inside cfg.bkps_dir and imports
        # the FIRST match (alphabetical), which is why a stale ``bkps-.sql``
        # would win over the operator's override.  When an override is set
        # on the Config tab we (1) purge every existing bkps*.sql in
        # cfg.bkps_dir and (2) stage ONLY the override there, so
        # reset_database has no choice but to import it.
        import glob as _glob
        import shutil
        bd = getattr(cfg, "bkps_dir", "") or ""
        override = getattr(cfg, "bkps_sql_path", "") or ""

        if override and os.path.isfile(override) and bd:
            os.makedirs(bd, exist_ok=True)
            override_basename = os.path.basename(override)
            for existing in _glob.glob(os.path.join(bd, "bkps*.sql")):
                # Skip if the override IS this file already.
                try:
                    if os.path.samefile(existing, override):
                        continue
                except OSError:
                    pass
                if os.path.basename(existing) == override_basename:
                    continue
                try:
                    os.remove(existing)
                    print(f"Removed stale SQL: {os.path.basename(existing)}")
                except OSError as exc:
                    print(f"Could not remove {existing}: {exc}")
            dest = os.path.join(bd, override_basename)
            try:
                same = os.path.exists(dest) and os.path.samefile(override, dest)
            except OSError:
                same = False
            if not same:
                shutil.copy2(override, dest)
                print(f"Staged operator-overridden SQL for reset: "
                      f"{override_basename}")
        reset_database(cfg)

    def _pipe_start_server(cfg):
        # Apply operator-supplied env-var overrides and JVM flags from the
        # Settings box above, then start. Server Control Panel Start Server
        # reuses the same widgets via read_server_launch_settings().
        extra, env_text = read_server_launch_settings(host)
        if start_bkps_with_launch_settings(cfg, extra, env_text) is False:
            return False

    def _pipe_super_admin(cfg):
        print_info("Starting BKPS server for initial service bootstrap...")
        if _pipe_start_server(cfg) is False:
            raise RuntimeError(
                "BKPS server failed to start during database bootstrap."
            )
        token = extract_token_from_logs(cfg)
        if not token:
            token = _wait_for_token(cfg, timeout=120, log_start_pos=0)
        if not token:
            raise RuntimeError(
                "Could not extract the initial user access token from bkps.log."
            )
        create_super_admin(cfg, token)
        if not _wait_for_authenticated_ready(cfg):
            raise RuntimeError(
                "Super admin created but authenticated REST APIs did not "
                "become ready in time — retry this step."
            )

    def _pipe_bkps_keys(cfg):
        configure_bkps_keys(cfg)
        print_info(
            "BKP configuration completed..."
        )
        try:
            marker = os.path.join(cfg.bkps_dir, ".bkps_setup_complete")
            with open(marker, "w") as f:
                f.write("1")
        except OSError:
            pass

    host._step_dispatch[("server", "db_reset")]     = _pipe_db_reset
    host._step_dispatch[("server", "super_admin")]  = _pipe_super_admin
    host._step_dispatch[("server", "auth_keys")]    = create_authentication_keys
    host._step_dispatch[("server", "bkps_keys")]    = _pipe_bkps_keys

    specs = [
        ("db_reset",     "Stops any running BKPS process internally, then initializes "
                         "a new database or resets an existing one by "
                         "running bkps_database.reset_database. Uses PostgreSQL's "
                         "administrator credentials for role/database creation, "
                         "then imports the configured BKPS SQL schema as the BKPS "
                         "application user."),
        ("super_admin",  "Starts BKPS internally with the settings above, waits for the "
                         "one-time token in the log, creates the super admin, "
                         "then blocks until the authenticated REST APIs are stable."),
        ("auth_keys",    "Runs bkps_keys.create_authentication_keys."),
        ("bkps_keys",    "Runs bkps_configure.configure_bkps_keys and writes the "
                         "setup completion marker."),
    ]
    btns = _register_buttons(host, "server", specs)
    layout.addLayout(_manual_mode_row(host, "server"))
    _add_row_with_arrows(layout, [btns[sid] for sid, _ in specs],
                         host=host, group="server")
    return box


# ── AES pipeline -----------------------------------------------------------
def build_aes_pipeline_box(host) -> QGroupBox:
    box = QGroupBox("AES Compact Certificate Pipeline")
    layout = QVBoxLayout(box)
    layout.setContentsMargins(8, 8, 8, 8)
    layout.setSpacing(4)

    # ── Settings ────────────────────────────────────────────────────
    sbox, slay = _settings_box("Settings")
    host._aes_hex_edit = _le(
        "Leave blank for a fresh random key, or enter 64 hex chars",
        tip="Optional 64-char hex AES-256 key.  Used by 'Generate AES Key' "
            "(imports the key into SoftHSM when set) and by 'Create QEK + "
            "ccert + Sign' (SoftHSM ccert wrap).",
    )
    host._aes_hex_edit.setMaxLength(64)
    host._aes_hex_edit.setFixedWidth(520)
    hex_row = QHBoxLayout()
    hex_row.addWidget(QLabel("Customized AES Key Hex (optional):"))
    hex_row.addWidget(host._aes_hex_edit)
    hex_row.addStretch()
    slay.addLayout(hex_row)
    layout.addWidget(sbox)

    def _is_agilex5():
        return (getattr(host.cfg, "profile_name", "") == "agilex5")

    def _pipe_init_token(cfg):
        if not _is_agilex5():
            return True
        return softhsm_init_token(cfg)

    def _pipe_create_key(cfg):
        if not _is_agilex5():
            return True
        aes_hex = host._aes_hex_edit.text().strip()
        if aes_hex:
            if len(aes_hex) != 64:
                raise ValueError("Customized AES key hex must be exactly 64 characters.")
            return softhsm_import_aes_key(cfg, aes_hex)
        return softhsm_generate_aes_key(cfg)

    def _pipe_create_qek(cfg):
        aes_hex = host._aes_hex_edit.text().strip()
        if _is_agilex5():
            result = softhsm_create_qek_and_ccert(cfg, aes_hex)
        else:
            result = create_aes_key(cfg)
        try:
            if _is_agilex5():
                url = extract_and_save_corim_url_from_provision_helper(cfg)
                print_info(f"Configuration corimUrl will be auto-filled: {url}")
        except Exception as exc:
            print_warning(f"CoRIM URL auto-extract failed (corimUrl not updated): {exc}")
        sig = getattr(host, "aes_hex_updated", None)
        if sig is not None:
            try:
                sig.emit()
            except Exception:
                pass
        return result

    host._step_dispatch[("aes", "init_token")]       = _pipe_init_token
    host._step_dispatch[("aes", "create_key")]       = _pipe_create_key
    host._step_dispatch[("aes", "create_qek_ccert")] = _pipe_create_qek

    specs = [
        ("init_token",       "Initialise a SoftHSM token (Agilex 5).  On SIGMA this step "
                             "is a no-op that auto-succeeds."),
        ("create_key",       "Generate/import an AES key in SoftHSM (Agilex 5).  On SIGMA "
                             "this step is a no-op that auto-succeeds."),
        ("create_qek_ccert", "Build QEK, wrap in ccert, sign → signed_aes_efuse.ccert.  "
                             "On SIGMA this runs bkps_keys.create_aes_key end-to-end."),
    ]
    btns = _register_buttons(host, "aes", specs)
    layout.addLayout(_manual_mode_row(host, "aes"))
    _add_row_with_arrows(layout, [btns[sid] for sid, _ in specs],
                         host=host, group="aes")
    return box


# ── Configuration pipeline -------------------------------------------------
_FAMILY_TEMPLATE = {
    "agilex5":   "sample_AgilexB.json",
    "agilex":   "sample_Agilex.json",
    "easic_n5x": "sample_EasicN5X.json",
    "stratix10": "sample_S10.json",
}

_IMPORT_MODES = ["ENCRYPTED", "PLAINTEXT"]
_BOOL_CHOICES = ["True", "False"]

# Allowed pufType values, filtered by device family.  EFUSE is universal;
# INTEL / INTEL_USER are Agilex 5 only; IID / IIDUSER are Agilex 7 only.
def _puf_type_options(profile: str) -> list[str]:
    prof = (profile or "").strip().lower()
    if prof == "agilex5":
        return ["EFUSE", "INTEL", "INTEL_USER"]
    if prof == "agilex":
        return ["EFUSE", "IID", "IIDUSER"]
    if prof == "easic_n5x":
        return ["EFUSE"]
    if prof == "stratix10":
        return ["EFUSE", "IID", "IIDUSER"]
    return ["EFUSE"]


def _read_hex_file(path: str) -> str:
    """Return the trimmed **lowercase** hex string at *path*, or "" when missing.

    The BKPS server's ``confidentialData.qek.value`` /
    ``confidentialData.aesKey.value`` validators are case-sensitive
    and reject uppercase hex with ``"Failed to parse ..."`` (matches
    the reference tooling in ``bkps_configure.create_aes_configuration_
    file`` which uses Python's default ``.hex()``).  Older runs of
    ``softhsm_create_qek_and_ccert`` used to write uppercase files —
    we ``.lower()`` here so those still upload cleanly without needing
    to re-run the AES pipeline first.
    """
    try:
        if not path or not os.path.isfile(path):
            return ""
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip().lower()
    except OSError:
        return ""


def _ccert_hex_from_disk(cfg) -> str:
    """Return the signed AES ccert hex produced by the AES pipeline."""
    keys_dir = getattr(cfg, "quartus_keys_dir", "") or ""
    return _read_hex_file(os.path.join(keys_dir, "signed_aes_efuse.ccert_hex.txt"))


def _qek_hex_from_disk(cfg) -> str:
    """Return the QEK hex produced by the AES pipeline."""
    keys_dir = getattr(cfg, "quartus_keys_dir", "") or ""
    return _read_hex_file(os.path.join(keys_dir, "aes_hsm_root.qek_hex.txt"))


def _corim_url_from_disk(cfg) -> str:
    """Return the CoRIM URL extracted after the AES ccert step."""
    return read_saved_corim_url(cfg)


def _is_attestation_key(key_path: str) -> bool:
    """True if *key_path* belongs to the (hidden) attestationConfig subtree."""
    return (
        key_path == "attestationConfig"
        or key_path.startswith("attestationConfig.")
        or ".attestationConfig." in key_path
    )


def _is_aes_ccert_value_key(key_path: str) -> bool:
    """True for confidentialData.{aes,aesKey}.value — target of ccert hex."""
    return key_path in ("confidentialData.aes.value",
                        "confidentialData.aesKey.value")


def _is_qek_value_key(key_path: str) -> bool:
    """True for confidentialData.qek.value — target of QEK hex."""
    return key_path == "confidentialData.qek.value"


def _is_corim_url_key(key_path: str) -> bool:
    """True for the top-level corimUrl field."""
    return key_path == "corimUrl"


def _is_import_mode_key(key_path: str) -> bool:
    """True for confidentialData.importMode"""
    return key_path == "confidentialData.importMode"


def _is_test_mode_secrets_key(key_path: str) -> bool:
    return key_path == "testModeSecrets"


def _is_puf_type_key(key_path: str) -> bool:
    return key_path.endswith(".pufType") or key_path == "pufType"


def _combo_select(combo: QComboBox, value) -> None:
    """Select the combo item matching *value* from the template or saved JSON."""
    cur = "" if value is None else str(value)
    idx = combo.findText(cur)
    if idx < 0:
        for i in range(combo.count()):
            if combo.itemText(i).lower() == cur.lower():
                idx = i
                break
    if idx < 0 and cur:
        combo.addItem(cur)
        idx = combo.findText(cur)
    combo.setCurrentIndex(max(idx, 0))


def build_configuration_settings_box(host, include_config_id: bool = True) -> QGroupBox:
    """Build the AES-configuration settings groupbox (family label + JSON
    table + optional Config ID field) and wire every ``_config_*`` helper
    on host.

    Extracted from :func:`build_configuration_pipeline_box` so the
    Configuration Utilities tab can spawn an INDEPENDENT copy of the
    same table + helpers.  Each host that calls this function gets its
    own :class:`QTableWidget` bound to its own JSON root — call
    ``host._config_reload_family()`` after the host tab is visible to
    populate it from the working file.

    Args:
        host: the tab to attach ``_config_*`` helpers + widgets to.
        include_config_id: when False, the ``Config ID`` row is omitted
            entirely (used by the utilities tab which never runs the
            ``generate_bkp_options`` step).

    Wires on host:
        ``_config_family_label``, ``_config_json_table``,
        ``_config_bkp_status_label``, ``_config_json_root``,
        ``_config_reload_family``, ``_config_working_file_path``,
        ``_config_template_path``, ``_config_save_table_to_file``,
        ``_config_load_table_from_file``, and (only when
        ``include_config_id``) ``_config_id_edit``.
    """
    import json
    from collections import OrderedDict

    # ── Settings ────────────────────────────────────────────────────
    sbox, s1 = _settings_box("Settings")

    host._config_family_label = QLabel("Device family: (unknown)")
    host._config_family_label.setStyleSheet("color:#888; font-style:italic;")
    s1.addWidget(host._config_family_label)

    tbl_label = QLabel("Configuration table (double-click a value to edit):")
    tbl_label.setStyleSheet("color:#ccc;")
    s1.addWidget(tbl_label)

    host._config_json_table = QTableWidget(0, 2)
    host._config_json_table.setHorizontalHeaderLabels(["Field", "Value"])
    host._config_json_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
    host._config_json_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
    host._config_json_table.verticalHeader().setVisible(False)
    host._config_json_table.setEditTriggers(
        QAbstractItemView.EditTrigger.DoubleClicked
        | QAbstractItemView.EditTrigger.SelectedClicked
        | QAbstractItemView.EditTrigger.EditKeyPressed
    )
    host._config_json_table.setMinimumHeight(240)
    s1.addWidget(host._config_json_table)

    if include_config_id:
        id_row = QHBoxLayout()
        id_row.addWidget(QLabel("Config ID (Step 2):"))
        host._config_id_edit = _le(
            "Auto-filled from config_id.txt",
            tip="AES configuration ID.  Auto-filled from config_id.txt when "
                "it exists.  Consumed by Step 2 (Generate bkp_options.txt).",
        )
        host._config_id_edit.setMaximumWidth(360)
        id_row.addWidget(host._config_id_edit)
        id_row.addStretch()
        s1.addLayout(id_row)

    host._config_bkp_status_label = QLabel("")
    host._config_bkp_status_label.setWordWrap(True)
    host._config_bkp_status_label.setStyleSheet("color:#888;")
    s1.addWidget(host._config_bkp_status_label)

    host._config_json_root = None

    def _template_path():
        profile = (host.cfg.profile_name or "").strip().lower()
        template_name = _FAMILY_TEMPLATE.get(profile)
        if not template_name:
            return ""
        return os.path.join(host.cfg.bkps_dir, "admin-tools", template_name)

    def _working_file_path():
        profile = (host.cfg.profile_name or "").strip().lower() or "unknown"
        return os.path.join(host.cfg.bkps_dir, "bkps_configs", f"aes_config_{profile}.json")

    def _refresh_working_file(force: bool = False):
        working = _working_file_path()
        os.makedirs(os.path.dirname(working), exist_ok=True)
        template = _template_path()
        if not template or not os.path.isfile(template):
            host.log.append_error(
                f"Sample template not found for profile '{host.cfg.profile_name}'."
            )
            return ""
        try:
            rebuilt = materialize_reference_configuration(
                template,
                working,
                aes_hex=_ccert_hex_from_disk(host.cfg),
                qek_hex=_qek_hex_from_disk(host.cfg),
                corim_url=_corim_url_from_disk(host.cfg),
                force=force,
            )
        except (OSError, ValueError) as error:
            host.log.append_error(
                f"Failed to build {os.path.basename(working)} from "
                f"{os.path.basename(template)}: {error}"
            )
            return ""
        if rebuilt:
            host.log.append_success(
                f"Built {os.path.basename(working)} from complete reference "
                f"template {os.path.basename(template)}; preserved generated "
                "AES/QEK/CoRIM values."
            )
        return working

    def _ensure_working_file():
        return _refresh_working_file(force=False)

    def _flatten(prefix, obj, out):
        if isinstance(obj, dict):
            for k, v in obj.items():
                _flatten(f"{prefix}.{k}" if prefix else k, v, out)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                _flatten(f"{prefix}[{i}]", v, out)
        else:
            out.append((prefix, obj))

    def _load_table_from_file(path):
        host._config_json_table.setRowCount(0)
        host._config_json_root = None
        # Track special rows so _save_table_to_file knows how to read them.
        host._config_row_widgets: dict[int, str] = {}   # row → widget kind
        host._config_row_readonly: set[int] = set()      # rows we skip in save
        if not path or not os.path.isfile(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f, object_pairs_hook=OrderedDict)
        except (OSError, json.JSONDecodeError) as e:
            host.log.append_error(f"Failed to parse {os.path.basename(path)}: {e}")
            return
        host._config_json_root = data

        # Prime the two confidential-data fields from the hex files the AES
        # pipeline emits so the on-disk JSON is always the source of truth.
        # These edits also survive to _save_table_to_file because we mutate
        # the shared root dict directly.
        ccert_hex = _ccert_hex_from_disk(host.cfg)
        qek_hex   = _qek_hex_from_disk(host.cfg)
        corim_url = _corim_url_from_disk(host.cfg)
        conf = data.get("confidentialData")
        if isinstance(conf, dict):
            if ccert_hex and "aesKey" in conf and isinstance(conf["aesKey"], dict) and "value" in conf["aesKey"]:
                conf["aesKey"]["value"] = ccert_hex
            if qek_hex and "qek" in conf and isinstance(conf["qek"], dict) and "value" in conf["qek"]:
                conf["qek"]["value"] = qek_hex
        if corim_url:
            data["corimUrl"] = corim_url

        # Flatten AFTER the disk-hex prime so the table shows the effective
        # values the operator is about to upload.
        rows_all: list[tuple[str, object]] = []
        _flatten("", data, rows_all)
        # Hide every attestationConfig row entirely — they stay in the JSON
        # root (untouched) and get preserved on save.
        rows = [(k, v) for (k, v) in rows_all if not _is_attestation_key(k)]

        puf_options = _puf_type_options(getattr(host.cfg, "profile_name", ""))
        host._config_json_table.setRowCount(len(rows))
        for r, (k, v) in enumerate(rows):
            it_key = QTableWidgetItem(k)
            it_key.setFlags(it_key.flags() & ~Qt.ItemFlag.ItemIsEditable)
            host._config_json_table.setItem(r, 0, it_key)

            if _is_aes_ccert_value_key(k) or _is_qek_value_key(k):
                # Auto-primed from the on-disk hex file produced by the AES
                # pipeline (or the template fallback when the AES pipeline
                # hasn't been run yet).  Editable — the operator can still
                # overwrite it manually before Create Configuration.
                it_val = QTableWidgetItem("" if v is None else str(v))
                it_val.setForeground(QColor("#7fbf7f"))
                origin = ("signed_aes_efuse.ccert_hex.txt"
                          if _is_aes_ccert_value_key(k)
                          else "aes_hsm_root.qek_hex.txt")
                it_val.setToolTip(
                    f"Auto-populated from {origin} produced by the AES "
                    "pipeline (Create QEK + ccert + Sign).  Editable — "
                    "type over the value if you need to override the "
                    "pipeline output before Create Configuration."
                )
                host._config_json_table.setItem(r, 1, it_val)
                continue

            if _is_corim_url_key(k):
                it_val = QTableWidgetItem("" if v is None else str(v))
                it_val.setForeground(QColor("#7fbf7f"))
                it_val.setToolTip(
                    "Auto-populated from the PROVISION helper image after "
                    "Create QEK + ccert + Sign "
                    "(quartus_pfg --helper_image → .corim → .diag → "
                    "corim.href).  Saved to corim_url.txt.  Editable — "
                    "type over the value if you need to override before "
                    "Create Configuration."
                )
                host._config_json_table.setItem(r, 1, it_val)
                continue

            if _is_import_mode_key(k):
                combo = QComboBox()
                combo.addItems(_IMPORT_MODES)
                _combo_select(combo, v)
                combo.setToolTip(
                    "confidentialData.importMode: ENCRYPTED or PLAINTEXT "
                    "(from the family template or the saved working file)."
                )
                host._config_json_table.setCellWidget(r, 1, combo)
                host._config_row_widgets[r] = "combo"
                continue

            if _is_test_mode_secrets_key(k):
                combo = QComboBox()
                combo.addItems(_BOOL_CHOICES)
                _combo_select(combo, v)
                combo.setToolTip(
                    "testModeSecrets: True is the Agilex B reference setting for "
                    "non-secure (non real-OWNED) devices and permits test-mode "
                    "DICE flags; False requires empty flags for CMF measurements. "
                    "Use False for a real-OWNED device."
                )
                host._config_json_table.setCellWidget(r, 1, combo)
                host._config_row_widgets[r] = "combo"
                continue

            if _is_puf_type_key(k):
                combo = QComboBox()
                combo.addItems(puf_options)
                _combo_select(combo, v)
                combo.setToolTip(
                    "PUF type options are filtered by device family: "
                    "INTEL / INTEL_USER are Agilex 5 only, IID / IIDUSER "
                    "are Agilex 7 only, EFUSE is available on every family."
                )
                host._config_json_table.setCellWidget(r, 1, combo)
                host._config_row_widgets[r] = "combo"
                continue

            it_val = QTableWidgetItem("" if v is None else str(v))
            host._config_json_table.setItem(r, 1, it_val)

    def _reload_family():
        profile = (host.cfg.profile_name or "").strip().lower()
        template_name = _FAMILY_TEMPLATE.get(profile, "(no template)")
        display = host.cfg.device_family or profile or "(unknown)"
        host._config_family_label.setText(
            f"Device family: {display}   |   Template: {template_name}   |   "
            f"Working file: {_working_file_path()}"
        )
        _load_table_from_file(_ensure_working_file())

    def _save_table_to_file(path):
        if not path or host._config_json_root is None:
            return False
        def _set_by_path(root, key_path, val):
            cur = root
            parts = key_path.replace("]", "").split(".")
            for p in parts[:-1]:
                if "[" in p:
                    name, idx = p.split("[")
                    cur = cur[name][int(idx)]
                else:
                    cur = cur[p]
            last = parts[-1]
            if "[" in last:
                name, idx = last.split("[")
                cur[name][int(idx)] = val
            else:
                cur[last] = val
        row_widgets  = getattr(host, "_config_row_widgets",  {}) or {}
        row_readonly = getattr(host, "_config_row_readonly", set()) or set()
        for r in range(host._config_json_table.rowCount()):
            k_item = host._config_json_table.item(r, 0)
            if k_item is None:
                continue
            k = k_item.text()
            # Read-only rows (aes/qek hex) were primed into the JSON root at
            # load time and must not be overwritten by table scrapes.
            if r in row_readonly:
                continue

            widget = host._config_json_table.cellWidget(r, 1)
            if widget is not None and row_widgets.get(r) == "combo":
                raw = widget.currentText()
            else:
                v_item = host._config_json_table.item(r, 1)
                if v_item is None:
                    continue
                raw = v_item.text()

            # Coerce best-effort: bool, int, float, else string.
            if raw.lower() in ("true", "false"):
                val = (raw.lower() == "true")
            else:
                try:
                    val = int(raw)
                except ValueError:
                    try:
                        val = float(raw)
                    except ValueError:
                        val = raw
            try:
                _set_by_path(host._config_json_root, k, val)
            except (KeyError, IndexError, TypeError):
                continue
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(host._config_json_root, f, indent=2)
        except OSError as e:
            host.log.append_error(f"Failed to write {path}: {e}")
            return False
        return True

    # Expose for the utilities tab (Reload From Template / Update).
    host._config_reload_family      = _reload_family
    host._config_refresh_working_file = _refresh_working_file
    host._config_working_file_path  = _working_file_path
    host._config_template_path      = _template_path
    host._config_save_table_to_file = _save_table_to_file
    host._config_load_table_from_file = _load_table_from_file
    return sbox


def build_configuration_pipeline_box(host) -> QGroupBox:
    """AES-configuration + bkp_options.txt pipeline.

    Uses :func:`build_configuration_settings_box` for the top-of-flow
    settings widget (JSON table + Config ID), then adds the two step
    buttons in the standard horizontal row.
    """
    box = QGroupBox("Configuration Pipeline")
    outer = QVBoxLayout(box)
    outer.setContentsMargins(8, 8, 8, 8)
    outer.setSpacing(6)

    sbox = build_configuration_settings_box(host)
    outer.addWidget(sbox)

    def _pipe_create_config(cfg):
        # NOTE: we deliberately do NOT re-load the table from disk here.
        # The AES pipeline emits an ``aes_hex_updated`` signal that refreshes
        # the table right after Create QEK + ccert succeeds, so any operator
        # edits made AFTER that (including manual overrides to the aes/qek
        # hex fields) must survive Create Configuration untouched.
        working = host._config_working_file_path()
        if not host._config_save_table_to_file(working):
            raise RuntimeError("Failed to save the table before uploading.")
        return upload_aes_configuration_file(cfg, working)

    host._step_dispatch[("configuration", "create_config")] = _pipe_create_config

    def _pipe_create_programmer(cfg):
        # Reuse the shared bkps_users.create_user helper — same code path as
        # the manual "Create User" utility, just pinned to ROLE_PROGRAMMER
        # so bkp_options.txt generation (below) has a programmer identity
        # to embed in the runner config.  No server restart is required:
        # runner.py picks up the new cert/key via runner-config.json on the
        # next invocation.
        return create_user(cfg, "ROLE_PROGRAMMER")

    host._step_dispatch[("configuration", "create_programmer")] = _pipe_create_programmer

    def _pipe_generate_bkp(cfg):
        config_id = host._config_id_edit.text().strip() or None
        if not config_id and not read_config_id(cfg):
            raise RuntimeError(
                "No Config ID entered and config_id.txt not found.  "
                "Run Create Configuration first, or paste an ID."
            )
        return create_bkp_config(cfg, config_id)

    host._step_dispatch[("configuration", "generate_bkp_options")] = _pipe_generate_bkp

    specs = [
        ("create_config",        "Saves the table above to disk and uploads it "
                                 "to BKPS as a new configuration."),
        ("create_programmer",    "Create a ROLE_PROGRAMMER user (cert + PFX) "
                                 "so bkp_options.txt / runner.py have a "
                                 "programmer identity to authenticate with."),
        ("generate_bkp_options", "Generate bkp_options.txt using the Config ID "
                                 "in the settings box (falls back to "
                                 "config_id.txt when blank)."),
    ]
    btns = _register_buttons(host, "configuration", specs)
    outer.addLayout(_manual_mode_row(host, "configuration"))
    _add_row_with_arrows(outer, [btns[sid] for sid, _ in specs],
                         host=host, group="configuration")
    return box


# ── Programming pipeline ---------------------------------------------------
def build_programming_pipeline_box(host) -> QGroupBox:
    """Programming pipeline with a single top settings box + horizontal steps.

    Every operator-tunable input (JIC-generation params, JIC file to
    program, PUF-activate PUF type, Set-Authority PUF type + slot ID)
    is bundled into a top settings groupbox so the operator can pre-fill
    everything before starting the pipeline.  Steps are then a single
    horizontal row like every other pipeline flow.
    """
    box = QGroupBox("Programming Pipeline")
    outer = QVBoxLayout(box)
    outer.setContentsMargins(8, 8, 8, 8)
    outer.setSpacing(6)

    # ── Settings ────────────────────────────────────────────────────
    sbox, slay = _settings_box("Settings")

    host._prog_bkp_status = QLabel(""); host._prog_bkp_status.setWordWrap(True)
    slay.addWidget(host._prog_bkp_status)

    def _labeled(label, placeholder, tip, browse_cb=None):
        row = QHBoxLayout()
        lbl = QLabel(label); lbl.setFixedWidth(140)
        row.addWidget(lbl)
        edit = _le(placeholder, tip=tip)
        if browse_cb is not None:
            row.addLayout(_file_row(edit, browse_cb, None))
        else:
            row.addWidget(edit)
        return row, edit

    # JIC generation inputs (Step 1).
    jic_gen_hdr = QLabel("JIC generation")
    jic_gen_hdr.setStyleSheet("color:#f0c060; font-weight:bold;")
    slay.addWidget(jic_gen_hdr)

    sof_row, host._prog_sof = _labeled(
        "SOF File:", "Path to design.sof",
        "Compiled Quartus SOF used as input.",
        lambda: _browse(host, host._prog_sof, "SOF files (*.sof);;All files (*)"))
    slay.addLayout(sof_row)
    rbf_row, host._prog_rbf = _labeled(
        "RBF File:", "Optional existing design.rbf. When defined, takes PRIORITY over SOF.",
        "Optional pre-baked RBF.  When set, takes PRIORITY over SOF: "
        "the RBF is staged into the output directory as design.rbf and "
        "fed straight into quartus_pfg with NO extra processing (no "
        "SOF→RBF conversion, encryption, or signing).",
        lambda: _browse(host, host._prog_rbf, "RBF files (*.rbf);;All files (*)"))
    slay.addLayout(rbf_row)
    flash_row = QHBoxLayout()
    fl = QLabel("Flash Device:"); fl.setFixedWidth(140); flash_row.addWidget(fl)
    host._prog_flash_dev = _le("e.g. MT25QU02G", tip="Flash device type.")
    flash_row.addWidget(host._prog_flash_dev)
    flash_row.addSpacing(12)
    flash_row.addWidget(QLabel("Flash Loader:"))
    host._prog_flash_ldr = _le(
        "Defaults from Config → Device Part",
        tip="Flash loader device for PFG.  Defaults to Device Part from "
            "the Config tab; you can override it here.",
    )
    # Prime from Config device_part; refresh keeps it in sync until the
    # operator edits the field to something else.
    _part = (getattr(host.cfg, "device_part", "") or "").strip()
    if _part:
        host._prog_flash_ldr.setText(_part)
    host._prog_flash_ldr_auto = _part
    flash_row.addWidget(host._prog_flash_ldr)
    slay.addLayout(flash_row)
    outdir_row, host._prog_outdir = _labeled(
        "Output Dir:", "Auto = <cm_provisioning_dir>/device_onboarding",
        "Output directory for the JIC. Defaults to the device_onboarding "
        "folder below CM Provisioning Dir from the Config tab.",
        lambda: _browse_dir(host, host._prog_outdir))
    _auto_outdir = resolve_jic_output_dir(host.cfg)
    if _auto_outdir:
        host._prog_outdir.setText(_auto_outdir)
    host._prog_outdir_auto = _auto_outdir
    slay.addLayout(outdir_row)

    # JIC file to program (Step 4).
    prog_hdr = QLabel("Custom JIC to program (Optional)")
    prog_hdr.setStyleSheet("color:#f0c060; font-weight:bold;")
    slay.addWidget(prog_hdr)
    jic_row = QHBoxLayout()
    jl = QLabel("JIC File:"); jl.setFixedWidth(140); jic_row.addWidget(jl)
    host._prog_jic = _le("Auto-filled after Generate JIC, or browse",
                         tip="JIC image to program.")
    jic_row.addLayout(_file_row(
        host._prog_jic,
        lambda: _browse(host, host._prog_jic, "JIC files (*.jic);;All files (*)"),
        None))
    slay.addLayout(jic_row)

    # PUF settings (Steps 6 & 9) — kept visible only when applicable.
    host._prog_puf_settings_box = QGroupBox("PUF settings (Steps 6 && 9, when applicable)")
    puf_lay = QVBoxLayout(host._prog_puf_settings_box)
    puf_lay.setContentsMargins(8, 8, 8, 8)

    # Wrap each combo row in its own container widget so the
    # PUF-Activate row can be shown/hidden independently of the
    # Set-Authority row (INTERNAL ccert types skip PUF activation
    # entirely and must hide the Step 6 combo).
    host._prog_puf_act_row = QWidget()
    pa = QHBoxLayout(host._prog_puf_act_row)
    pa.setContentsMargins(0, 0, 0, 0)
    pa_lbl = QLabel("Step 6 PUF Type:"); pa_lbl.setFixedWidth(140); pa.addWidget(pa_lbl)
    host._prog_puf_act_combo = QComboBox()
    pa.addWidget(host._prog_puf_act_combo)
    pa.addStretch()
    puf_lay.addWidget(host._prog_puf_act_row)

    host._prog_set_auth_row = QWidget()
    sa = QHBoxLayout(host._prog_set_auth_row)
    sa.setContentsMargins(0, 0, 0, 0)
    sa_lbl = QLabel("Step 9 PUF Type:"); sa_lbl.setFixedWidth(140); sa.addWidget(sa_lbl)
    host._prog_set_auth_combo = QComboBox()
    sa.addWidget(host._prog_set_auth_combo)
    sa.addSpacing(12)
    sa.addWidget(QLabel("Slot ID:"))
    host._prog_slot_spin = QSpinBox()
    host._prog_slot_spin.setRange(0, 7)
    host._prog_slot_spin.setFixedWidth(60)
    sa.addWidget(host._prog_slot_spin)
    sa.addStretch()
    puf_lay.addWidget(host._prog_set_auth_row)

    slay.addWidget(host._prog_puf_settings_box)
    outer.addWidget(sbox)

    # ── Step dispatch table ────────────────────────────────────────
    #
    # IMPORTANT: these callables run on a ``BkpsWorker`` background
    # thread.  Every Qt-widget touch (read OR write) MUST go through
    # ``run_on_gui`` so it executes on the main thread — otherwise the
    # race described at the top of this file (worker read vs. GUI
    # thread widget-``d``-ptr reallocation) crashes libQt6Gui with a
    # NULL-d-ptr deref at offset 0x10.  The crash reliably reproduces
    # in manual mode after a failed step because ``refresh_pipeline_gating``
    # re-styles all 10 programming buttons at once and the failed-step
    # traceback repaint keeps the GUI-thread paint pipeline busy just
    # long enough to collide with the next worker's widget read.
    def _pipe_generate_jic(cfg):
        # Snapshot every operator-tunable JIC-generation input in a
        # single main-thread hop so we don't pay N BlockingQueued round
        # trips for N widgets.
        inputs = run_on_gui(lambda: {
            "sof": host._prog_sof.text().strip() or None,
            "rbf": host._prog_rbf.text().strip() or None,
            "out": host._prog_outdir.text().strip(),
            "fd":  host._prog_flash_dev.text().strip(),
            "fl":  host._prog_flash_ldr.text().strip(),
        })
        sof, rbf = inputs["sof"], inputs["rbf"]
        out = resolve_jic_output_dir(cfg, inputs["out"])
        fd, fl = inputs["fd"], inputs["fl"]
        if out and not inputs["out"]:
            run_on_gui(lambda value=out: host._prog_outdir.setText(value))
        # SOF is required only when no RBF is provided — RBF path skips
        # SOF conversion; Studio never encrypts or signs either input path.
        missing = [n for n, v in (
            ("output dir", out), ("flash device", fd),
            ("flash loader", fl)) if not v]
        if missing:
            raise ValueError("Missing required input(s): " + ", ".join(missing))
        if not sof and not rbf:
            raise ValueError("Provide either a SOF file or an RBF file.")
        if rbf and not os.path.isfile(rbf):
            raise FileNotFoundError(f"RBF file not found: {rbf}")
        if sof and not os.path.isfile(sof):
            raise FileNotFoundError(f"SOF file not found: {sof}")
        result = generate_jic(cfg, sof, out, fd, fl, rbf=rbf)
        if isinstance(result, str) and result.endswith(".jic"):
            # Widget mutation MUST run on the GUI thread. Fire-and-forget
            # is fine here — we don't need the setText call to complete
            # before we return.
            run_on_gui(lambda r=result: host._prog_jic.setText(r))
        return result

    def _pipe_program_helper_image(cfg):
        return program_helper_image(cfg)

    def _pipe_program_jic(cfg):
        jic = run_on_gui(lambda: host._prog_jic.text().strip())
        if not jic or not os.path.isfile(jic):
            raise FileNotFoundError("JIC file missing.")
        return program_jic(cfg, jic)

    def _pipe_puf_activate(cfg):
        puf = run_on_gui(lambda: host._prog_puf_act_combo.currentText())
        return bkp_puf_activate(cfg, puf)

    def _pipe_set_authority(cfg):
        combo = run_on_gui(lambda: (
            host._prog_set_auth_combo.currentText(),
            host._prog_slot_spin.value(),
        ))
        return bkp_set_authority(cfg, combo[0], combo[1])

    host._step_dispatch[("programming", "generate_jic")]             = _pipe_generate_jic
    host._step_dispatch[("programming", "program_helper_image_pre")]  = _pipe_program_helper_image
    host._step_dispatch[("programming", "provision_rkh_pre")]         = provision_rkh_virtual
    host._step_dispatch[("programming", "program_jic")]               = _pipe_program_jic
    host._step_dispatch[("programming", "prefetch")]                  = bkp_prefetch
    host._step_dispatch[("programming", "puf_activate")]              = _pipe_puf_activate
    # Post-PUF repeats — same callables as the pre-JIC steps.
    host._step_dispatch[("programming", "program_helper_image")]      = _pipe_program_helper_image
    host._step_dispatch[("programming", "provision_rkh")]             = provision_rkh_virtual
    host._step_dispatch[("programming", "set_authority")]             = _pipe_set_authority
    host._step_dispatch[("programming", "provision")]                 = run_bkp

    specs = [
        ("generate_jic",             "Convert SOF → JIC using the JIC-generation settings above."),
        ("program_helper_image_pre", "Program the PROVISION Helper Image to the device via JTAG "),
        ("provision_rkh_pre",        "Provision Device Owner Root Key to the virtual fuse. "
                                     "Skipped automatically if key already present on device."),
        ("program_jic",              "Program the selected .jic to the device via JTAG."),
        ("prefetch",                 "Run BKP prefetch on the connected device via JTAG."),
        ("puf_activate",             "Activate on-device PUF via JTAG.  The chain "
                                     "PAUSES after this step — power-cycle the "
                                     "device, then click 'Program Helper Image (post-PUF)' "
                                     "to continue.  Hidden entirely when the "
                                     "selected AES ccert type resolves to an "
                                     "INTERNAL PUF (no PUF activation needed)."),
        ("program_helper_image",     "Re-program the PROVISION Helper Image after PUF "
                                     "activation."),
        ("provision_rkh",            "Re-provision Device Owner Root Key after PUF "
                                     "activation.  Skipped automatically if key already present on device."),
        ("set_authority",            "Set device authority via JTAG (hidden when N/A)."),
        ("provision",                "Run the full BKP provisioning flow."),
    ]
    btns = _register_buttons(host, "programming", specs)
    outer.addLayout(_manual_mode_row(host, "programming"))
    _add_row_with_arrows(outer, [btns[sid] for sid, _ in specs],
                         host=host, group="programming")

    return box


# ── Small file/dir browse helpers used by the Programming builder ─────────
def _browse(host, line_edit: QLineEdit, filter_str: str):
    path = _pick_file(host, "Select file", filter_str)
    if path:
        line_edit.setText(path)


def _browse_dir(host, line_edit: QLineEdit):
    path = _pick_dir(host, "Select directory")
    if path:
        line_edit.setText(path)


# ── Post-build helpers combined tabs call from their showEvent ------------
def refresh_aes_pipeline_visibility(host) -> None:
    """Show/hide Agilex-5-only AES buttons based on cfg.profile_name."""
    profile = getattr(host.cfg, "profile_name", "") or ""
    is_agilex5 = (profile == "agilex5")
    for sid in ("init_token", "create_key"):
        btn = host._pipe_buttons.get("aes", {}).get(sid)
        if btn is not None:
            btn.setVisible(is_agilex5)
    _refresh_step_arrows(host, "aes")


def _ccert_puf_hint(cfg) -> str:
    """Return the PUF-type hint associated with ``cfg.aes_ccert_type``.

    ``AES_CCERT_TYPES`` is keyed by device family and each entry is
    ``{ccert_type: [puf_type, key_storage]}``.  Returns the PUF type for
    the selected ``cfg.aes_ccert_type``.
    """
    profile = getattr(cfg, "profile_name", "") or ""
    ccert_type = (getattr(cfg, "aes_ccert_type", "") or "").strip()
    puf_type, _ = aes_ccert_lookup(profile, ccert_type)
    return puf_type.upper()


def refresh_programming_pipeline_visibility(host) -> None:
    """Show/hide programming-pipeline widgets based on family + ccert PUF hint.

    Pre-JIC helper image + root-key-hash (``program_helper_image_pre`` /
    ``provision_rkh_pre``) are always visible — compulsory for INTERNAL
    and non-INTERNAL.

    INTERNAL ccert types skip PUF activation and the post-PUF repeats::

        Generate JIC → Program Helper Image → Program Root Key Hash
            → Program JIC → BKP Prefetch → BKP Set Authority → BKP Provision

    Non-INTERNAL (Agilex) keeps the full flow (post-PUF helper + RKH after
    power-cycle)::

        Generate JIC → Program Helper Image → Program Root Key Hash
            → Program JIC → BKP Prefetch → BKP PUF Activate
            → Program Helper Image (post-PUF) → Program Root Key Hash (post-PUF)
            → BKP Set Authority → BKP Provision

    Stratix 10 never needs the post-PUF helper / RKH repeats (even for
    IID_PUF ccert types) — those steps are hidden and auto-succeeded.

    The Step-6 PUF-Activate combo row is hidden alongside its step
    button when INTERNAL.  The Step-9 Set-Authority combo is filtered
    per hint: INTERNAL exposes only ``UDS_EFUSE`` (eFuse-backed
    authority is the only meaningful choice), while non-INTERNAL hides
    ``UDS_EFUSE`` and exposes only PUF-backed options.
    """
    profile = getattr(host.cfg, "profile_name", "") or ""
    puf_cfg = PUF_TYPES.get(profile, {})
    hint = _ccert_puf_hint(host.cfg)
    is_internal = (hint == "INTERNAL")
    is_stratix10 = (profile == "stratix10")

    pa_family_ok = "puf_activate" in puf_cfg
    sa_family_ok = "set_authority" in puf_cfg

    # Pre-JIC helper / RKH always shown.  Post-PUF repeats only for
    # non-INTERNAL families that need them (not Stratix 10).
    pa_apply = pa_family_ok and not is_internal
    sa_apply = sa_family_ok
    show_post_puf = (not is_internal) and (not is_stratix10)

    # Flash Loader ← Config Device Part (default only; keep user edits).
    if hasattr(host, "_prog_flash_ldr"):
        part = (getattr(host.cfg, "device_part", "") or "").strip()
        current = host._prog_flash_ldr.text().strip()
        last_auto = getattr(host, "_prog_flash_ldr_auto", None)
        if part and (not current or current == last_auto):
            host._prog_flash_ldr.setText(part)
            host._prog_flash_ldr_auto = part
        elif not part and not current:
            host._prog_flash_ldr_auto = ""

    # Output Dir ← <CM Provisioning Dir>/device_onboarding.  Track the last
    # automatic value so config changes update it without overwriting a path
    # the operator selected manually.
    if hasattr(host, "_prog_outdir"):
        auto_outdir = resolve_jic_output_dir(host.cfg)
        current = host._prog_outdir.text().strip()
        last_auto = getattr(host, "_prog_outdir_auto", None)
        if auto_outdir and (not current or current == last_auto):
            host._prog_outdir.setText(auto_outdir)
            host._prog_outdir_auto = auto_outdir
        elif not auto_outdir and not current:
            host._prog_outdir_auto = ""

    prog_btns = host._pipe_buttons.get("programming", {})
    if "program_helper_image_pre" in prog_btns:
        prog_btns["program_helper_image_pre"].setVisible(True)
    if "provision_rkh_pre" in prog_btns:
        prog_btns["provision_rkh_pre"].setVisible(True)
    if "puf_activate" in prog_btns:
        prog_btns["puf_activate"].setVisible(pa_apply)
    if "program_helper_image" in prog_btns:
        prog_btns["program_helper_image"].setVisible(show_post_puf)
    if "provision_rkh" in prog_btns:
        prog_btns["provision_rkh"].setVisible(show_post_puf)
    if "set_authority" in prog_btns:
        prog_btns["set_authority"].setVisible(sa_apply)

    # Settings box + per-row visibility.
    if hasattr(host, "_prog_puf_act_row"):
        host._prog_puf_act_row.setVisible(pa_apply)
    if hasattr(host, "_prog_set_auth_row"):
        host._prog_set_auth_row.setVisible(sa_apply)
    if hasattr(host, "_prog_puf_settings_box"):
        host._prog_puf_settings_box.setVisible(pa_apply or sa_apply)

    if pa_apply and hasattr(host, "_prog_puf_act_combo"):
        host._prog_puf_act_combo.clear()
        host._prog_puf_act_combo.addItems(puf_cfg["puf_activate"])

    # Set-Authority combo filtering — hint drives which PUF-type
    # options make sense:
    #   INTERNAL  → only UDS_EFUSE (eFuse-backed authority)
    #   non-INTERNAL → every option EXCEPT UDS_EFUSE (PUF-backed only)
    if sa_apply and hasattr(host, "_prog_set_auth_combo"):
        host._prog_set_auth_combo.clear()
        all_options = list(puf_cfg["set_authority"])
        if is_internal:
            filtered = [o for o in all_options if o == "UDS_EFUSE"]
        else:
            filtered = [o for o in all_options if o != "UDS_EFUSE"]
        # Fall back to the full list if filtering wiped everything —
        # never leave the operator with an empty combo (would break
        # bkp_set_authority which requires a value).
        host._prog_set_auth_combo.addItems(filtered or all_options)

    visible_steps = {sid for sid, _ in PIPELINE_STEPS["programming"]}
    if not pa_apply:
        visible_steps.discard("puf_activate")
    if not show_post_puf:
        visible_steps.discard("program_helper_image")
        visible_steps.discard("provision_rkh")
    if not sa_apply:
        visible_steps.discard("set_authority")
    _renumber_visible_pipeline_buttons(host, "programming", visible_steps)
    _refresh_step_arrows(host, "programming")

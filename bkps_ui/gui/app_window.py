#!/usr/bin/env python3
"""
app_window.py - Main application window.

AppWindow is the top-level QMainWindow for the Black Key Provisioning Automation Studio.
It contains:
- Menu bar (File, Help)
- QTabWidget with every BKPS workflow tab
- Status bar with Server + DB health indicators polled every 10 s on a
  background _HealthChecker thread so the UI is never blocked

Exports:
    AppWindow  - the main window class (instantiated once in main.py)
"""

import socket
import sys
import os
import subprocess

from PySide6.QtCore import QTimer, QThread, Signal as QtSignal, Qt
from PySide6.QtGui import QAction, QFont, QColor
from PySide6.QtWidgets import (
    QMainWindow, QStatusBar,
    QLabel, QFileDialog, QMessageBox, QWidget,
    QVBoxLayout, QHBoxLayout, QProgressBar,
    QListWidget, QListWidgetItem, QStackedWidget, QFrame,
    QSizePolicy,
)

from config_store import ConfigStore
from stdout_capture import StdoutCapture
from pipeline import PipelineState, PIPELINE_STEPS, PIPELINE_CHAIN, StepStatus
from bkps_autosetup import check_setup_complete
from bkps_configure import read_config_id
# Tab imports
from tabs.tab_config import ConfigTab
from tabs.tab_setup import SetupTab
from tabs.tab_bkp_config import BkpConfigTab
from tabs.tab_bkp import BkpTab
from tabs.tab_server_operations import ServerOperationsTab
from tabs.tab_server_utilities import ServerUtilitiesTab
from tabs.tab_aes_utilities import AesUtilitiesTab
from tabs.tab_configuration_utilities import ConfigurationUtilitiesTab
from tabs.tab_debug import DebugTab

# Hoisted (previously inline) imports
import psycopg2



class _PhaseCard(QFrame):
    """A single clickable phase card in the top-of-window stepper.

    Shows a large step number, a title, and a status dot / label whose
    colour reflects one of ``pending`` / ``active`` / ``done``.  Clicking
    the card jumps the main nav to the tab it represents so operators
    can use the stepper as both a status display and shortcut bar.
    """

    _STATE_COLOURS = {
        "pending": ("#3a3a3a", "#888",     "#2a2a2a", "○"),
        "active":  ("#f39c12", "#ffffff",  "#5a3a15", "●"),
        "done":    ("#27ae60", "#ffffff",  "#1e4a2a", "✓"),
    }

    clicked = QtSignal(str)  # emits the nav_attr string on click

    def __init__(self, number: int, title: str, subtitle: str, nav_attr: str, parent=None):
        super().__init__(parent)
        self._nav_attr = nav_attr
        self._state = "pending"

        self.setObjectName("PhaseCard")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(64)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(12, 8, 12, 8)
        outer.setSpacing(10)

        self._num_lbl = QLabel(str(number))
        f = self._num_lbl.font()
        f.setBold(True); f.setPointSizeF(f.pointSizeF() + 8)
        self._num_lbl.setFont(f)
        self._num_lbl.setFixedWidth(28)
        self._num_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(self._num_lbl)

        text_box = QVBoxLayout()
        text_box.setContentsMargins(0, 0, 0, 0); text_box.setSpacing(1)
        self._title_lbl = QLabel(title)
        tf = self._title_lbl.font(); tf.setBold(True); tf.setPointSizeF(tf.pointSizeF() + 1)
        self._title_lbl.setFont(tf)
        text_box.addWidget(self._title_lbl)
        self._subtitle_lbl = QLabel(subtitle)
        sf = self._subtitle_lbl.font(); sf.setPointSizeF(max(1.0, sf.pointSizeF() - 1))
        self._subtitle_lbl.setFont(sf)
        text_box.addWidget(self._subtitle_lbl)
        outer.addLayout(text_box, stretch=1)

        self._status_lbl = QLabel("○")
        stf = self._status_lbl.font()
        stf.setBold(True); stf.setPointSizeF(stf.pointSizeF() + 6)
        self._status_lbl.setFont(stf)
        self._status_lbl.setFixedWidth(28)
        self._status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(self._status_lbl)

        self.set_state("pending")

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._nav_attr)
        super().mousePressEvent(event)

    def set_state(self, state: str) -> None:
        """One of ``pending`` / ``active`` / ``done``."""
        if state not in self._STATE_COLOURS:
            state = "pending"
        self._state = state
        border, fg, bg, icon = self._STATE_COLOURS[state]
        self.setStyleSheet(
            f"QFrame#PhaseCard {{ background:{bg}; border:2px solid {border}; "
            f"border-radius:6px; }}"
            f"QLabel {{ color:{fg}; background:transparent; border:none; }}"
        )
        self._status_lbl.setText(icon)


class _PhaseConnector(QLabel):
    """Chevron / arrow drawn between two ``_PhaseCard`` widgets."""

    def __init__(self, parent=None):
        super().__init__("▶", parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedWidth(28)
        f = self.font()
        f.setPointSizeF(f.pointSizeF() + 6); f.setBold(True)
        self.setFont(f)
        self._done = False
        self._refresh_style()

    def set_done(self, done: bool) -> None:
        self._done = done
        self._refresh_style()

    def _refresh_style(self):
        colour = "#27ae60" if self._done else "#555"
        self.setStyleSheet(f"color:{colour}; background:transparent;")


class _HealthChecker(QThread):
    """Background thread: performs TCP/DB probes without blocking the UI.

    Emits result(srv_ok, db_ok) once when both probes complete.  The
    probes use short timeouts (1 s TCP, 1 s DB) so the thread is fast.
    """
    result = QtSignal(bool, bool)   # (srv_ok, db_ok)

    def __init__(self, host: str, port: int, db_port: int,
                 db_user: str, db_password: str, db_name: str):
        """Initialise the health checker with connection parameters.

        Args:
            host:        Hostname or IP of the BKPS server.
            port:        HTTPS port of the BKPS server (typically 9443).
            db_port:     PostgreSQL port (typically 5432).
            db_user:     Database username.
            db_password: Database password (may be empty).
            db_name:     Database name to connect to.
        """
        super().__init__()
        self._host = host
        self._port = port
        self._db_port = db_port
        self._db_user = db_user
        self._db_password = db_password
        self._db_name = db_name

    def run(self) -> None:
        """Run TCP and DB probes and emit result on completion."""
        # ── BKPS server probe (TCP connect) ────────────────────────────────
        # Server check — TCP only (1 s timeout so this thread is fast)
        srv_ok = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            srv_ok = (sock.connect_ex((self._host, self._port)) == 0)
            sock.close()
        except Exception:
            pass

        # ── Database probe ─────────────────────────────────────────────────
        # DB check
        db_ok = False
        try:
            conn = psycopg2.connect(
                host="localhost", port=self._db_port,
                user=self._db_user, password=self._db_password,
                database=self._db_name, connect_timeout=1,
            )
            conn.close()
            db_ok = True
        except Exception:
            # psycopg2 not installed or wrong credentials — fall back to psql CLI.
            try:
                result = subprocess.run(
                    ["psql", "-h", "localhost", "-p", str(self._db_port),
                     "-U", self._db_user, "-d", self._db_name, "-c", "SELECT 1;"],
                    capture_output=True, timeout=2,
                    env={**os.environ, "PGPASSWORD": self._db_password},
                )
                db_ok = result.returncode == 0
            except Exception:
                pass

        self.result.emit(srv_ok, db_ok)


class AppWindow(QMainWindow):
    """Top-level application window for the Black Key Provisioning Automation Studio.

    Builds the menu bar, tab widget, and status bar, then starts the
    10-second health-poll timer.  All tabs are instantiated eagerly so
    their LogPanels are ready to receive output from the moment the
    window appears.
    """

    def __init__(self, store: ConfigStore, capture: StdoutCapture):
        """Create the main window.

        Args:
            store:   Shared ConfigStore instance (passed down to every tab).
            capture: Active StdoutCapture (passed down to every tab so workers
                     can register their thread for per-tab log routing).
        """
        super().__init__()
        self._store = store
        self._capture = capture

        # Shared pipeline state (used by Installation and Server tabs).
        # Instantiated *before* the tabs so their build_controls() can find
        # it via ``self.window().pipeline`` during construction.
        self.pipeline = PipelineState(self)

        # Every per-flow "Manual mode" checkbox is forced OFF by
        #     wiping the persisted ``pipeline/manual_mode/<group>`` keys
        #     under our QSettings scope BEFORE ``_build_tabs`` runs, so
        #     ``_manual_mode_row`` reads the reset (False) value when
        #     it constructs the checkbox for every flow.
        try:
            from PySide6.QtCore import QSettings
            _s = QSettings("Intel", "BKPS-Studio")
            for _grp in PIPELINE_STEPS.keys():
                _s.remove(f"pipeline/manual_mode/{_grp}")
            _s.sync()
        except Exception:
            # QSettings failures are non-fatal — worst case the checkbox
            # keeps its last-session value, which is exactly the old
            # behavior we're moving away from but not a crash.
            pass

        self.setWindowTitle("Black Key Provisioning Automation Studio")
        self.resize(1100, 780)
        self.setMinimumSize(900, 600)

        self._build_menu()
        self._build_tabs()
        self._build_status_bar()
        self._start_poll_timer()

        # Pipeline status is initially PENDING, then restored below only from
        # artifacts belonging to the selected BKPS project.
        self.pipeline.changed.connect(self._on_pipeline_changed)
        self.pipeline.group_completed.connect(self._on_pipeline_group_completed)

        # Inject the BKP tab's configuration bridge into the Configuration
        # Utilities tab so Reload / Update use the shared JSON table state.
        if hasattr(self, "_tab_cfg_util") and hasattr(self, "_tab_bkp_config"):
            self._tab_cfg_util.config_bridge = self._tab_bkp_config.config_bridge

        # Config → Apply Changes unlocks every pipeline + utility button.
        # A completed prior project is restored without asking the operator
        # to repeat BKPS Setup.
        self._tab_config.config_applied.connect(self._on_config_applied)
        self._tab_config.project_loaded.connect(self._on_project_loaded)
        self._restore_project_state(reset=False)

    # ------------------------------------------------------------------
    # Menu bar
    # ------------------------------------------------------------------

    def _build_menu(self) -> None:
        """Construct the menu bar with File, Keystore, and Help menus."""
        mb = self.menuBar()

        file_menu = mb.addMenu("&File")

        load_act = QAction("&Load Config…", self)
        load_act.setShortcut("Ctrl+O")
        load_act.triggered.connect(self._load_config)
        file_menu.addAction(load_act)

        save_act = QAction("&Save Config…", self)
        save_act.setShortcut("Ctrl+S")
        save_act.triggered.connect(self._save_config)
        file_menu.addAction(save_act)

        file_menu.addSeparator()

        exit_act = QAction("E&xit", self)
        exit_act.setShortcut("Ctrl+Q")
        exit_act.triggered.connect(self.close)
        file_menu.addAction(exit_act)

        help_menu = mb.addMenu("&Help")

        about_act = QAction("&About", self)
        about_act.triggered.connect(self._show_about)
        help_menu.addAction(about_act)

    # ------------------------------------------------------------------
    # Tab widget
    # ------------------------------------------------------------------

    # Definitions used by both nav construction and per-tab lookup.  Each
    # entry is either a category header ``("__header__", text, kind)`` or a
    # real tab description ``(label, cls, attr, gated_on, kind)``.  ``kind``
    # drives the visual weight the nav gives to that row:
    #   "flow"     — the guided-setup path (Config → Setup → BKP), bold + tinted
    #   "utility"  — secondary manual tabs, muted colour + smaller font
    #   "util_hdr" — the Utilities category header
    _NAV_ENTRIES: list = [
        ("1. Config",                        "ConfigTab",                   "_tab_config",       None, "flow"),
        ("2. BKPS Setup",                    "SetupTab",                    "_tab_setup",        None, "flow"),
        ("3. BKPS Configuration",            "BkpConfigTab",                "_tab_bkp_config",   None, "flow"),
        ("4. BKP Onboarding/Provision",      "BkpTab",                      "_tab_bkp",          None, "flow"),
        ("__header__", "── Utilities ──", "util_hdr"),
        ("Server Control Panel",             "ServerOperationsTab",         "_tab_server_ops",   None, "utility"),
        ("Server Utilities",                 "ServerUtilitiesTab",          "_tab_server_util",  None, "utility"),
        ("AES Utilities",                    "AesUtilitiesTab",             "_tab_aes_util",     None, "utility"),
        ("Configuration Utilities",          "ConfigurationUtilitiesTab",   "_tab_cfg_util",     None, "utility"),
        ("Debug",                            "DebugTab",                    "_tab_debug",        None, "utility"),
    ]
    
    _TAB_CLASSES: dict = {
        "ConfigTab":                  ConfigTab,
        "SetupTab":                   SetupTab,
        "BkpConfigTab":                 BkpConfigTab,
        "BkpTab":                     BkpTab,
        "ServerOperationsTab":        ServerOperationsTab,
        "ServerUtilitiesTab":         ServerUtilitiesTab,
        "AesUtilitiesTab":            AesUtilitiesTab,
        "ConfigurationUtilitiesTab":  ConfigurationUtilitiesTab,
        "DebugTab":                   DebugTab,
    }

    def _build_tabs(self) -> None:
        """Build the categorized left-side navigation and the stacked pages.

        The navigation uses a ``QListWidget`` (with disabled header items to
        visually group the entries) driving a ``QStackedWidget`` on the
        right.  Entries under *BKPS Setup* and *BKP Onboarding /
        Provisioning* groups form a sequential guided-setup chain — each
        gated tab only becomes selectable once every step in the previous
        pipeline group has been marked SUCCESS.  Debug lives under
        *Utilities* and is always accessible; it does not participate in
        the progress bar.  Administration content has been folded into the
        Server tab (below the guided pipeline) for manual triggering.
        """
        # ── Left navigation list (categorized) ────────────────────────
        self._nav = QListWidget()
        self._nav.setFixedWidth(260)
        self._nav.setSpacing(2)
        self._nav.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._nav.setStyleSheet(
            "QListWidget { background: #1e1e1e; border: none; padding: 6px; }"
            "QListWidget::item { padding: 6px 10px; border-radius: 3px; }"
            "QListWidget::item:selected { background: #3d5a8a; color: white; }"
            "QListWidget::item:hover:!selected { background: #2a2a2a; }"
            "QListWidget::item:disabled { color: #777; }"
        )

        # ── Right page stack ──────────────────────────────────────────
        self._pages = QStackedWidget()

        # Track nav-index → gate-group and nav-index → page-widget so we
        # can toggle enable-state without recomputing on every event.
        self._nav_gate: dict[int, str] = {}
        self._nav_page: dict[int, QWidget] = {}

        for entry in self._NAV_ENTRIES:
            if entry[0] == "__header__":
                _, header_text, kind = entry
                item = QListWidgetItem(header_text)
                item.setFlags(Qt.ItemFlag.NoItemFlags)
                f = item.font()
                f.setBold(True)
                # Utilities header: dim + smaller.
                item.setForeground(QColor("#6a6a6a"))
                f.setPointSizeF(max(1.0, f.pointSizeF() - 1.0))
                item.setFont(f)
                self._nav.addItem(item)
                # Placeholder page keeps stack indices aligned with nav rows.
                self._pages.addWidget(QWidget())
                continue

            label, cls_name, attr, gated_on, kind = entry
            tab_cls = self._TAB_CLASSES[cls_name]
            tab = tab_cls(self._store, self._capture)
            setattr(self, attr, tab)

            item = QListWidgetItem(label)
            f = item.font()
            if kind == "flow":
                # Prominent: bold, slightly larger, warm accent colour so
                # the guided path visually dominates the nav.
                f.setBold(True)
                f.setPointSizeF(f.pointSizeF() + 1.0)
                item.setForeground(QColor("#f5c26b"))
                # A little extra vertical padding via the size hint so
                # flow items look chunkier than utility rows.
                hint = item.sizeHint()
                hint.setHeight(hint.height() + 6)
                item.setSizeHint(hint)
            else:
                f.setPointSizeF(max(1.0, f.pointSizeF() - 0.5))
                item.setForeground(QColor("#bcbcbc"))
            item.setFont(f)

            self._nav.addItem(item)
            self._pages.addWidget(tab)
            idx = self._nav.count() - 1
            self._nav_page[idx] = tab
            if gated_on is not None:
                self._nav_gate[idx] = gated_on

        self._nav.currentRowChanged.connect(self._on_nav_row_changed)

        # Select the first selectable entry so the app starts on Config.
        for i in range(self._nav.count()):
            it = self._nav.item(i)
            if it and (it.flags() & Qt.ItemFlag.ItemIsSelectable):
                self._nav.setCurrentRow(i)
                break

        # ── Assemble central widget: stepper + nav | pages + bar ──────
        central = QWidget()
        outer = QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Guided-flow stepper (Config → Setup → BKP) sits on top so the
        # operator sees the linked phases at a glance and can click any
        # card to jump to it.
        outer.addWidget(self._build_phase_stepper())

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._nav)
        # Thin separator between nav and page area.
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setFrameShadow(QFrame.Shadow.Sunken)
        body.addWidget(sep)
        body.addWidget(self._pages, stretch=1)
        outer.addLayout(body, stretch=1)

        bar_row = QHBoxLayout()
        bar_row.setContentsMargins(6, 2, 6, 4)
        bar_row.setSpacing(6)
        self._pipeline_label = QLabel("Progress:")
        self._pipeline_label.setStyleSheet("color:#aaa; font-size:9pt;")
        bar_row.addWidget(self._pipeline_label)

        self._pipeline_bar = QProgressBar()
        self._pipeline_bar.setRange(0, max(1, self.pipeline.total()))
        self._pipeline_bar.setValue(0)
        self._pipeline_bar.setFormat("%v / %m steps  (%p%)")
        self._pipeline_bar.setTextVisible(True)
        self._pipeline_bar.setFixedHeight(18)
        bar_row.addWidget(self._pipeline_bar, stretch=1)
        outer.addLayout(bar_row)

        self.setCentralWidget(central)

    # ------------------------------------------------------------------
    # Phase stepper (Config → Setup → BKP Onboarding / Provisioning)
    # ------------------------------------------------------------------

    def _build_phase_stepper(self) -> QWidget:
        """Return a horizontal card-stepper showing the three guided phases.

        Each card is a ``_PhaseCard`` (clickable) and pairs are joined by
        a ``_PhaseConnector`` chevron.  The stepper is the primary visual
        cue for "run these in order" — the connectors turn green as each
        upstream phase completes so the operator can literally see the
        flow being consumed.
        """
        wrap = QFrame()
        wrap.setStyleSheet(
            "QFrame { background:#141414; border-bottom:1px solid #333; }"
        )
        v = QVBoxLayout(wrap)
        v.setContentsMargins(10, 8, 10, 8); v.setSpacing(4)

        title = QLabel("Guided setup: complete stages 1–4 from left to right.")
        title.setStyleSheet("color:#888; font-size:11pt; background:transparent;")
        v.addWidget(title)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0); row.setSpacing(6)

        self._phase_cards: dict[str, _PhaseCard] = {}
        self._phase_connectors: list[_PhaseConnector] = []

        phases = [
            (1, "Config",                        "Apply your device / paths",       "_tab_config"),
            (2, "BKPS Setup",                    "BKPS + Database Installation",    "_tab_setup"),
            (3, "BKPS Configuration",            "AES ccert+ BKPS configuration",   "_tab_bkp_config"),
            (4, "BKP Onboarding/Provision",      "BKP Onboarding + BKP Provision",  "_tab_bkp"),
        ]
        for i, (num, title_text, subtitle, attr) in enumerate(phases):
            card = _PhaseCard(num, title_text, subtitle, attr)
            card.clicked.connect(self._jump_to_tab_by_attr)
            self._phase_cards[attr] = card
            row.addWidget(card, stretch=1)
            if i < len(phases) - 1:
                conn = _PhaseConnector()
                self._phase_connectors.append(conn)
                row.addWidget(conn)

        v.addLayout(row)
        return wrap

    def _jump_to_tab_by_attr(self, attr: str) -> None:
        """Navigate the left nav to the tab stored on ``self.<attr>``."""
        target = getattr(self, attr, None)
        if target is None:
            return
        for idx, tab in self._nav_page.items():
            if tab is target:
                self._nav.setCurrentRow(idx)
                return

    def _refresh_phase_stepper(self) -> None:
        """Update card + connector colours based on live pipeline state."""
        cards = getattr(self, "_phase_cards", None)
        if not cards:
            return
        applied = self._prior_apply_marker() or getattr(
            getattr(self, "_tab_setup", None), "_config_applied", False
        )

        # Config phase — done once Apply Changes has been clicked (or the
        # legacy marker is on disk); otherwise active on first launch.
        cards["_tab_config"].set_state("done" if applied else "active")

        # BKPS Setup — active as soon as Config is applied, done once
        # every step in installation + server is SUCCESS.
        setup_done = all(
            self.pipeline.is_group_complete(g) for g in ("installation", "server")
        )
        cards["_tab_setup"].set_state(
            "done" if setup_done else ("active" if applied else "pending")
        )

        # BKP Config phase — active once Setup is done, done when both
        # AES and Configuration groups are SUCCESS.
        prep_done = all(
            self.pipeline.is_group_complete(g) for g in ("aes", "configuration")
        )
        cards["_tab_bkp_config"].set_state(
            "done" if prep_done else ("active" if setup_done else "pending")
        )

        # BKP Provisioning phase — active once Prep is done, done when
        # every Programming step is SUCCESS.
        prog_done = self.pipeline.is_group_complete("programming")
        cards["_tab_bkp"].set_state(
            "done" if prog_done else ("active" if prep_done else "pending")
        )

        # Connectors: colour each arrow green once the upstream phase is done.
        if len(self._phase_connectors) >= 3:
            self._phase_connectors[0].set_done(applied)
            self._phase_connectors[1].set_done(setup_done)
            self._phase_connectors[2].set_done(prep_done)

    def _on_nav_row_changed(self, row: int) -> None:
        """Sync the page stack when the nav selection changes.

        Disabled (gated) rows should never fire this — Qt already refuses
        to change ``currentRow`` to a non-selectable item — but the guard
        keeps the stack in sync should a stray call arrive.
        """
        if row < 0:
            return
        it = self._nav.item(row)
        if it is None:
            return
        flags = it.flags()
        if not (flags & Qt.ItemFlag.ItemIsSelectable) or not (flags & Qt.ItemFlag.ItemIsEnabled):
            return
        self._pages.setCurrentIndex(row)

    # ------------------------------------------------------------------
    # Status bar
    # ------------------------------------------------------------------

    def _build_status_bar(self) -> None:
        """Create the status bar with Server and DB health indicator labels."""
        sb: QStatusBar = self.statusBar()

        self._lbl_server = QLabel("Server: unknown")
        self._lbl_db     = QLabel("DB: unknown")

        for lbl in (self._lbl_server, self._lbl_db):
            lbl.setStyleSheet("padding: 0 8px; color: #aaa;")
            sb.addPermanentWidget(lbl)

        sb.showMessage("Ready")

    def _start_poll_timer(self) -> None:
        """Start the 10-second timer that fires the health-check probe."""
        self._health_thread: _HealthChecker | None = None
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(10_000)
        self._poll_timer.timeout.connect(self._poll_health)
        self._poll_timer.start()

    def _poll_health(self) -> None:
        """Spawn a background thread for health checks — never blocks the UI."""
        if self._health_thread is not None and self._health_thread.isRunning():
            return  # previous check still in progress; skip this tick

        cfg = self._store.cfg
        db_port = int(cfg.db_port) if cfg.db_port else 5432
        port = int(cfg.bkps_server_port) if cfg.bkps_server_port else 9443
        host = cfg.bkps_server_ip or "localhost"

        self._health_thread = _HealthChecker(
            host, port, db_port,
            cfg.db_user or "", cfg.db_password or "", cfg.db_name or "",
        )
        self._health_thread.result.connect(self._on_health_result)
        self._health_thread.start()

    def _on_health_result(self, srv_ok: bool, db_ok: bool) -> None:
        """Update status-bar labels on the main thread (called via signal)."""
        self._lbl_db.setText("DB: " + ("OK" if db_ok else "offline"))
        self._lbl_db.setStyleSheet(
            f"padding:0 8px; color:{'#50fa7b' if db_ok else '#ff5555'};"
        )
        self._lbl_server.setText("Server: " + ("OK" if srv_ok else "offline"))
        self._lbl_server.setStyleSheet(
            f"padding:0 8px; color:{'#50fa7b' if srv_ok else '#ff5555'};"
        )
        server_ops = getattr(self, "_tab_server_ops", None)
        if server_ops is not None:
            server_ops.set_server_running(srv_ok)

    def closeEvent(self, event) -> None:
        """Stop the poll timer and wait for any running health thread."""
        self._poll_timer.stop()
        server_ops = getattr(self, "_tab_server_ops", None)
        if server_ops is not None:
            server_ops.shutdown()
        if self._health_thread is not None and self._health_thread.isRunning():
            self._health_thread.quit()
            self._health_thread.wait(2000)
        super().closeEvent(event)

    # ------------------------------------------------------------------
    # Guided setup pipeline: progress bar + tab gating
    # ------------------------------------------------------------------

    def _prime_pipeline_from_disk_helper(self, group, sid, cond):
        """Set a step to SUCCESS when the on-disk condition is satisfied."""
        if cond:
            self.pipeline.set_status(group, sid, StepStatus.SUCCESS)

    @staticmethod
    def _artifact_ready(path: str) -> bool:
        """True when *path* exists as a non-empty file."""
        try:
            return os.path.isfile(path) and os.path.getsize(path) > 0
        except OSError:
            return False

    def _prime_group_cascade(self, group: str, evidence: list[bool]) -> None:
        """Mark steps 0..N SUCCESS when step N (or earlier) has on-disk evidence.

        Later pipeline steps imply their prerequisites already ran, so a
        returning operator who stopped mid-flow still sees every completed
        button green — including steps that leave no durable artefact of
        their own (for example ``dependency_setup``).
        """
        steps = [sid for sid, _ in PIPELINE_STEPS[group]]
        farthest = -1
        for i, ok in enumerate(evidence):
            if ok and i < len(steps):
                farthest = i
        for i in range(farthest + 1):
            self.pipeline.set_status(group, steps[i], StepStatus.SUCCESS)

    def _installation_step_evidence(self, cfg, sid: str) -> bool:
        """Return whether *sid* left durable Installation artefacts on disk."""
        import glob as _glob

        bd = getattr(cfg, "bkps_dir", "") or ""
        if not bd:
            return False
        if sid == "dependency_setup":
            # Machine-level step; restored only via cascade from later evidence.
            return False
        if sid == "repo_setup":
            jars = (
                _glob.glob(os.path.join(bd, "*.jar"))
                + _glob.glob(os.path.join(bd, "build", "libs", "*.jar"))
            )
            return any(AppWindow._artifact_ready(path) for path in jars)
        if sid == "security_provider":
            provider = (
                getattr(cfg, "security_provider", "") or "bouncycastle"
            ).strip().lower()
            if provider == "luna":
                return AppWindow._artifact_ready(
                    os.path.join(bd, "config", "application-luna.yml")
                )
            if provider == "ncipher":
                return AppWindow._artifact_ready(
                    os.path.join(bd, "config", "application-ncipher.yml")
                )
            yml_ok = AppWindow._artifact_ready(
                os.path.join(bd, "config", "application-bouncycastle.yml")
            ) or AppWindow._artifact_ready(
                os.path.join(bd, "config", "application-bc.yml")
            )
            jars = _glob.glob(
                os.path.join(bd, "libs-ext", "bcprov-jdk18on-*.jar")
            )
            return yml_ok and any(AppWindow._artifact_ready(path) for path in jars)
        if sid == "ssl_certs":
            required = (
                os.path.join(bd, "keys", "bkps_ssl_cert", "bkps_ssl_cert.crt"),
                os.path.join(bd, "keys", "bkps_ssl_cert", "bkps_ssl_private.pem"),
                os.path.join(bd, "keys", "bkps_ssl_cert", "bkps_ssl.p12"),
                os.path.join(bd, "keys", "super_admin_cert.crt"),
                os.path.join(bd, "keys", "tsci_cert", "tsci_altera_com.pem"),
            )
            return all(AppWindow._artifact_ready(path) for path in required)
        if sid == "bkps_keystore":
            return AppWindow._artifact_ready(
                os.path.join(bd, "keys", "bkps_keystore.p12")
            )
        if sid == "bkps_config":
            profile = getattr(cfg, "profile_name", "") or ""
            if not profile:
                return False
            return AppWindow._artifact_ready(
                os.path.join(bd, "config", f"application-{profile}.yml")
            )
        return False

    def _server_step_evidence(self, cfg, sid: str) -> bool:
        """Return whether *sid* left durable Server-pipeline artefacts on disk."""
        bd = getattr(cfg, "bkps_dir", "") or ""
        qd = getattr(cfg, "quartus_keys_dir", "") or ""
        if sid == "db_reset":
            # No durable project file; restored via cascade.
            return False
        if sid == "super_admin":
            return bool(bd) and AppWindow._artifact_ready(
                os.path.join(bd, "keys", "super_admin_bkps_signed.crt")
            )
        if sid == "auth_keys":
            return bool(qd) and AppWindow._artifact_ready(
                os.path.join(qd, "root0.qky")
            ) and AppWindow._artifact_ready(
                os.path.join(qd, "root0_private.pem")
            )
        if sid == "bkps_keys":
            return bool(qd) and AppWindow._artifact_ready(
                os.path.join(qd, "bkps_import_pubkey.pem")
            )
        return False

    def _prime_pipeline_from_disk(self) -> None:
        """Pre-populate pipeline status from on-disk artifacts.

        This lets a returning user who stopped mid-pipeline (or previously
        completed the flow) see every already-done step marked SUCCESS at
        launch.  Full Setup completion still uses ``check_setup_complete``;
        partial Installation / Server progress is restored per-step with
        cascade so prerequisite buttons that leave no artefact of their
        own also turn green.
        """
        cfg = self._store.cfg
        pl = self.pipeline

        # ── BKPS Setup: Installation + Server ─────────────────────────
        try:
            if check_setup_complete(cfg):
                pl.mark_group_success("installation")
                pl.mark_group_success("server")
            else:
                install_steps = [
                    sid for sid, _ in PIPELINE_STEPS["installation"]
                ]
                AppWindow._prime_group_cascade(
                    self,
                    "installation",
                    [
                        AppWindow._installation_step_evidence(self, cfg, sid)
                        for sid in install_steps
                    ],
                )
                server_steps = [sid for sid, _ in PIPELINE_STEPS["server"]]
                AppWindow._prime_group_cascade(
                    self,
                    "server",
                    [
                        AppWindow._server_step_evidence(self, cfg, sid)
                        for sid in server_steps
                    ],
                )
        except Exception:
            pass

        # ── AES compact certificate group ─────────────────────────────
        try:
            signed_ccert = os.path.join(cfg.quartus_keys_dir,
                                        "signed_aes_efuse.ccert")
            if os.path.isfile(signed_ccert):
                pl.mark_group_success("aes")
        except Exception:
            pass

        # ── Configuration group ───────────────────────────────────────
        # Cascade so a later artefact (e.g. bkp_options.txt) also greens
        # the earlier Create Configuration / Programmer buttons.
        try:
            programmer_outputs = [
                os.path.join(cfg.quartus_keys_dir,
                             "programmer_bkps_signed.crt"),
                os.path.join(cfg.quartus_keys_dir,
                             "programmer_private.pem"),
            ]
            if sys.platform.startswith("win"):
                programmer_outputs.append(
                    os.path.join(cfg.quartus_keys_dir, "programmer.pfx")
                )
            programmer_ok = all(
                AppWindow._artifact_ready(path) for path in programmer_outputs
            )
            bkp_opts = os.path.join(cfg.cm_provisioning_dir, "bkp_options.txt")
            AppWindow._prime_group_cascade(
                self,
                "configuration",
                [
                    bool(read_config_id(cfg)),
                    programmer_ok,
                    AppWindow._artifact_ready(bkp_opts),
                ],
            )
        except Exception:
            pass

        # ── Programming group ─────────────────────────────────────────
        # Only the JIC-generation step produces a persistent artefact.
        # The other steps require live JTAG so are left PENDING; PUF-related
        # steps that don't apply to the current device family are marked
        # SUCCESS below so they don't gate the pipeline.
        try:
            import glob as _glob
            jic_dir = os.path.join(cfg.cm_provisioning_dir, "device_onboarding")
            if _glob.glob(os.path.join(jic_dir, "*.jic")):
                pl.set_status("programming", "generate_jic", StepStatus.SUCCESS)
        except Exception:
            pass
        try:
            from bkps_config import PUF_TYPES
            profile = getattr(cfg, "profile_name", "") or ""
            puf_cfg = PUF_TYPES.get(profile, {})
            if "puf_activate" not in puf_cfg:
                pl.set_status("programming", "puf_activate", StepStatus.SUCCESS)
            if "set_authority" not in puf_cfg:
                pl.set_status("programming", "set_authority", StepStatus.SUCCESS)
        except Exception:
            pass

    def _on_pipeline_changed(self, group: str, step_id: str, status: str) -> None:
        """React to a single-step status transition anywhere in the pipeline.

        Also re-runs gating on every combined tab so a downstream tab's
        cross-tab prerequisite lockout (``_prereq_groups``) reacts even
        to a single-step transition — e.g. a Server step that regresses
        from SUCCESS back to FAILED immediately re-locks every button
        on BKP Config and BKP Provisioning.
        """
        self._refresh_progress_bar()
        self._refresh_phase_stepper()
        for attr in ("_tab_setup", "_tab_bkp_config", "_tab_bkp"):
            tab = getattr(self, attr, None)
            if tab is not None and hasattr(tab, "refresh_pipeline_gating"):
                tab.refresh_pipeline_gating()

    def _on_project_loaded(self) -> None:
        """Rebuild guided-flow state after the operator loads another project."""
        self._restore_project_state(reset=True)

    def _restore_project_state(self, *, reset: bool) -> None:
        """Restore gates from persistent artifacts for the active project.

        An unfinished project remains protected because no group is marked
        successful unless its expected outputs exist.  A completed project
        restores Installation + Server and can continue at BKPS Configuration.
        """
        if reset:
            self.pipeline.reset()
            self._clear_config_applied()
        self._prime_pipeline_from_disk()
        if self._prior_apply_marker():
            self._on_config_applied()
        self._refresh_progress_bar()
        self._refresh_tab_gating()
        self._refresh_phase_stepper()
        # Always re-apply button colours after priming so a reopen shows
        # completed steps green even when Apply Changes was already set
        # before any status transition signal ran.
        for attr in ("_tab_setup", "_tab_bkp_config", "_tab_bkp"):
            tab = getattr(self, attr, None)
            if tab is not None and hasattr(tab, "refresh_pipeline_gating"):
                tab.refresh_pipeline_gating()

    def _clear_config_applied(self) -> None:
        """Relock actions before evaluating a newly loaded project config."""
        for attr in ("_tab_setup", "_tab_bkp_config", "_tab_bkp",
                     "_tab_server_ops", "_tab_server_util",
                     "_tab_aes_util", "_tab_cfg_util"):
            tab = getattr(self, attr, None)
            if tab is None:
                continue
            if hasattr(tab, "on_config_cleared"):
                tab.on_config_cleared()
            elif hasattr(tab, "_config_applied"):
                tab._config_applied = False
            if hasattr(tab, "refresh_pipeline_gating"):
                tab.refresh_pipeline_gating()
            for button in getattr(tab, "_util_buttons", None) or []:
                button.setEnabled(False)

    def _on_pipeline_group_completed(self, group: str) -> None:
        """React to a pipeline group finishing.

        The combined Setup / BKP tabs already refresh their own gating
        after every step, but we also poke them here so the cross-flow
        unlock (e.g. Installation finished → enable first Server button)
        applies even if the pipeline state was changed programmatically
        (priming from disk, etc.).
        """
        self._refresh_tab_gating()
        for attr in ("_tab_setup", "_tab_bkp_config", "_tab_bkp"):
            tab = getattr(self, attr, None)
            if tab is not None and hasattr(tab, "refresh_pipeline_gating"):
                tab.refresh_pipeline_gating()
        self._refresh_phase_stepper()

    def _refresh_progress_bar(self) -> None:
        """Sync the bottom progress bar with ``self.pipeline`` counters."""
        total = max(1, self.pipeline.total())
        done = self.pipeline.completed()
        self._pipeline_bar.setRange(0, total)
        self._pipeline_bar.setValue(done)
        # Colour the chunk green on completion, orange during progress.
        colour = "#27ae60" if done == total else "#f39c12"
        self._pipeline_bar.setStyleSheet(
            f"QProgressBar {{ border: 1px solid #444; border-radius: 3px; "
            f"background: #222; color: #eee; }} "
            f"QProgressBar::chunk {{ background: {colour}; }}"
        )

    def _on_config_applied(self) -> None:
        """Handle Config → Apply Changes: unlock pipeline + utility buttons.

        Every downstream tab exposes an ``on_config_applied`` method that
        flips its internal ``_config_applied`` flag and re-runs its own
        gating logic.  The nav rows themselves are always previewable —
        this only enables the *buttons* on those tabs.
        """
        for attr in ("_tab_setup", "_tab_bkp_config", "_tab_bkp",
                     "_tab_server_ops", "_tab_server_util",
                     "_tab_aes_util", "_tab_cfg_util"):
            tab = getattr(self, attr, None)
            if tab is not None and hasattr(tab, "on_config_applied"):
                tab.on_config_applied()
        self._refresh_phase_stepper()

    def _prior_apply_marker(self) -> bool:
        """Return True when a previous session already completed setup.

        The marker is accepted only together with the final Setup artifacts.
        This avoids unlocking a project whose marker was copied without its
        certificates, or whose setup outputs were removed after completion.
        """
        try:
            marker = os.path.join(self._store.cfg.bkps_dir, ".bkps_setup_complete")
            return (
                bool(self._store.cfg.bkps_dir)
                and os.path.isfile(marker)
                and check_setup_complete(self._store.cfg)
            )
        except Exception:
            return False

    def _refresh_tab_gating(self) -> None:
        """Refresh nav tooltips based on pipeline group completion.

        Every tab is always previewable — the operator can click through
        the whole workflow to inspect what each tab looks like without
        having to complete earlier steps first.  When a tab's upstream
        pipeline group hasn't finished yet, we keep the row enabled but
        surface a tooltip pointing at the group that still owes work so
        the guided-flow order stays discoverable.
        """
        pl = self.pipeline
        base_flags = Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled
        for idx, gate in self._nav_gate.items():
            item = self._nav.item(idx)
            if item is None:
                continue
            item.setFlags(base_flags)
            if pl.is_group_complete(gate):
                item.setToolTip("")
            else:
                item.setToolTip(
                    f"Preview enabled — complete every step in the '{gate}' "
                    f"pipeline before running the guided flow on this page."
                )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _load_config(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Config", "", "Config files (*.conf *.cfg);;All files (*)"
        )
        if path:
            try:
                self._store.load(path)
                self._tab_config.refresh_fields()
                self._on_project_loaded()
                self.statusBar().showMessage(f"Config loaded: {path}", 5000)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load config:\n{e}")

    def _save_config(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Config", self._store.cfg.config_file or "",
            "Config files (*.conf);;All files (*)"
        )
        if path:
            try:
                self._store.save(path)
                self.statusBar().showMessage(f"Config saved: {path}", 5000)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save config:\n{e}")

    def _show_about(self) -> None:
        QMessageBox.about(
            self, "About Black Key Provisioning Automation Studio",
            "<b>Black Key Provisioning Automation Studio</b><br>"
            "PySide6 front-end for Intel BKPS provisioning workflow.<br><br>"
            "Python modules: <tt>bkps_py/</tt><br>"
            "GUI: <tt>bkps_gui/</tt>",
        )

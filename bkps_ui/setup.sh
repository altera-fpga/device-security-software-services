#!/usr/bin/env bash
# =============================================================================
# setup.sh — Prepare BKPS tool runtime on Linux.
#
# Supported distributions:
#   Ubuntu / Debian / Linux Mint (apt)
#   RHEL / CentOS / Fedora / Rocky / AlmaLinux (dnf / yum)
#
# Usage:
#   chmod +x setup.sh && ./setup.sh
#
# What it does:
#   1. Installs Python + display system libraries (including Xvfb for headless)
#   2. Creates a local virtual environment (.venv)
#   3. Installs Python dependencies from requirements.txt (includes PySide6 GUI)
#   4. Verifies core imports
#   5. Generates run.sh to launch BKPS GUI or CLI
#
# Headless / server installs:
#   The GUI is always installed. On headless systems the script installs Xvfb
#   (virtual framebuffer X server) so the GUI can be used over X11 forwarding,
#   VNC, or Xvfb virtual display. See run.sh for details.
#
# Windows users: use setup.bat instead.
# =============================================================================

set -e

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }
header()  { echo -e "\n${BOLD}── $* ──${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
REQ_FILE="$SCRIPT_DIR/requirements.txt"
RUN_SH="$SCRIPT_DIR/run.sh"

FAILED=()

header "BKPS setup"
info "Working directory: $SCRIPT_DIR"

# ── Distro / package manager detection ───────────────────────────────────────
DISTRO_NAME="Unknown"
if [[ -f /etc/os-release ]]; then
    DISTRO_NAME="$(. /etc/os-release && echo "${PRETTY_NAME:-$NAME}")"
elif command -v lsb_release &>/dev/null; then
    DISTRO_NAME="$(lsb_release -ds 2>/dev/null)"
fi

if command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
    info "Detected OS: ${DISTRO_NAME} (Debian/Ubuntu family)"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
    info "Detected OS: ${DISTRO_NAME} (RHEL/Fedora family — using dnf)"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"
    info "Detected OS: ${DISTRO_NAME} (RHEL/CentOS family — using yum)"
else
    error "No supported package manager found (apt / dnf / yum)."
    error "On Windows, use setup.bat instead of this script."
    error "For other systems: install Python 3.8+, pip, and venv manually, then re-run."
    exit 1
fi

# ── Headless notice ───────────────────────────────────────────────────────────
IS_HEADLESS=0
if [[ -z "${DISPLAY:-}" && -z "${WAYLAND_DISPLAY:-}" ]]; then
    IS_HEADLESS=1
    warn "No display detected — headless environment."
    info "The GUI will be installed and can be accessed via:"
    info "  • X11 forwarding   : ssh -X user@$(hostname) && ./run.sh"
    info "  • Xvfb (virtual)   : Xvfb will be installed; run.sh starts it automatically"
    info "  • VNC              : install a VNC server (tigervnc-server / xrdp)"
    echo
fi

echo
read -r -p "Continue with setup? [y/N] " REPLY
if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
    info "Aborted."
    exit 0
fi

# =============================================================================
# 1. Install system packages
# =============================================================================
header "Installing system packages"
if [[ "$PKG_MGR" == "apt" ]]; then
    sudo apt-get update -qq
    # Python runtime
    sudo apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv
    # Qt / PySide6 display runtime libraries
    sudo apt-get install -y --no-install-recommends \
        libgl1 libegl1 libglib2.0-0 libdbus-1-3 \
        libfontconfig1 libfreetype6 \
        libx11-6 libxext6 libxrender1 libxcb1 \
        || warn "Some display libraries could not be installed (minimal image?)."
    # Virtual display for headless (Xvfb)
    if [[ "$IS_HEADLESS" -eq 1 ]]; then
        sudo apt-get install -y --no-install-recommends xvfb \
            || warn "Xvfb not available — GUI will require X11 forwarding or VNC."
    fi

elif [[ "$PKG_MGR" == "dnf" ]]; then
    sudo dnf install -y python3 python3-pip
    # python3-venv bundled in python3 on RHEL 8+; fall back to virtualenv if needed
    python3 -m venv --help &>/dev/null || sudo dnf install -y python3-virtualenv
    # Qt / PySide6 display runtime libraries
    sudo dnf install -y \
        mesa-libGL mesa-libEGL glib2 dbus-libs fontconfig freetype \
        libX11 libXext libXrender libxcb \
        || warn "Some display libraries could not be installed."
    if [[ "$IS_HEADLESS" -eq 1 ]]; then
        sudo dnf install -y xorg-x11-server-Xvfb \
            || warn "Xvfb not available — GUI will require X11 forwarding or VNC."
    fi

elif [[ "$PKG_MGR" == "yum" ]]; then
    sudo yum install -y python3 python3-pip
    python3 -m venv --help &>/dev/null || sudo yum install -y python3-virtualenv
    sudo yum install -y \
        mesa-libGL mesa-libEGL glib2 dbus-libs fontconfig freetype \
        libX11 libXext libXrender libxcb \
        || warn "Some display libraries could not be installed."
    if [[ "$IS_HEADLESS" -eq 1 ]]; then
        sudo yum install -y xorg-x11-server-Xvfb \
            || warn "Xvfb not available — GUI will require X11 forwarding or VNC."
    fi
fi
success "System packages installed."

# =============================================================================
# 1b. Install SoftHSM2 + PKCS#11 tools (required for SPDM devices, e.g. Agilex 5)
# =============================================================================
header "Installing SoftHSM2 + PKCS#11 tools (SPDM)"
if [[ "$PKG_MGR" == "apt" ]]; then
    sudo apt-get install -y --no-install-recommends \
        softhsm2 opensc pcscd libpcsclite-dev \
        || warn "Some SoftHSM/PKCS#11 packages could not be installed."
elif [[ "$PKG_MGR" == "dnf" ]]; then
    sudo dnf install -y \
        softhsm opensc pcsc-lite pcsc-lite-devel \
        || warn "Some SoftHSM/PKCS#11 packages could not be installed."
elif [[ "$PKG_MGR" == "yum" ]]; then
    sudo yum install -y \
        softhsm opensc pcsc-lite pcsc-lite-devel \
        || warn "Some SoftHSM/PKCS#11 packages could not be installed."
fi

for tool in softhsm2-util pkcs11-tool; do
    if command -v "$tool" &>/dev/null; then
        success "$tool installed"
    else
        warn "$tool not found — SoftHSM/PKCS#11 operations will not work"
        FAILED+=("tool:$tool")
    fi
done

# PKCS#11 providers are commonly absent from ldconfig because applications
# load them directly by path. Check the package layouts used by Debian
# multiarch, Ubuntu, RHEL, and local installations instead.
SOFTHSM_PROVIDER=""
for candidate in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/*/softhsm/libsofthsm2.so \
    /usr/lib64/softhsm/libsofthsm2.so \
    /usr/local/lib/softhsm/libsofthsm2.so
do
    if [[ -f "$candidate" ]]; then
        SOFTHSM_PROVIDER="$(readlink -f "$candidate")"
        break
    fi
done

if [[ -n "$SOFTHSM_PROVIDER" ]]; then
    success "SoftHSM PKCS#11 library found: $SOFTHSM_PROVIDER"
else
    warn "SoftHSM PKCS#11 library not found in standard or multiarch paths"
    FAILED+=("library:libsofthsm2.so")
fi

# The tool uses its own per-user configuration and token directory rather
# than the system store, so a missing user configuration is not a failure.
# It is created by the dependency-setup step.
USER_SOFTHSM_CONFIG="$HOME/.config/softhsm2/softhsm2.conf"
if [[ -f "$USER_SOFTHSM_CONFIG" ]]; then
    success "SoftHSM user configuration: $USER_SOFTHSM_CONFIG"
else
    info "SoftHSM user configuration will be created on dependency setup:"
    info "  $USER_SOFTHSM_CONFIG"
fi

# =============================================================================
# 2. Create virtual environment
# =============================================================================
header "Creating virtual environment"
if [[ ! -f "$VENV_DIR/bin/activate" ]]; then
    python3 -m venv "$VENV_DIR"
    success "Created venv: $VENV_DIR"
else
    info "Using existing venv: $VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

# =============================================================================
# 3. Install Python dependencies
# =============================================================================
header "Installing Python dependencies"
python3 -m pip install --upgrade pip --quiet

if [[ -f "$REQ_FILE" ]]; then
    python3 -m pip install --upgrade -r "$REQ_FILE"
    success "Installed requirements from: $REQ_FILE"
else
    warn "requirements.txt not found, installing fallback packages"
    python3 -m pip install --upgrade \
        PySide6 docopt cryptography pyOpenSSL \
        pycryptodome psycopg2-binary requests packaging
fi

# =============================================================================
# 4. Verify imports
# =============================================================================
header "Verification"

check_py_pkg() {
    if python3 -c "import $1" &>/dev/null; then
        VER=$(python3 -c "import $1; print(getattr($1, '__version__', 'ok'))" 2>/dev/null)
        success "python import $1 — $VER"
    else
        warn "python import $1 — FAILED"
        FAILED+=("python:$1")
    fi
}

check_py_pkg PySide6
check_py_pkg docopt
check_py_pkg cryptography
check_py_pkg requests
check_py_pkg packaging
check_py_pkg psycopg2
check_py_pkg OpenSSL
check_py_pkg Crypto

# =============================================================================
# 5. Generate run.sh
# =============================================================================
header "Generating run.sh"

cat > "$RUN_SH" <<'RUNEOF'
#!/usr/bin/env bash
# run.sh — Launch BKPS Demo Automation (GUI or CLI).
# Generated by setup.sh — re-run setup.sh to regenerate.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "$SCRIPT_DIR/.venv/bin/activate" ]]; then
    echo "[ERROR] Missing virtual environment: $SCRIPT_DIR/.venv"
    echo "Run: ./setup.sh"
    exit 1
fi

source "$SCRIPT_DIR/.venv/bin/activate"

# CLI mode — no display required
if [[ "$1" == "--cli" ]]; then
    shift
    exec python3 "$SCRIPT_DIR/bkps_main.py" "$@"
fi

# GUI mode — ensure a display is available
if [[ -z "${DISPLAY:-}" && -z "${WAYLAND_DISPLAY:-}" ]]; then
    if command -v Xvfb &>/dev/null; then
        # Start a virtual framebuffer on an unused display number
        XVFB_DISP=":99"
        if ! xdpyinfo -display "$XVFB_DISP" &>/dev/null 2>&1; then
            Xvfb "$XVFB_DISP" -screen 0 1280x800x24 -ac +extension GLX &>/dev/null &
            XVFB_PID=$!
            sleep 1
            echo "[INFO] Started Xvfb virtual display on $XVFB_DISP (PID: $XVFB_PID)"
        else
            echo "[INFO] Reusing existing display $XVFB_DISP"
        fi
        export DISPLAY="$XVFB_DISP"
    else
        echo "[WARN] No display detected and Xvfb is not installed."
        echo ""
        echo "Options to access the BKPS GUI from a headless server:"
        echo "  1. X11 forwarding (recommended):"
        echo "       ssh -X $(whoami)@$(hostname)"
        echo "       ./run.sh"
        echo ""
        echo "  2. Install Xvfb (virtual display, run locally):"
        echo "       Ubuntu/Debian: sudo apt-get install -y xvfb"
        echo "       RHEL/Fedora:   sudo dnf install -y xorg-x11-server-Xvfb"
        echo "       Then re-run: ./run.sh"
        echo ""
        echo "  3. VNC / RDP (persistent remote desktop):"
        echo "       Ubuntu: sudo apt-get install -y tigervnc-standalone-server"
        echo "       RHEL:   sudo dnf install -y tigervnc-server"
        echo "       or:     sudo dnf install -y xrdp && sudo systemctl start xrdp"
        echo ""
        echo "  4. CLI mode (no display needed):"
        echo "       ./run.sh --cli --help"
        echo ""
        echo "Setting QT_QPA_PLATFORM=offscreen as fallback (GUI runs but is not visible)."
        export QT_QPA_PLATFORM=offscreen
    fi
fi

exec python3 "$SCRIPT_DIR/gui/main.py" "$@"
RUNEOF

chmod +x "$RUN_SH"
success "run.sh written: $RUN_SH"

echo
if [[ ${#FAILED[@]} -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}BKPS setup completed successfully.${NC}"
else
    echo -e "${YELLOW}${BOLD}BKPS setup completed with warnings.${NC}"
    for item in "${FAILED[@]}"; do
        echo "  • $item"
    done
fi

echo
echo "To start BKPS GUI:"
echo "  $RUN_SH"
if [[ "$IS_HEADLESS" -eq 1 ]]; then
    echo ""
    echo "Headless access options:"
    if command -v Xvfb &>/dev/null; then
        echo "  • Xvfb installed — run.sh will start a virtual display automatically"
    else
        echo "  • X11 forwarding: ssh -X $(whoami)@$(hostname) && ./run.sh"
        echo "  • Install Xvfb:   sudo apt-get install -y xvfb  (then ./run.sh)"
    fi
fi
echo ""
echo "To use BKPS CLI (no display required):"
echo "  $RUN_SH --cli --help"

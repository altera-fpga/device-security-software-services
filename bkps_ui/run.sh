#!/usr/bin/env bash
# run.sh — Launch BKPS Demo Automation (GUI or CLI).
# Re-run setup.sh to regenerate this file.
#
# Usage:
#   ./run.sh                        Launch GUI
#   ./run.sh --cli --help           BKPS CLI help
#   ./run.sh --cli --status         Run CLI command

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "$SCRIPT_DIR/.venv/bin/activate" ]]; then
    echo "[ERROR] Missing virtual environment: $SCRIPT_DIR/.venv"
    echo "Run: ./setup.sh"
    exit 1
fi

source "$SCRIPT_DIR/.venv/bin/activate"

# ── CLI mode — no display required ───────────────────────────────────────────
if [[ "$1" == "--cli" ]]; then
    shift
    exec python3 "$SCRIPT_DIR/bkps_main.py" "$@"
fi

# ── GUI mode — ensure a display is available ─────────────────────────────────
if [[ -z "${DISPLAY:-}" && -z "${WAYLAND_DISPLAY:-}" ]]; then

    if command -v Xvfb &>/dev/null; then
        # Start a virtual framebuffer on display :99 if not already running
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
        echo ""
        echo "  1. X11 forwarding (recommended, no extra install needed):"
        echo "       ssh -X $(whoami)@$(hostname)"
        echo "       ./run.sh"
        echo ""
        echo "  2. Install Xvfb (virtual display — GUI runs locally, invisible):"
        echo "       Ubuntu/Debian:  sudo apt-get install -y xvfb"
        echo "       RHEL/Fedora:    sudo dnf install -y xorg-x11-server-Xvfb"
        echo "       Then re-run:    ./run.sh"
        echo ""
        echo "  3. VNC (persistent remote desktop, visible over any VNC client):"
        echo "       Ubuntu:  sudo apt-get install -y tigervnc-standalone-server"
        echo "       RHEL:    sudo dnf install -y tigervnc-server"
        echo "       or RDP:  sudo dnf install -y xrdp && sudo systemctl start xrdp"
        echo ""
        echo "  4. CLI mode (no display needed at all):"
        echo "       ./run.sh --cli --help"
        echo ""
        echo "Setting QT_QPA_PLATFORM=offscreen as last-resort fallback."
        export QT_QPA_PLATFORM=offscreen
    fi
fi

exec python3 "$SCRIPT_DIR/gui/main.py" "$@"

#!/usr/bin/env bash
# =============================================================================
# run_unit_tests.sh — Run bkps_ui Python unit tests (CI / local).
#
# Usage:
#   ./run_unit_tests.sh              # tests/ suite (Qt tests skip if libs missing)
#   ./run_unit_tests.sh --cli-only   # skip hard PySide6/GUI modules
#
# Creates .venv if missing, installs deps, runs unittest discover.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CLI_ONLY=0
LOG_FILE="${UNITTEST_LOG:-unittest.log}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cli-only) CLI_ONLY=1; shift ;;
    --log) LOG_FILE="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

python3 -m pip install -U pip
if [[ "$CLI_ONLY" -eq 1 ]]; then
  python3 -m pip install -r requirements-cli.txt
else
  python3 -m pip install -r requirements.txt
  export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}"
fi

export PYTHONPATH="${SCRIPT_DIR}:${SCRIPT_DIR}/gui${PYTHONPATH:+:$PYTHONPATH}"

# Modules that import PySide6/GUI at load time (fail without Qt).
GUI_HARD_MODULES=(
  test_bkps_utils
  test_gui_restart_state
  test_log_panel_capacity
  test_release_fetch_combo
  test_server_operations
)

run_discover() {
  python3 -m unittest discover -s tests -p 'test_*.py' -v
}

run_cli_only() {
  local mods=()
  local f
  for f in tests/test_*.py; do
    local mod="${f##*/}"
    mod="${mod%.py}"
    local skip=0
    local hard
    for hard in "${GUI_HARD_MODULES[@]}"; do
      if [[ "$mod" == "$hard" ]]; then
        skip=1
        break
      fi
    done
    if [[ "$skip" -eq 0 ]]; then
      mods+=("tests.${mod}")
    fi
  done
  echo "CLI-only: running ${#mods[@]} modules (skipped ${#GUI_HARD_MODULES[@]} GUI modules)"
  python3 -m unittest "${mods[@]}" -v
}

echo "Running bkps_ui unit tests (cli_only=${CLI_ONLY}) ..."
set +e
if [[ "$CLI_ONLY" -eq 1 ]]; then
  run_cli_only 2>&1 | tee "$LOG_FILE"
else
  run_discover 2>&1 | tee "$LOG_FILE"
fi
rc=${PIPESTATUS[0]}
set -e

deactivate || true
exit "$rc"

# BKPS Demo Automation Tool

Automation tool for Intel BKPS (Black Key Provisioning Service) demonstrations.

## Quick Start

### 1. First-Time Setup

**Linux / macOS:**

```bash
cd Tools/bkps
chmod +x setup.sh
./setup.sh
```

**Windows:**

```bat
cd Tools\bkps
setup.bat
```

Both scripts will:
- Detect the OS/runtime environment and check tool availability
- Create a `.venv` virtual environment in `Tools/bkps`
- Install Python packages from `requirements.txt`

The Automation Studio directory and the BKPS project directory are independent:

- The tool locates its own scripts and `.venv` relative to the launcher.
- The operator selects **BKPS Project Dir** in the Configuration tab.
- Generated server files, logs, keys, provisioning files, and the default source
  checkout are placed under that project directory, not under the tool source.
- Configuration paths may be absolute or relative to the configuration file.
- `BKPS_PROJECT_ROOT` may set the CLI default project directory; the GUI always
  requires an explicit operator-selected project directory.

Platform-specific behavior:
- `setup.sh` (Linux/macOS): installs required system packages via `apt`/`dnf`/`yum`, including GUI runtime libraries and SoftHSM/PKCS#11 tools.
- `setup.bat` (Windows): checks required system tools and attempts to install missing tools via `winget` when available, including PostgreSQL, OpenSC, and OpenSSL. It installs a pinned and validated SoftHSM demo runtime per user. Quartus tools remain manual.

### 2. Launch the GUI

**Linux:**
```bash
./run.sh
```

Or with a config file:
```bash
./run.sh path/to/config.conf
```

**Windows:**
```bat
run.bat
run.bat path\to\config.conf
```

### 3. CLI Usage

**Linux:**
```bash
./run.sh --cli --config <config_file> <command>
# or directly:
python3 bkps_main.py --config <config_file> <command>
```

**Windows:**
```bat
run.bat --cli --config <config_file> <command>
```

Commands use `--option` style, for example:
```
--install-dependencies      Install system tool dependencies
--check-dependencies        Check tool availability
--first-time-installation   Full end-to-end setup
--start-bkps                Start the BKPS server
--stop-bkps                 Stop the BKPS server
--check-health              Check BKPS health
--status                    Show overall status
```

Run `--help` for the full command list.

---

## System Requirements

### Required Tools

| Tool | Description | Installation |
|------|-------------|--------------|
| Python 3.8+ | Runtime | https://python.org |
| Java JDK/JRE | For BKPS server | https://adoptium.net |
| PostgreSQL | Database (`psql`) | https://postgresql.org |
| Quartus Prime | FPGA programming | Intel FPGA website |
| OpenSSL | Certificate operations | https://openssl.org |
| wget, curl | HTTP utilities | Package manager |
| git | Version control | https://git-scm.com |
| jq | JSON processing | Package manager |
| CMake | Native SPDM wrapper configuration | https://cmake.org |
| Visual Studio 2022 C++ Build Tools | Required by the current upstream Windows `build-dependencies.bat` | `setup.bat` installs the standalone MSVC, CMake, and Windows SDK components without the Visual Studio IDE |
| Strawberry Perl | Required by the upstream Windows OpenSSL source build | `setup.bat` installs it through `winget`; upstream currently requires `C:\Strawberry\perl\bin\perl.exe` |

### Setup Automation Notes

- Linux/macOS: `setup.sh` installs Python runtime, GUI runtime libraries, and SoftHSM packages automatically.
- Windows: `setup.bat` can auto-install many missing tools through `winget`, including the standalone Visual Studio 2022 C++ Build Tools components, and then configures `.venv` + Python dependencies.
- If `winget` is unavailable, `setup.bat` reports manual install commands and continues with Python environment setup.
- Quartus Prime tools must be installed manually on all platforms.

### Windows BKPS Source Build

The Automation Studio setup and the cloned BKPS source build are separate:

- `setup.bat` prepares the Automation Studio and host prerequisites only.
- The cloned BKPS repository's `gradlew.bat` builds the BKPS JAR and SQL schema.
- The cloned repository's unmodified `build-dependencies.bat` owns the Windows
  dependency, `libspdm_wrapper.dll`, BKPS JAR, and SQL-schema build. Selection
  is passed as a single `--full` / `--bkp-with-bkpprogrammer` / `--bkp-only`
  flag derived from `BKPS_BUILD_MODE` / `INCLUDE_BKP_PROGRAMMER`.
- The current upstream Windows script requires Visual Studio C++ build tools.
  The Automation Studio discovers them with `BKPS_VS_BUILD_DIR`, an active
  Visual Studio developer environment, or `vswhere.exe`. The Windows setup
  installs the standalone Build Tools workload and required MSVC x64/x86,
  CMake, and Windows SDK components; the Visual Studio IDE is not installed.
- Use `setup.bat --check-msvc` for a non-installing validation or
  `setup.bat --ensure-msvc` to install or repair only the required Build Tools
  components.
- Use `setup.bat --check-java` to validate that the resolved Java runtime is
  version 17 or newer without installing or changing it.
- Use `setup.bat --ensure-strawberry-perl` to install or verify the Perl path
  required by the cloned repository's Windows OpenSSL build.
- No Windows repository overlay is applied. The checked-out repository revision
  is the authoritative source for the Windows build flow.

### Optional Tools

| Tool | Description |
|------|-------------|
| netcat (`nc`) | Port connectivity checks |

### SoftHSM Note

- SoftHSM installation is automated in Linux setup flows (`setup.sh` and dependency-install flow for Agilex 5).
- Windows setup installs a pinned, hash-checked, Authenticode-verified SoftHSM
  demo runtime below the current account's local application-data directory.

### Python Packages

For GUI + CLI installs:
```bash
pip install -r requirements.txt
```

For headless / server installs (no GUI, no display required):
```bash
pip install -r requirements-cli.txt
```

**`requirements.txt` (includes GUI):**
- **PySide6** - GUI framework *(not needed for CLI-only installs)*
- **cryptography** - Cryptographic operations
- **pyOpenSSL** - OpenSSL bindings
- **pycryptodome** - Crypto primitives
- **docopt** - CLI argument parsing
- **requests** - HTTP client
- **packaging** - Version utilities

**`requirements-cli.txt`** adds:
- **psycopg2-binary** - PostgreSQL database connectivity

---

## Directory Structure

```
bkps/
├── setup.sh              # First-time setup (Linux/macOS)
├── setup.bat             # First-time setup (Windows)
├── run.sh                # Launch GUI or CLI (Linux/macOS)
├── run.bat               # Launch GUI or CLI (Windows)
├── setup.py              # Python dependency checker
├── requirements.txt      # Python dependencies (GUI + CLI)
├── requirements-cli.txt  # Python dependencies (CLI / headless only)
├── bkps_main.py          # CLI entry point
├── bkps_config.py        # Config dataclass and device families
├── bkps_server.py        # Server start/stop/health
├── bkps_server_setup.py  # Server installation/configuration
├── bkps_deps.py          # Dependency checks
├── bkps_build.py         # bundle build
├── bkps_keys.py          # Key generation
├── bkps_key_mgmt.py      # Key management (signing/sealing/import)
├── bkps_certs.py         # Certificate operations
├── bkps_configure.py     # BKPS service configuration
├── bkps_database.py      # Database setup and operations
├── bkps_device.py        # Device/JTAG/provisioning operations
├── bkps_users.py         # User management
├── bkps_softhsm.py       # SoftHSM token/key management
├── bkps_status.py        # Status and validation
├── bkps_monitoring.py    # Health monitoring
├── bkps_autosetup.py     # Auto-setup orchestration
├── bkps_audit.py         # Audit utilities
├── bkps_runner.py        # Subprocess utilities
├── bkps_printer.py       # Console output helpers
├── utils/                # GUI helper modules
│   ├── bkps_utils.py     # Qt widget factories (buttons, pickers)
│   ├── pipeline_spec.py # Pipeline step definitions
│   └── ui_helpers.py     # Qt-free helpers used by the GUI
└── gui/
    ├── main.py           # GUI entry point
    ├── app_window.py     # Main window (9 tabs)
    ├── worker.py         # Background worker threads
    ├── log_panel.py      # Per-tab log display
    ├── keystore_viewer.py# Keystore inspection dialog
    ├── tabs/             # Tab implementations
    └── resources/        # Stylesheets, icons
```

---

## Troubleshooting

### "Module not found" errors

Run setup again:

**Linux:** `./setup.sh` or `python setup.py`  
**Windows:** `setup.bat` or `python setup.py`

### Missing system tools

The setup scripts list missing tools and installation instructions.

- On Windows, `setup.bat` will try `winget` first for supported tools.
- If `winget` is missing, install **App Installer** from Microsoft Store, then rerun `setup.bat`.

### GUI doesn't start

Ensure PySide6 is installed and a display is available:
```bash
pip install PySide6
```

On headless Linux, install system display libraries:
```bash
# Ubuntu/Debian
sudo apt-get install -y libgl1 libegl1 libglib2.0-0
# RHEL/Fedora
sudo dnf install -y mesa-libGL mesa-libEGL glib2
```

For server installs without a display, use the CLI only (`requirements-cli.txt`).

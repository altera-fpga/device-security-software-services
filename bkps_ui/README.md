# BKPS Demo Automation Tool

GUI and CLI for Black Key Provisioning Service (BKPS) demonstrations.

- **Tool directory** — `bkps_ui`, including `.venv`.
- **BKPS demo tool project directory** — generated server files, logs, keys, and provisioning files.

## Quick start

### 1. Set up the tool

**Linux** (`apt`, `dnf`, or `yum`):

```bash
cd bkps_ui
chmod +x setup.sh
./setup.sh
```

**Windows:**

```bat
cd bkps_ui
setup.bat
```

`setup.sh` and `setup.bat`:

- Create `.venv` in `bkps_ui`
- Install `requirements.txt` (GUI included)
- `setup.sh` also installs system packages, GUI libraries, and SoftHSM
- `setup.bat` uses `winget` when it is available (PostgreSQL, OpenSSL, OpenSC, pinned SoftHSM)
- Quartus Prime is installed manually

`python setup.py`:

- Checks tools and installs packages into the current interpreter
- First-time setup is `setup.sh` or `setup.bat`
- `--check-only` checks without installing

### 2. Launch the GUI

```bash
./run.sh
./run.sh path/to/bkps_demo_config.conf
```

```bat
run.bat
run.bat path\to\bkps_demo_config.conf
```

- Config path is optional
- With no path, the GUI restores the last loaded or saved config
- The file must already exist

### 3. Run one CLI command

```bash
./run.sh --cli --help
./run.sh --cli --check-health
```

```bat
run.bat --cli --help
run.bat --cli --check-health
```

- `run.sh` and `run.bat` activate `.venv`, then start `bkps_main.py`
- One command per invocation
- `--verbose` (`-v`) and `--yes` (`-y`) may appear anywhere on the line
- `<ANGLE>` required, `[SQUARE]` optional
- Exit codes: `0` success, `1` failure, `2` already exists (step skipped)

## Configuration

The CLI loads one `KEY=VALUE` file:


| Source                    | Config file                                                |
| ------------------------- | ---------------------------------------------------------- |
| `BKPS_CONFIG_FILE` is set | That path                                                  |
| Otherwise                 | `<BKPS demo tool project directory>/bkps_demo_config.conf` |


- Directory is `BKPS_PROJECT_ROOT`, or `~/bkps` when that variable is unset
- Create the file with `./run.sh --cli --create-config`
- Paths in the file may be absolute, or relative to the file
- On the Config page, set this path yourself. It must be absolute.

Repository path:

- `bkps_ui` inside a BKPS source checkout: that checkout
- Otherwise: `<BKPS demo tool project directory>/bkps_repo`

Device profiles:


| Family     | Profile     |
| ---------- | ----------- |
| Agilex 5   | `agilex5`   |
| Agilex 7   | `agilex`    |
| Easic N5X  | `easic_n5x` |
| Stratix 10 | `stratix10` |


## GUI pages

**1. Config**

- Paths and directories: BKPS demo tool project directory, Quartus keys, CM provisioning
- Device, server, and database

**2. BKPS Setup**

Installation:

1. Check/Setup Dependencies
2. Setup BKPS Repository
3. Install Security Provider
4. Create SSL Certificates
5. Create BKPS Keystore
6. Create BKPS Configuration

Server:

1. Initialize / Reset Database
2. Create + Activate Super Admin
3. Create Authentication Keys
4. Configure BKPS Keys

**3. BKPS Configuration**

AES:

1. Init Token (Agilex 5)
2. Create Key (Agilex 5)
3. Create QEK + ccert + Sign

Init Token and Create Key are not required for Agilex 7, Easic N5X, and Stratix 10.

Configuration:

1. Create Configuration
2. Create Programmer User
3. Generate `bkp_options.txt`

**4. BKP Onboarding/Provision**

1. Generate JIC
2. Program Helper Image
3. Program Root Key Hash
4. Program JIC
5. BKP Prefetch
6. BKP PUF Activate
7. Program Helper Image (post-PUF)
8. Program Root Key Hash (post-PUF)
9. BKP Set Authority
10. BKP Provision

- PUF Activate is shown for Agilex 5 and Agilex 7 when the certificate type is not INTERNAL
- Steps 7–8 are hidden for an INTERNAL certificate type, and on Stratix 10
- Set Authority is hidden on Stratix 10
- After PUF Activate, power-cycle the device before step 7

Utilities: Server Control Panel, Server Utilities, AES Utilities, Configuration Utilities, Debug.

## Typical workflow

Installation through configuration follows the `bkps_ui` robot suites. Programming continues through BKP provision. Run one command at a time.

```bash
./run.sh --cli --create-config

# Installation
./run.sh --cli --install-dependencies
./run.sh --cli --check-dependencies
./run.sh --cli --build-all full
./run.sh --cli --auto-detect-prebuilt --save
./run.sh --cli --setup-bkps-server

# Server
./run.sh --cli --initialize-reset-database
./run.sh --cli --start-bkp-service
./run.sh --cli --get-token
./run.sh --cli --create-activate-super-admin <TOKEN>
./run.sh --cli --create-authentication-keys
./run.sh --cli --configure-bkps-keys

# AES
./run.sh --cli --init-token
./run.sh --cli --create-key
./run.sh --cli --create-qek-ccert

# Configuration
./run.sh --cli --create-configuration
./run.sh --cli --create-programmer-user
./run.sh --cli --generate-bkp-options

# Programming
./run.sh --cli --generate-jic <SOF_FILE> <OUT_DIR>
./run.sh --cli --program-helper-image
./run.sh --cli --program-root-key-hash
./run.sh --cli --program-jic <JIC_FILE>
./run.sh --cli --bkp-prefetch
./run.sh --cli --bkp-puf-activate <PUF_TYPE> # power-cycle the device before the post-PUF commands.
./run.sh --cli --program-helper-image
./run.sh --cli --program-root-key-hash
./run.sh --cli --bkp-set-authority
./run.sh --cli --bkp-provision
```

`full` includes the programmer. Other build selections: `bkps_only` (default), `bkps_with_programmer`.

Automated CLI setup (same commands as the automated robot suite):

```bash
./run.sh --cli --create-config
./run.sh --cli --first-time-installation
./run.sh --cli --auto-setup
```

- `--first-time-installation` and `--resume-setup` run the same resume-safe setup
- `--auto-setup` starts the service, reads the token, creates the super admin, then creates and configures keys

PUF values the GUI offers:


| Family     | `--bkp-puf-activate` | `--bkp-set-authority`      |
| ---------- | -------------------- | -------------------------- |
| Agilex 5   | `UDS_INTEL`          | `UDS_EFUSE` or `UDS_INTEL` |
| Agilex 7   | `UDS_IID`            | `UDS_EFUSE` or `UDS_IID`   |
| Easic N5X  | not offered          | `UDS_EFUSE`                |
| Stratix 10 | not offered          | not offered                |


`--bkp-set-authority` defaults to `UDS_EFUSE`, slot `0`. Slot range: `0`–`7`.

## CLI reference

The same list is printed by `./run.sh --cli --help`.

### Global flags


| Option            | Function                             |
| ----------------- | ------------------------------------ |
| `--help`, `-h`    | Show this command list.              |
| `--verbose`, `-v` | Diagnostic output and error traces.  |
| `--yes`, `-y`     | Auto-confirm destructive operations. |


### Setup


| Option                                        | Input                                        | Function                                                                                   |
| --------------------------------------------- | -------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `--create-config`                             |                                              | Write `bkps_demo_config.conf`.                                                             |
| `--load-config`                               |                                              | Load and validate the config file.                                                         |
| `--first-time-installation`, `--resume-setup` |                                              | Same resume-safe setup. Completed steps are skipped.                                       |
| `--auto-setup`                                |                                              | Start the service, read the token, create the super admin, then create and configure keys. |
| `--install-dependencies`                      |                                              | Install missing supported dependencies.                                                    |
| `--check-dependencies`                        |                                              | Report what is missing.                                                                    |
| `--auto-detect-prebuilt`                      | `[--save]`                                   | Find prebuilt artifacts. `--save` writes their paths into the config.                      |
| `--build-all`                                 | `[full, bkps_only, or bkps_with_programmer]` | Build repository artifacts. Default: `bkps_only`.                                          |
| `--setup-bkps-server`                         |                                              | Provider, TLS files, keystore, and server configuration.                                   |


### Database


| Option                                            | Function                          |
| ------------------------------------------------- | --------------------------------- |
| `--setup-database`                                | Create the BKPS database.         |
| `--check-sql-connection`                          | Test the database connection.     |
| `--reset-db-password`                             | Reset the database password.      |
| `--show-db-stats`                                 | Show database statistics.         |
| `--initialize-reset-database`, `--reset-database` | Initialize or reset the database. |


### Server


| Option                                                  | Input     | Function                                       |
| ------------------------------------------------------- | --------- | ---------------------------------------------- |
| `--configure-bkps-service`                              |           | Write `runner-config.json`.                    |
| `--start-bkp-service`, `--start-bkps`                   |           | Start BKPS and wait for the initial token.     |
| `--stop-bkp-service`, `--stop-bkps`                     |           | Stop BKPS.                                     |
| `--monitor-logs`                                        |           | Show recent logs and locate the initial token. |
| `--show-logs`                                           |           | Stream BKPS logs.                              |
| `--get-token`                                           |           | Print the initial access token.                |
| `--check-health`                                        |           | Query the health endpoint.                     |
| `--diagnose-jar`                                        |           | Diagnose JAR and classpath issues.             |
| `--create-activate-super-admin`, `--create-super-admin` | `<TOKEN>` | Create and activate the super administrator.   |
| `--create-authentication-keys`, `--create-keys`         |           | Generate authentication keys.                  |
| `--configure-bkps-keys`                                 |           | Configure BKPS service keys.                   |


### AES and SoftHSM


| Option                                                                 | Input      | Function                                               |
| ---------------------------------------------------------------------- | ---------- | ------------------------------------------------------ |
| `--init-token`, `--softhsm-init-token`                                 |            | Initialize the Agilex 5 SoftHSM token.                 |
| `--create-key`, `--softhsm-generate-aes-key`                           | `[64_HEX]` | Generate an AES-256 key, or import the supplied key.   |
| `--softhsm-import-aes-key`                                             | `<64_HEX>` | Import an AES-256 key. The hex string is required.     |
| `--create-qek-ccert`, `--softhsm-create-qek-ccert`, `--create-aes-key` | `[64_HEX]` | Create QEK and ccert files and update the AES JSON.    |
| `--softhsm-show-slots`                                                 |            | List SoftHSM slots.                                    |
| `--softhsm-list-objects`                                               |            | List SoftHSM objects.                                  |
| `--softhsm-delete-token`                                               |            | Delete the SoftHSM token.                              |
| `--softhsm-delete-key`                                                 |            | Delete the SoftHSM AES key.                            |
| `--import-aes-key-to-bc`                                               | `<64_HEX>` | Import an AES-256 key into the Bouncy Castle keystore. |


`64_HEX` is 64 hexadecimal characters (AES-256).

### Configurations, users, and keys


| Option                                                 | Input         | Function                                                                                           |
| ------------------------------------------------------ | ------------- | -------------------------------------------------------------------------------------------------- |
| `--create-configuration`, `--upload-aes-configuration` |               | Upload the working AES configuration.                                                              |
| `--upload-aes-configuration-file`                      | `<PATH>`      | Upload a specific AES JSON file.                                                                   |
| `--list-configurations`                                |               | List AES configurations.                                                                           |
| `--get-configuration`                                  | `<ID>`        | Get a configuration by numeric ID.                                                                 |
| `--update-configuration`                               | `<ID>`        | Update a configuration by numeric ID.                                                              |
| `--delete-configuration`                               | `<ID>`        | Delete a configuration by numeric ID.                                                              |
| `--validate-aes-configuration`                         |               | Validate the default AES configuration file.                                                       |
| `--generate-bkp-options`, `--create-bkp-config`        | `[ID]`        | Write `bkp_options.txt`.                                                                           |
| `--list-users`                                         |               | List BKPS users.                                                                                   |
| `--create-programmer-user`                             |               | Create a programmer user.                                                                          |
| `--create-user`                                        | `<ROLE>`      | Create a user. Role is `ROLE_SUPER_ADMIN`, `ROLE_ADMIN`, or `ROLE_PROGRAMMER`.                     |
| `--delete-user`                                        | `<ID>`        | Delete a user by numeric ID. On a terminal, an omitted ID is prompted.                             |
| `--unset-user-role`                                    | `<ID> <ROLE>` | Remove that role from the user.                                                                    |
| `--add-owner-root-key`                                 | `[PATH]`      | Add a device-owner root `.qky`. Default is the configured path, then `quartus_keys_dir/root0.qky`. |
| `--list-signing-keys`                                  |               | List signing keys.                                                                                 |
| `--list-root-signing-keys`                             |               | List root-signing keys.                                                                            |
| `--create-sealing-key`                                 |               | Create a sealing key.                                                                              |
| `--list-sealing-keys`                                  |               | List sealing keys.                                                                                 |
| `--rotate-sealing-key`                                 |               | Rotate the sealing key.                                                                            |
| `--create-import-key`                                  |               | Create an import key.                                                                              |
| `--get-import-pubkey`                                  |               | Retrieve the import public key.                                                                    |
| `--delete-import-key`                                  |               | Delete the import key.                                                                             |
| `--backup-sealing-keys`                                |               | Back up encrypted sealing keys.                                                                    |
| `--restore-sealing-keys`                               | `<FILE>`      | Restore sealing keys from a backup.                                                                |
| `--rotate-context-key`                                 |               | Rotate the context key.                                                                            |
| `--list-trusted-certs`                                 |               | List trusted certificates.                                                                         |
| `--delete-trusted-cert`                                | `<ALIAS>`     | Delete a trusted certificate. On a terminal, an omitted alias is prompted.                         |
| `--import-root-cert`                                   | `<PATH>`      | Import a root certificate.                                                                         |


### Programming and maintenance


| Option                                       | Input                                                 | Function                                                      |
| -------------------------------------------- | ----------------------------------------------------- | ------------------------------------------------------------- |
| `--generate-jic`                             | `<SOF> [OUT_DIR] [FLASH_DEVICE] [FLASH_LOADER] [RBF]` | Build a JIC. Use `-` for SOF when an RBF is set.              |
| `--program-helper-image`                     |                                                       | Generate and program the helper image.                        |
| `--program-root-key-hash`, `--provision-rkh` |                                                       | Program the root-key hash.                                    |
| `--program-jic`                              | `<JIC_FILE>`                                          | Program a JIC file.                                           |
| `--bkp-prefetch`                             |                                                       | Run BKP prefetch.                                             |
| `--bkp-puf-activate`                         | `<PUF_TYPE>`                                          | Activate PUF. See the family table above.                     |
| `--bkp-set-authority`                        | `[PUF_TYPE] [SLOT]`                                   | Set authority. Defaults: `UDS_EFUSE`, slot `0`.               |
| `--bkp-provision`, `--run-bkp`               |                                                       | Run BKP provisioning.                                         |
| `--check-jtag`                               |                                                       | Check the JTAG connection.                                    |
| `--check-jtag-status`                        | `<PROV or CONFIG>`                                    | Read provisioning or configuration status.                    |
| `--read-fuse-info`                           |                                                       | Read device fuse information.                                 |
| `--validate-setup`                           |                                                       | Check dependencies, services, certificates, and Quartus keys. |
| `--export-logs`                              | `[DAYS]`                                              | Export logs. Default: 7 days.                                 |
| `--backup`                                   |                                                       | Back up the setup.                                            |
| `--restore`                                  | `<DIR>`                                               | Restore a backup directory.                                   |
| `--cleanup`                                  |                                                       | Remove generated setup artifacts.                             |
| `--debug-tests`                              |                                                       | Run all diagnostics.                                          |
| `--debug-prechecks`                          |                                                       | Run preflight diagnostics.                                    |
| `--debug-connectivity`                       |                                                       | Run connectivity diagnostics.                                 |
| `--debug-cert-validity`                      |                                                       | Run certificate-validity diagnostics.                         |


`--generate-jic` defaults:

- Output directory: the SOF directory, or the working directory
- Flash device: `MT25QU02G`
- Flash loader: `device_part` from the config
- An RBF skips SOF conversion

## System requirements

- Python 3.10 or newer
- Java 17 or newer (`java`, `keytool`)
- Quartus Prime for programming (`quartus_pgm`, `quartus_pfg`)
- A missing Quartus install is a warning. The dependency check continues.

### Linux packages checked by `--check-dependencies`

`python3`, `java`, `psql`, `openssl`, `wget`, `aria2c`, `jq`, `curl`, `git`, `unzip`, `keytool`, `cmake`, `make`, `nc`.

- SoftHSM (`softhsm2-util`, `pkcs11-tool`, PKCS#11 library) is required for Agilex 5
- `setup.sh` installs SoftHSM on every Linux setup

### Windows

`setup.bat` can install through `winget`:

- Python 3.12, Java 17, PostgreSQL, OpenSSL, Git, curl, wget, jq, CMake, OpenSC, Strawberry Perl
- Visual Studio 2022 C++ Build Tools (MSVC, CMake, Windows SDK), without the IDE

Skipped by the Windows dependency check: `wget`, `aria2c`, `jq`, `unzip`, `nc`, `cmake`, `make`.

Windows source build:

- The cloned BKPS tree runs its own `build-dependencies.bat`
- That script builds dependencies, `libspdm_wrapper.dll`, the BKPS JAR, and the SQL schema
- This tool passes `--full`, `--bkp-with-bkpprogrammer`, or `--bkp-only`
- The flag comes from `BKPS_BUILD_MODE` and `INCLUDE_BKP_PROGRAMMER`
- Build Tools come from `BKPS_VS_BUILD_DIR`, a Visual Studio developer environment, or `vswhere.exe`


| Command                              | What it does                                                                                  |
| ------------------------------------ | --------------------------------------------------------------------------------------------- |
| `setup.bat --check-tool-paths`       | Report tool locations. Does not install.                                                      |
| `setup.bat --check-java`             | Check that Java is 17 or newer. Does not install.                                             |
| `setup.bat --check-msvc`             | Check Build Tools. Does not install.                                                          |
| `setup.bat --ensure-msvc`            | Install or repair the required Build Tools.                                                   |
| `setup.bat --ensure-strawberry-perl` | Install or verify `C:\Strawberry\perl\bin\perl.exe`, which the Windows OpenSSL build expects. |
| `setup.bat --ensure-softhsm`         | Install or verify the pinned SoftHSM runtime.                                                 |


If `winget` is missing:

- Install **App Installer** from the Microsoft Store, then run `setup.bat` again
- The script still creates `.venv` and prints manual install commands

### Python packages

GUI install (what `setup.sh` and `setup.bat` use):

```bash
pip install -r requirements.txt
```

CLI-only install (same packages, without PySide6):

```bash
pip install -r requirements-cli.txt
```


| Package                                        | Used for                                        |
| ---------------------------------------------- | ----------------------------------------------- |
| PySide6                                        | GUI. Present only in `requirements.txt`.        |
| cryptography, pyOpenSSL, pycryptodome          | Cryptographic operations.                       |
| ecdsa, docopt, requests, packaging, setuptools | The BKPS admin `runner.py`.                     |
| psycopg2-binary                                | PostgreSQL. Included in both requirement files. |


## Troubleshooting

**Module not found**

- Rerun `./setup.sh` or `setup.bat`
- Launch with `./run.sh` or `run.bat`

**Missing system tools**

- The setup script lists them
- Windows tries `winget` first

**GUI does not start**

- Install PySide6 in `.venv`: `pip install PySide6`
- A display is required
- Headless Linux: `./run.sh` starts Xvfb on `:99` when `Xvfb` is installed
- Otherwise it sets `QT_QPA_PLATFORM=offscreen`
- No display: `./run.sh --cli` with `requirements-cli.txt`

Display libraries:

```bash
# Ubuntu/Debian
sudo apt-get install -y libgl1 libegl1 libglib2.0-0 xvfb
# RHEL/Fedora
sudo dnf install -y mesa-libGL mesa-libEGL glib2 xorg-x11-server-Xvfb
```


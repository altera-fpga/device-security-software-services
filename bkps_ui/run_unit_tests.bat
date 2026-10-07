@echo off
setlocal EnableExtensions EnableDelayedExpansion
:: =============================================================================
:: run_unit_tests.bat - Run bkps_ui Python unit tests on Windows (CI / local).
::
:: Usage:
::   run_unit_tests.bat                 tests\ suite (Qt tests need PySide6)
::   run_unit_tests.bat --cli-only      skip modules that import PySide6 at load
::   run_unit_tests.bat --log out.log   write the unittest log to out.log
::
:: Creates .venv if missing, installs Python 3 if missing, installs deps, runs unittest.
:: =============================================================================

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"
set "CLI_ONLY=0"
set "LOG_FILE=unittest.log"
set "PYTHON_INSTALLER_URL=https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe"
set "PYTHON_INSTALLER=%TEMP%\python-3.12.10-amd64.exe"

:parse_args
if "%~1"=="" goto args_done
if /I "%~1"=="--cli-only" (
    set "CLI_ONLY=1"
    shift
    goto parse_args
)
if /I "%~1"=="--log" (
    set "LOG_FILE=%~2"
    shift
    shift
    goto parse_args
)
if /I "%~1"=="-h" goto usage
if /I "%~1"=="--help" goto usage
echo Unknown option: %~1
exit /b 2

:args_done
call :ensure_python
if errorlevel 1 exit /b 1

if not exist ".venv\Scripts\activate.bat" (
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        exit /b 1
    )
)

call ".venv\Scripts\activate.bat"
if errorlevel 1 (
    echo [ERROR] Failed to activate virtual environment.
    exit /b 1
)

python -m pip install -U pip
if errorlevel 1 exit /b 1

if "!CLI_ONLY!"=="1" (
    python -m pip install -r requirements-cli.txt
    if errorlevel 1 exit /b 1
) else (
    python -m pip install -r requirements.txt
    if errorlevel 1 exit /b 1
    if not defined QT_QPA_PLATFORM set "QT_QPA_PLATFORM=offscreen"
)

set "PRIOR_PYTHONPATH=%PYTHONPATH%"
set "PYTHONPATH=%SCRIPT_DIR%;%SCRIPT_DIR%gui"
if defined PRIOR_PYTHONPATH set "PYTHONPATH=%PYTHONPATH%;%PRIOR_PYTHONPATH%"

echo Running bkps_ui unit tests ^(cli_only=!CLI_ONLY!^) ...
call :run_tests > "%LOG_FILE%" 2>&1
set "RC=%ERRORLEVEL%"
type "%LOG_FILE%"
exit /b %RC%

:run_tests
if "!CLI_ONLY!"=="1" (
    python -c "import pathlib,subprocess,sys; skip={'test_bkps_utils','test_gui_restart_state','test_log_panel_capacity','test_release_fetch_combo','test_server_operations'}; mods=['tests.'+p.stem for p in sorted(pathlib.Path('tests').glob('test_*.py')) if p.stem not in skip]; print('CLI-only: running', len(mods), 'modules (skipped', len(skip), 'GUI modules)'); sys.exit(subprocess.call([sys.executable, '-m', 'unittest'] + mods + ['-v']))"
) else (
    python -m unittest discover -s tests -p "test_*.py" -v
)
if errorlevel 1 exit /b 1
exit /b 0

:usage
echo Usage: run_unit_tests.bat [--cli-only] [--log FILE]
exit /b 0

:ensure_python
call :find_python
if not errorlevel 1 exit /b 0

where winget >nul 2>&1
if not errorlevel 1 (
    echo [INFO] python.exe not found - attempting install via winget...
    winget install --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements --silent
) else (
    echo [INFO] python.exe not found and winget unavailable - downloading from python.org...
    call :install_python_from_official
    if errorlevel 1 exit /b 1
)
call :refresh_python_path
call :find_python
if not errorlevel 1 exit /b 0

echo [ERROR] Python 3.8+ not found after install.
echo         Install from: https://www.python.org/downloads/
echo         Or via winget: winget install Python.Python.3.12
exit /b 1

:find_python
where python.exe >nul 2>&1
if errorlevel 1 exit /b 1
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if errorlevel 1 exit /b 1
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo [INFO] Using %%v
exit /b 0

:install_python_from_official
echo [INFO] Downloading %PYTHON_INSTALLER_URL%
powershell -NoProfile -Command "try { Invoke-WebRequest -Uri '%PYTHON_INSTALLER_URL%' -OutFile '%PYTHON_INSTALLER%' -UseBasicParsing } catch { exit 1 }"
if errorlevel 1 (
    echo [ERROR] Failed to download Python installer from python.org.
    echo         Install from: https://www.python.org/downloads/
    exit /b 1
)
echo [INFO] Running silent Python installer...
"%PYTHON_INSTALLER%" /quiet InstallAllUsers=0 PrependPath=1 Include_test=0 SimpleInstall=1
set "INSTALL_RC=!ERRORLEVEL!"
del /q "%PYTHON_INSTALLER%" >nul 2>&1
if not "!INSTALL_RC!"=="0" (
    echo [ERROR] Python installer failed with exit code !INSTALL_RC!.
    echo         Install from: https://www.python.org/downloads/
    exit /b 1
)
exit /b 0

:refresh_python_path
for /f "usebackq delims=" %%p in (`powershell -NoProfile -Command "[Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')" 2^>nul`) do set "PATH=%%p"
for /d %%p in ("%LocalAppData%\Programs\Python\Python*") do (
    if exist "%%~fp\python.exe" set "PATH=%%~fp;%%~fp\Scripts;!PATH!"
)
exit /b 0

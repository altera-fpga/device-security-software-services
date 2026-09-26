@echo off
:: run.bat — Launch BKPS Demo Automation (GUI or CLI) on Windows.
::
:: Usage:
::   run.bat                          Launch GUI
::   run.bat --cli --help             BKPS CLI help
::   run.bat --cli --status           Run a CLI command
::   run.bat --cli --start-bkps       Start BKPS server (CLI)
::
:: Run setup.bat first if .venv does not exist.

setlocal EnableDelayedExpansion
set "SCRIPT_DIR=%~dp0"

if not exist "%SCRIPT_DIR%.venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found: %SCRIPT_DIR%.venv
    echo.
    echo Run setup.bat to create it.
    exit /b 1
)

call "%SCRIPT_DIR%.venv\Scripts\activate.bat"

:: CLI mode — collect all args after "--cli" into a new argument string
if /I "%1"=="--cli" (
    :: Build argument list without the leading --cli flag
    set "CLI_ARGS="
    shift
    :collect_args
    if "%1"=="" goto run_cli
    set "CLI_ARGS=!CLI_ARGS! %1"
    shift
    goto collect_args
    :run_cli
    python "%SCRIPT_DIR%bkps_main.py" !CLI_ARGS!
    goto :eof
)

:: GUI mode
python "%SCRIPT_DIR%gui\main.py" %*

endlocal

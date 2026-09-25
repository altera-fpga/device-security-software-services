@echo off
setlocal EnableExtensions EnableDelayedExpansion
:: =============================================================================
:: setup.bat - Prepare BKPS tool runtime on Windows.
::
:: Usage:
::   setup.bat
::   setup.bat --check-tool-paths
::   setup.bat --check-java
::   setup.bat --check-msvc
::   setup.bat --ensure-msvc
::   setup.bat --ensure-strawberry-perl
::   setup.bat --ensure-softhsm
::
:: What it does:
::   1. Detects Windows version and package-manager availability
::   2. Checks system tools and installs missing ones via winget when possible
::   3. Creates a local virtual environment (.venv)
::   4. Installs Python dependencies from requirements.txt
::   5. Verifies core imports and reports remaining gaps
::
:: Notes:
::   - Quartus Prime tools cannot be installed automatically here.
::   - OpenSC is installed through winget. For demo/test use, SoftHSM is
::     installed from a pinned, hash-checked, Authenticode-verified package.
::   - The cloned BKPS repository owns its native Windows build prerequisites.
::     The current upstream build-dependencies.bat requires Visual Studio C++
::     tools. This script installs the required standalone Visual Studio 2022
::     Build Tools components without installing the Visual Studio IDE.
:: =============================================================================

set "SCRIPT_DIR=%~dp0"
set "VENV_DIR=%SCRIPT_DIR%.venv"
set "REQ_FILE=%SCRIPT_DIR%requirements.txt"
set "RUN_BAT=%SCRIPT_DIR%run.bat"
set "FAILED=0"
set "WARNINGS=0"
set "HAS_WINGET=0"
set "PYTHON_EXE=python"
set "OS_NAME=Windows"
set "OS_VERSION=Unknown"
set "VS_BUILD_TOOLS_PACKAGE=Microsoft.VisualStudio.2022.BuildTools"
set "VS_VCTOOLS_WORKLOAD=Microsoft.VisualStudio.Workload.VCTools"
set "VS_CPP_COMPONENT=Microsoft.VisualStudio.Component.VC.Tools.x86.x64"
set "VS_CMAKE_COMPONENT=Microsoft.VisualStudio.Component.VC.CMake.Project"
set "VS_SDK_COMPONENT=Microsoft.VisualStudio.Component.Windows11SDK.26100"
set "VSWHERE_EXE="
set "VS_INSTALLER_EXE="
set "VS_INSTALL_ROOT="
set "VS_BUILD_DIR="
set "STRAWBERRY_PERL_EXE=C:\Strawberry\perl\bin\perl.exe"

if /I "%~1"=="--check-tool-paths" goto mode_check_tool_paths
if /I "%~1"=="--check-msvc" goto mode_check_msvc
if /I "%~1"=="--check-java" goto mode_check_java
if /I "%~1"=="--ensure-msvc" goto mode_ensure_msvc
if /I "%~1"=="--ensure-strawberry-perl" goto mode_ensure_strawberry_perl
if /I "%~1"=="--ensure-softhsm" goto mode_ensure_softhsm
goto main

:mode_check_tool_paths
    call :refresh_known_paths
    set "CHECK_FAILED=0"
    call :report_tool_path "psql" "PostgreSQL"
    if errorlevel 1 set "CHECK_FAILED=1"
    call :report_tool_path "pkcs11-tool" "OpenSC PKCS11 tools"
    if errorlevel 1 set "CHECK_FAILED=1"
    call :report_tool_path "openssl" "OpenSSL"
    if errorlevel 1 set "CHECK_FAILED=1"
    call :report_tool_path "softhsm2-util" "SoftHSM2"
    if errorlevel 1 set "CHECK_FAILED=1"
    call :detect_visual_studio_build_tools
    if errorlevel 1 (
        echo   FAIL: Visual Studio C++ Build Tools not found
        set "CHECK_FAILED=1"
    ) else (
        echo   OK: Visual Studio C++ Build Tools - !VS_BUILD_DIR!
    )
    if exist "!STRAWBERRY_PERL_EXE!" (
        echo   OK: Strawberry Perl - !STRAWBERRY_PERL_EXE!
    ) else (
        echo   FAIL: Strawberry Perl not found at upstream-required path - !STRAWBERRY_PERL_EXE!
        set "CHECK_FAILED=1"
    )
    if !CHECK_FAILED! equ 0 (
        echo Tool path discovery passed.
        endlocal & exit /b 0
    )
    echo Tool path discovery failed.
    endlocal & exit /b 1

:mode_check_msvc
    call :detect_visual_studio_build_tools
    if not errorlevel 1 (
        echo Visual Studio C++ Build Tools check passed.
        echo   VC build directory: !VS_BUILD_DIR!
        call :report_visual_studio_build_tools
        endlocal & exit /b 0
    )
    echo Visual Studio C++ Build Tools check failed.
    endlocal & exit /b 1

:mode_check_java
    call :detect_java17
    if not errorlevel 1 (
        echo Java 17+ check passed: !JAVA_VERSION_LINE!
        endlocal & exit /b 0
    )
    echo Java 17+ check failed.
    endlocal & exit /b 1

:mode_ensure_msvc
    call :detect_winget
    call :ensure_visual_studio_build_tools
    if !FAILED! equ 0 (
        echo Visual Studio C++ Build Tools setup passed.
        endlocal & exit /b 0
    )
    echo Visual Studio C++ Build Tools setup failed.
    endlocal & exit /b 1

:mode_ensure_strawberry_perl
    call :detect_winget
    call :ensure_strawberry_perl
    if !FAILED! equ 0 (
        echo Strawberry Perl setup passed.
        endlocal & exit /b 0
    )
    echo Strawberry Perl setup failed.
    endlocal & exit /b 1

:mode_ensure_softhsm
    call :detect_winget
    call :refresh_known_paths
    call :ensure_tool "pkcs11-tool" "OpenSC PKCS11 tools" "OpenSC.OpenSC"
    call :ensure_softhsm
    if !FAILED! equ 0 (
        echo SoftHSM setup passed.
        endlocal & exit /b 0
    )
    echo SoftHSM setup failed.
    endlocal & exit /b 1

:main
echo.
echo == BKPS setup (Windows) =========================================
echo.

call :detect_os
call :detect_winget

echo [1/6] Checking Python...
call :ensure_python
if errorlevel 1 exit /b 1
call :check_python_version
if errorlevel 1 exit /b 1

echo.
echo [2/6] Checking system tools...
call :refresh_known_paths
call :ensure_java
call :ensure_tool "git" "Git" "Git.Git"
call :ensure_tool "pkcs11-tool" "OpenSC PKCS11 tools" "OpenSC.OpenSC"
call :ensure_softhsm
call :ensure_postgresql
call :ensure_openssl
call :ensure_tool "jq" "jq" "jqlang.jq"
call :ensure_tool "curl" "curl" "cURL.cURL"
call :ensure_tool "wget" "wget" "JernejSimoncic.Wget"
call :ensure_tool "cmake" "CMake" "Kitware.CMake"
call :ensure_visual_studio_build_tools
call :ensure_strawberry_perl
call :ensure_quartus

echo.
echo [3/6] Creating virtual environment...
if not exist "%VENV_DIR%\Scripts\activate.bat" (
    "%PYTHON_EXE%" -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        exit /b 1
    )
    echo   OK: created %VENV_DIR%
) else (
    echo   OK: using existing %VENV_DIR%
)

call "%VENV_DIR%\Scripts\activate.bat"
if errorlevel 1 (
    echo [ERROR] Failed to activate virtual environment.
    exit /b 1
)
set "PYTHON_EXE=python"

echo.
echo [4/6] Installing Python packages...
python -m pip install --upgrade pip --quiet

if exist "%REQ_FILE%" (
    python -m pip install --upgrade -r "%REQ_FILE%"
    if errorlevel 1 (
        echo [WARN] Some packages from requirements.txt may have failed.
        set /a WARNINGS+=1
        set FAILED=1
    ) else (
        echo   OK: requirements.txt installed
    )
) else (
    echo [WARN] requirements.txt not found - installing fallback packages
    python -m pip install PySide6 docopt ecdsa cryptography pyOpenSSL pycryptodome psycopg2-binary requests packaging "setuptools>=65.0,<72"
    if errorlevel 1 (
        echo [WARN] Fallback package installation had failures.
        set /a WARNINGS+=1
        set FAILED=1
    )
)

python -m pip install --force-reinstall --no-cache-dir "setuptools>=65.0,<72" --quiet
python -c "import pkg_resources" >nul 2>&1
if errorlevel 1 (
    echo [WARN] pkg_resources still not importable - admin-tools/runner.py may fail
    set /a WARNINGS+=1
    set FAILED=1
) else (
    echo   OK: setuptools^<72 ^(pkg_resources available^)
)

echo.
echo [5/6] Verifying imports...
for %%p in (PySide6 docopt ecdsa cryptography pkg_resources requests packaging psycopg2 OpenSSL Crypto) do (
    python -c "import %%p" >nul 2>&1
    if !errorlevel! equ 0 (
        echo   OK: %%p
    ) else (
        echo   WARN: %%p not importable
        set /a WARNINGS+=1
        set FAILED=1
    )
)

echo.
echo [6/6] Finalizing setup...
if exist "%RUN_BAT%" (
    echo   OK: launcher found - %RUN_BAT%
) else (
    echo   WARN: run.bat not found - launch CLI with: python bkps_main.py --help
    set /a WARNINGS+=1
    set FAILED=1
)

echo.
echo =================================================================
echo   OS: %OS_NAME% ^(%OS_VERSION%^)
if %HAS_WINGET% equ 1 (
    echo   Package manager: winget available
) else (
    echo   Package manager: winget not found
)
if %FAILED% equ 0 (
    echo   STATUS: Setup completed successfully.
) else (
    echo   STATUS: Setup completed with warnings ^(see above^).
)
echo.
echo   To launch the BKPS GUI:
echo     run.bat
echo.
echo   To use the BKPS CLI:
echo     run.bat --cli --help
echo     or directly: python bkps_main.py --help
echo =================================================================
echo.

if %FAILED% equ 0 (
    endlocal & exit /b 0
) else (
    endlocal & exit /b 1
)

:detect_os
for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "(Get-CimInstance Win32_OperatingSystem).Caption" 2^>nul`) do set "OS_NAME=%%v"
for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "(Get-CimInstance Win32_OperatingSystem).Version" 2^>nul`) do set "OS_VERSION=%%v"
if "%OS_NAME%"=="Windows" for /f "tokens=*" %%v in ('ver') do set "OS_VERSION=%%v"
echo   Detected OS: %OS_NAME% (%OS_VERSION%)
exit /b 0

:detect_winget
where winget >nul 2>&1
if %errorlevel% equ 0 (
    set "HAS_WINGET=1"
    echo   OK: winget available
    for /f "tokens=*" %%v in ('winget --version 2^>nul') do echo      version %%v
) else (
    echo   WARN: winget not found - system tools may need manual installation
)
exit /b 0

:ensure_python
where python >nul 2>&1
if %errorlevel% equ 0 (
    set "PYTHON_EXE=python"
    for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo   OK: %%v
    exit /b 0
)

if %HAS_WINGET% equ 1 (
    echo   INFO: Python not found - attempting install via winget...
    winget install --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements --silent
    call :refresh_known_paths
    where python >nul 2>&1
    if %errorlevel% equ 0 (
        set "PYTHON_EXE=python"
        for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo   OK: %%v
        exit /b 0
    )
)

for /d %%p in ("%LocalAppData%\Programs\Python\Python*") do (
    if exist "%%~fp\python.exe" set "PYTHON_EXE=%%~fp\python.exe"
)
if exist "%PYTHON_EXE%" (
    for /f "tokens=*" %%v in ('"%PYTHON_EXE%" --version 2^>^&1') do echo   OK: %%v
    exit /b 0
)

echo.
echo [ERROR] Python 3.8+ not found.
echo.
echo         Install from: https://www.python.org/downloads/
echo         Or via winget: winget install Python.Python.3.12
echo.
echo         Then re-run setup.bat.
exit /b 1

:check_python_version
"%PYTHON_EXE%" -c "import sys; exit(0 if sys.version_info >= (3,8) else 1)" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3.8 or newer is required.
    exit /b 1
)
exit /b 0

:detect_java17
set "JAVA_VERSION_LINE="
set "JAVA_VERSION="
set "JAVA_MAJOR="
where java >nul 2>&1
if errorlevel 1 exit /b 1
for /f "usebackq delims=" %%v in (`java -version 2^>^&1`) do if not defined JAVA_VERSION_LINE set "JAVA_VERSION_LINE=%%v"
if not defined JAVA_VERSION_LINE exit /b 1
for /f tokens^=2^ delims^=^" %%v in ("!JAVA_VERSION_LINE!") do if not defined JAVA_VERSION set "JAVA_VERSION=%%v"
if not defined JAVA_VERSION exit /b 1
for /f "tokens=1,2 delims=." %%a in ("!JAVA_VERSION!") do (
    set "JAVA_MAJOR=%%a"
    if "%%a"=="1" set "JAVA_MAJOR=%%b"
)
if not defined JAVA_MAJOR exit /b 1
for /f "delims=0123456789" %%x in ("!JAVA_MAJOR!") do exit /b 1
if !JAVA_MAJOR! lss 17 exit /b 1
exit /b 0

:ensure_java
call :detect_java17
if not errorlevel 1 (
    echo   OK: Java !JAVA_VERSION_LINE!
    goto java_done
)
echo   INFO: Java 17+ missing - attempting install
if %HAS_WINGET% equ 1 (
    winget install --id Microsoft.OpenJDK.17 --accept-package-agreements --accept-source-agreements --silent
    call :refresh_known_paths
    call :detect_java17
    if not errorlevel 1 (
        echo   OK: Java installed - !JAVA_VERSION_LINE!
        goto java_done
    )
)
echo   WARN: Java 17+ not available. Install: winget install Microsoft.OpenJDK.17
set /a WARNINGS+=1
set FAILED=1
:java_done
where keytool >nul 2>&1
if %errorlevel% equ 0 (
    echo   OK: keytool
    exit /b 0
)
echo   WARN: keytool not found - ensure a full JDK is installed, not JRE only
set /a WARNINGS+=1
set FAILED=1
exit /b 0

:ensure_openssl
where openssl >nul 2>&1
if %errorlevel% equ 0 (
    echo   OK: OpenSSL
    exit /b 0
)
if exist "%ProgramFiles%\Git\usr\bin\openssl.exe" (
    set "PATH=%ProgramFiles%\Git\usr\bin;%PATH%"
    echo   OK: OpenSSL found in Git for Windows
    exit /b 0
)
echo   INFO: OpenSSL missing - attempting install
if %HAS_WINGET% equ 1 (
    winget install --id ShiningLight.OpenSSL.Light --exact --accept-package-agreements --accept-source-agreements --silent
    call :refresh_known_paths
    where openssl >nul 2>&1
    if %errorlevel% equ 0 (
        echo   OK: OpenSSL installed
        exit /b 0
    )
)
echo   WARN: OpenSSL not available. Install: winget install ShiningLight.OpenSSL.Light
set /a WARNINGS+=1
set FAILED=1
exit /b 0

:ensure_postgresql
where psql >nul 2>&1
if not errorlevel 1 (
    echo   OK: PostgreSQL
    call :start_postgresql
    exit /b 0
)

echo   INFO: PostgreSQL missing
if %HAS_WINGET% equ 1 (
    echo         Starting the PostgreSQL 17 installer.
    echo         Set the postgres password to the PG_SUPERUSER_PASSWORD value
    echo         that will be used in the BKPS configuration.
    winget install --id PostgreSQL.PostgreSQL.17 --exact --interactive --accept-package-agreements --accept-source-agreements
    call :refresh_known_paths
    where psql >nul 2>&1
    if not errorlevel 1 (
        echo   OK: PostgreSQL installed
        call :start_postgresql
        exit /b 0
    )
)

echo   WARN: PostgreSQL not available - install manually
echo         winget install --id PostgreSQL.PostgreSQL.17 --exact --interactive
set /a WARNINGS+=1
set FAILED=1
exit /b 0

:start_postgresql
for %%s in (postgresql-x64-18 postgresql-x64-17 postgresql-x64-16 postgresql-x64-15 postgresql) do (
    sc query "%%s" >nul 2>&1
    if not errorlevel 1 (
        net start "%%s" >nul 2>&1
        sc query "%%s" | findstr /i "RUNNING" >nul 2>&1
        if not errorlevel 1 (
            echo   OK: PostgreSQL service ready - %%s
            exit /b 0
        )
    )
)
echo   WARN: PostgreSQL is installed but no running service was detected.
set /a WARNINGS+=1
set FAILED=1
exit /b 0

:ensure_tool
set "TOOL_CMD=%~1"
set "TOOL_NAME=%~2"
set "TOOL_WINGET=%~3"
where %TOOL_CMD% >nul 2>&1
if %errorlevel% equ 0 (
    echo   OK: %TOOL_NAME%
    exit /b 0
)

echo   INFO: %TOOL_NAME% missing
if %HAS_WINGET% equ 1 if not "%TOOL_WINGET%"=="" (
    winget install --id %TOOL_WINGET% --exact --accept-package-agreements --accept-source-agreements --silent
    call :refresh_known_paths
    where %TOOL_CMD% >nul 2>&1
    if %errorlevel% equ 0 (
        echo   OK: %TOOL_NAME% installed
        exit /b 0
    )
)

echo   WARN: %TOOL_NAME% not available - install manually
if /i "%TOOL_NAME%"=="PostgreSQL" echo         winget install PostgreSQL.PostgreSQL
if /i "%TOOL_NAME%"=="Git" echo         winget install Git.Git
if /i "%TOOL_NAME%"=="jq" echo         winget install jqlang.jq
if /i "%TOOL_NAME%"=="curl" echo         winget install cURL.cURL
if /i "%TOOL_NAME%"=="wget" echo         winget install JernejSimoncic.Wget
if /i "%TOOL_NAME%"=="CMake" echo         winget install Kitware.CMake
if /i "%TOOL_NAME%"=="OpenSC PKCS11 tools" echo         winget install --id OpenSC.OpenSC --exact
set /a WARNINGS+=1
set FAILED=1
exit /b 0

:ensure_softhsm
set "SOFTHSM_INSTALLER=%SCRIPT_DIR%install_softhsm_windows.ps1"
if defined BKPS_SOFTHSM_INSTALL_ROOT (
    set "SOFTHSM_MANAGED_ROOT=%BKPS_SOFTHSM_INSTALL_ROOT%"
) else (
    set "SOFTHSM_MANAGED_ROOT=%LOCALAPPDATA%\BKPS\SoftHSM2\runtime-2.5.0"
)
if not exist "%SOFTHSM_INSTALLER%" (
    echo   WARN: Windows SoftHSM installer is missing: %SOFTHSM_INSTALLER%
    set /a WARNINGS+=1
    set FAILED=1
    exit /b 0
)
if exist "!SOFTHSM_MANAGED_ROOT!\bin\softhsm2-util.exe" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SOFTHSM_INSTALLER%" -ValidateOnly
) else (
    echo   INFO: Installing the pinned, signed SoftHSM2 demo/test runtime.
    echo         This software HSM is not a production key-protection boundary.
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SOFTHSM_INSTALLER%"
)
if errorlevel 1 (
    echo   WARN: SoftHSM2 installation or validation failed.
    set /a WARNINGS+=1
    set FAILED=1
    exit /b 0
)
set "BKPS_SOFTHSM_ROOT=!SOFTHSM_MANAGED_ROOT!"
call :refresh_known_paths
where softhsm2-util >nul 2>&1
if not errorlevel 1 (
    echo   OK: SoftHSM2 token manager installed and validated
    exit /b 0
)
echo   WARN: SoftHSM2 validation passed, but softhsm2-util.exe is unresolved.
set /a WARNINGS+=1
set FAILED=1
exit /b 0

:ensure_quartus
where quartus_pgm >nul 2>&1
if %errorlevel% equ 0 (
    echo   OK: Quartus Prime tools
    exit /b 0
)
echo   WARN: Quartus Prime tools not found - install manually from Intel FPGA software
set /a WARNINGS+=1
set FAILED=1
exit /b 0

:locate_visual_studio_installer
set "VSWHERE_EXE="
set "VS_INSTALLER_EXE="
for %%r in ("%ProgramFiles(x86)%" "%ProgramFiles%") do if not "%%~r"=="" (
    if not defined VSWHERE_EXE if exist "%%~r\Microsoft Visual Studio\Installer\vswhere.exe" set "VSWHERE_EXE=%%~r\Microsoft Visual Studio\Installer\vswhere.exe"
    if not defined VS_INSTALLER_EXE if exist "%%~r\Microsoft Visual Studio\Installer\setup.exe" set "VS_INSTALLER_EXE=%%~r\Microsoft Visual Studio\Installer\setup.exe"
)
if not defined VSWHERE_EXE for /f "usebackq delims=" %%p in (`where vswhere.exe 2^>nul`) do if not defined VSWHERE_EXE set "VSWHERE_EXE=%%p"
exit /b 0

:validate_visual_studio_build_tools
if not defined VS_BUILD_DIR exit /b 1
if not exist "!VS_BUILD_DIR!\vcvarsall.bat" exit /b 1
if not exist "!VS_BUILD_DIR!\vcvarsamd64_x86.bat" exit /b 1

for %%r in ("!VS_BUILD_DIR!\..\..\..") do set "VS_INSTALL_ROOT=%%~fr"
if not exist "!VS_INSTALL_ROOT!\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" exit /b 1

set "VS_NATIVE_TOOLS_OK=0"
for /d %%t in ("!VS_INSTALL_ROOT!\VC\Tools\MSVC\*") do (
    if exist "%%~ft\bin\Hostx64\x64\cl.exe" if exist "%%~ft\bin\Hostx64\x64\nmake.exe" set "VS_NATIVE_TOOLS_OK=1"
)
if "!VS_NATIVE_TOOLS_OK!"=="0" exit /b 1
exit /b 0

:report_visual_studio_build_tools
set "MSVC_COMPILER_VERSION="
if exist "!VS_INSTALL_ROOT!\VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt" (
    set /p "MSVC_COMPILER_VERSION=" < "!VS_INSTALL_ROOT!\VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt"
)
if not defined MSVC_COMPILER_VERSION for /d %%t in ("!VS_INSTALL_ROOT!\VC\Tools\MSVC\*") do set "MSVC_COMPILER_VERSION=%%~nxt"
if defined MSVC_COMPILER_VERSION (
    echo   INFO: MSVC compiler version - !MSVC_COMPILER_VERSION!
) else (
    echo   WARN: MSVC compiler version could not be resolved.
)
echo   INFO: BKPS Boost bootstrap mapping - vc143
echo   INFO: BKPS Boost.Build mapping - msvc-14.3
echo   INFO: BKPS CMake platform toolset - v143
exit /b 0

:detect_visual_studio_build_tools
set "VS_INSTALL_ROOT="
set "VS_BUILD_DIR="

if defined BKPS_VS_BUILD_DIR (
    set "VS_BUILD_DIR=!BKPS_VS_BUILD_DIR:"=!"
    call :validate_visual_studio_build_tools
    if not errorlevel 1 exit /b 0
    set "VS_BUILD_DIR="
    set "VS_INSTALL_ROOT="
)

call :locate_visual_studio_installer
if defined VSWHERE_EXE if exist "!VSWHERE_EXE!" (
    for /f "usebackq delims=" %%p in (`"!VSWHERE_EXE!" -latest -products * -requires !VS_CPP_COMPONENT! !VS_CMAKE_COMPONENT! !VS_SDK_COMPONENT! -property installationPath 2^>nul`) do set "VS_INSTALL_ROOT=%%p"
)
if defined VS_INSTALL_ROOT set "VS_BUILD_DIR=!VS_INSTALL_ROOT!\VC\Auxiliary\Build"
call :validate_visual_studio_build_tools
if not errorlevel 1 exit /b 0

set "VS_INSTALL_ROOT="
set "VS_BUILD_DIR="
exit /b 1

:find_existing_visual_studio_build_tools
set "VS_INSTALL_ROOT="
call :locate_visual_studio_installer
if defined VSWHERE_EXE if exist "!VSWHERE_EXE!" (
    for /f "usebackq delims=" %%p in (`"!VSWHERE_EXE!" -latest -products Microsoft.VisualStudio.Product.BuildTools -property installationPath 2^>nul`) do set "VS_INSTALL_ROOT=%%p"
)
if defined VS_INSTALL_ROOT exit /b 0
exit /b 1

:ensure_visual_studio_build_tools
call :detect_visual_studio_build_tools
if not errorlevel 1 (
    echo   OK: Visual Studio C++ Build Tools - !VS_BUILD_DIR!
    call :report_visual_studio_build_tools
    exit /b 0
)

echo   INFO: Required standalone Visual Studio 2022 Build Tools components are missing.
echo         Installing the MSVC x64/x86 toolchain, CMake integration, and Windows SDK.
echo         The Visual Studio IDE will not be installed.

call :find_existing_visual_studio_build_tools
if not errorlevel 1 if defined VS_INSTALLER_EXE if exist "!VS_INSTALLER_EXE!" (
    call :is_elevated
    if errorlevel 1 (
        echo   WARN: Existing Visual Studio Build Tools components can only be modified
        echo         from an Administrator terminal. No modification was attempted.
        echo         Re-run setup.bat as Administrator.
        set /a WARNINGS+=1
        set FAILED=1
        exit /b 0
    )
    echo         Adding missing components to: !VS_INSTALL_ROOT!
    "!VS_INSTALLER_EXE!" modify --installPath "!VS_INSTALL_ROOT!" --quiet --norestart --add !VS_VCTOOLS_WORKLOAD! --add !VS_CPP_COMPONENT! --add !VS_CMAKE_COMPONENT! --add !VS_SDK_COMPONENT!
    set "VS_INSTALL_EXIT=!errorlevel!"
    call :detect_visual_studio_build_tools
    if not errorlevel 1 (
        echo   OK: Visual Studio C++ Build Tools components installed
        call :report_visual_studio_build_tools
        if not "!VS_INSTALL_EXIT!"=="0" echo   INFO: Installer returned !VS_INSTALL_EXIT!; restart Windows if requested.
        exit /b 0
    )
    echo   WARN: Visual Studio Build Tools component modification failed with exit code !VS_INSTALL_EXIT!.
)

if !HAS_WINGET! equ 1 (
    winget install --id !VS_BUILD_TOOLS_PACKAGE! --exact --source winget --accept-package-agreements --accept-source-agreements --silent --override "--wait --quiet --norestart --add !VS_VCTOOLS_WORKLOAD! --add !VS_CPP_COMPONENT! --add !VS_CMAKE_COMPONENT! --add !VS_SDK_COMPONENT!"
    set "VS_INSTALL_EXIT=!errorlevel!"
    call :detect_visual_studio_build_tools
    if not errorlevel 1 (
        echo   OK: Visual Studio C++ Build Tools components installed
        call :report_visual_studio_build_tools
        if not "!VS_INSTALL_EXIT!"=="0" echo   INFO: winget returned !VS_INSTALL_EXIT!; restart Windows if requested.
        exit /b 0
    )
    echo   WARN: winget Build Tools installation failed with exit code !VS_INSTALL_EXIT!.
)

echo   WARN: Visual Studio C++ Build Tools components are unavailable.
echo         Re-run setup.bat from an Administrator terminal, or install:
echo         !VS_VCTOOLS_WORKLOAD!
echo         !VS_CPP_COMPONENT!
echo         !VS_CMAKE_COMPONENT!
echo         !VS_SDK_COMPONENT!
set /a WARNINGS+=1
set FAILED=1
exit /b 0

:is_elevated
powershell -NoProfile -Command "$identity=[Security.Principal.WindowsIdentity]::GetCurrent(); $principal=New-Object Security.Principal.WindowsPrincipal($identity); if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }" >nul 2>&1
exit /b !errorlevel!

:ensure_strawberry_perl
if exist "!STRAWBERRY_PERL_EXE!" (
    echo   OK: Strawberry Perl - !STRAWBERRY_PERL_EXE!
    exit /b 0
)

echo   INFO: Strawberry Perl missing - attempting install
echo         The upstream BKPS OpenSSL build calls !STRAWBERRY_PERL_EXE! directly.
if !HAS_WINGET! equ 1 (
    winget install --id StrawberryPerl.StrawberryPerl --exact --source winget --accept-package-agreements --accept-source-agreements --silent
    set "STRAWBERRY_INSTALL_EXIT=!errorlevel!"
    if exist "!STRAWBERRY_PERL_EXE!" (
        echo   OK: Strawberry Perl installed - !STRAWBERRY_PERL_EXE!
        if not "!STRAWBERRY_INSTALL_EXIT!"=="0" echo   INFO: winget returned !STRAWBERRY_INSTALL_EXIT!; restart Windows if requested.
        exit /b 0
    )
    echo   WARN: Strawberry Perl installation failed with exit code !STRAWBERRY_INSTALL_EXIT!.
)

echo   WARN: Strawberry Perl is unavailable at !STRAWBERRY_PERL_EXE!.
echo         Install with: winget install --id StrawberryPerl.StrawberryPerl --exact
set /a WARNINGS+=1
set FAILED=1
exit /b 0

:refresh_known_paths
for /f "usebackq delims=" %%p in (`powershell -NoProfile -Command "[Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')" 2^>nul`) do set "PATH=%%p"

for %%r in ("%ProgramW6432%" "%ProgramFiles%" "%ProgramFiles(x86)%") do (
    if not "%%~r"=="" for %%d in (
        "%%~r\Git\cmd"
        "%%~r\Git\usr\bin"
        "%%~r\OpenSSL-Win64\bin"
        "%%~r\OpenSSL-Win32\bin"
        "%%~r\CMake\bin"
        "%%~r\OpenSC Project\OpenSC\tools"
        "%%~r\SoftHSM2\bin"
    ) do if exist "%%~d" set "PATH=%%~d;!PATH!"

    if not "%%~r"=="" for /d %%d in ("%%~r\Microsoft\jdk-*") do if exist "%%~fd\bin\java.exe" set "PATH=%%~fd\bin;!PATH!"
    if not "%%~r"=="" for /d %%d in ("%%~r\Eclipse Adoptium\jdk-*") do if exist "%%~fd\bin\java.exe" set "PATH=%%~fd\bin;!PATH!"
    if not "%%~r"=="" for /d %%d in ("%%~r\PostgreSQL\*") do if exist "%%~fd\bin\psql.exe" set "PATH=%%~fd\bin;!PATH!"
)

if defined BKPS_SOFTHSM_INSTALL_ROOT if exist "%BKPS_SOFTHSM_INSTALL_ROOT%\bin\softhsm2-util.exe" (
    set "BKPS_SOFTHSM_ROOT=%BKPS_SOFTHSM_INSTALL_ROOT%"
    set "PATH=%BKPS_SOFTHSM_INSTALL_ROOT%\bin;%BKPS_SOFTHSM_INSTALL_ROOT%\lib;!PATH!"
)
if not defined BKPS_SOFTHSM_INSTALL_ROOT if exist "%LOCALAPPDATA%\BKPS\SoftHSM2\runtime-2.5.0\bin\softhsm2-util.exe" (
    set "BKPS_SOFTHSM_ROOT=%LOCALAPPDATA%\BKPS\SoftHSM2\runtime-2.5.0"
    set "PATH=%LOCALAPPDATA%\BKPS\SoftHSM2\runtime-2.5.0\bin;%LOCALAPPDATA%\BKPS\SoftHSM2\runtime-2.5.0\lib;!PATH!"
)

exit /b 0

:report_tool_path
set "FOUND_TOOL_PATH="
for /f "usebackq delims=" %%p in (`where %~1 2^>nul`) do if not defined FOUND_TOOL_PATH set "FOUND_TOOL_PATH=%%p"
if not defined FOUND_TOOL_PATH (
    echo   FAIL: %~2 not found
    exit /b 1
)
echo   OK: %~2 - !FOUND_TOOL_PATH!
exit /b 0

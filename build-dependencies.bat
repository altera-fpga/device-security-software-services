@echo off
:: CMD looks up CALL :labels using the original %0. Re-enter with a
:: fully-qualified path so subroutine labels stay resolvable.
if not defined _BKPS_DEPS_RELAUNCH (
	set "_BKPS_DEPS_RELAUNCH=1"
	call "%~f0" %*
	set "_BKPS_DEPS_EXIT=%ERRORLEVEL%"
	set "_BKPS_DEPS_RELAUNCH="
	exit /b %_BKPS_DEPS_EXIT%
)
:: Disable QuickEdit mode for this specific window session
powershell -NoProfile -Command "$h = Get-Host; $ui = $h.UI.RawUI; $m = $ui.BufferCellType; $ui.Select($null, $null, $null, $null)" 2>nul
setlocal
setlocal EnableDelayedExpansion

set openssl_exists=0
set libspdm_exists=0
set libcurl_exists=0
set boost_exists=0
set gtest_exists=0
set current_dir=%cd%
set dependencies_dir=%current_dir%\dependencies
set spdm_wrapper_dir=%current_dir%\spdm_wrapper
set bkpprogrammer_dir=%current_dir%\bkpprogrammer
set output_dir=%current_dir%\out
set KEYSTORE_TRUSTSTORE_PATH=%current_dir%\bkps-nonprod.p12
set JAVA_HOME=%JAVA_HOME:"=%
set KEYTOOL_EXE="%JAVA_HOME%/bin/keytool.exe"
set "BUILD_SELECTION=full"
set "VS_BUILD_DIR="
set "BUILD_VERSION="
:: build-dependencies-ext.bat [VS Build Directory] [version] [--full|--bkp-with-bkpprogrammer|--bkp-only]
:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="--full" set "BUILD_SELECTION=full" & shift & goto parse_args
if /i "%~1"=="--bkp-with-bkpprogrammer" set "BUILD_SELECTION=bkp-with-bkpprogrammer" & shift & goto parse_args
if /i "%~1"=="--bkp-only" set "BUILD_SELECTION=bkp_only" & shift & goto parse_args
if /i "%~1"=="-h" goto print_usage
if /i "%~1"=="--help" goto print_usage
if not defined VS_BUILD_DIR (
	set "VS_BUILD_DIR=%~1"
	shift
	goto parse_args
)
if not defined BUILD_VERSION (
	set "BUILD_VERSION=%~1"
	shift
	goto parse_args
)
echo [ERROR] Unknown option: %~1
goto print_usage
:args_done

if /i not "%BUILD_SELECTION%"=="full" if /i not "%BUILD_SELECTION%"=="bkp-with-bkpprogrammer" if /i not "%BUILD_SELECTION%"=="bkp_only" (
	echo [ERROR] BUILD_SELECTION must be 'full', 'bkp-with-bkpprogrammer' or 'bkp_only', not '%BUILD_SELECTION%'
	goto print_usage
)

if exist "%~dp0config.txt" call :_load_config "%~dp0config.txt"
if exist "config.txt" call :_load_config "config.txt"
if errorlevel 1 exit /b 1
if /i "%BUILD_SELECTION%"=="bkp_only" (
	set "boost.version="
	set "libcurl.version="
	set "gtest.version="
)
echo Build selection: %BUILD_SELECTION%
if /i "%BUILD_SELECTION%"=="bkp_only" (
	echo BKPProgrammer: skipped
) else (
	echo BKPProgrammer: included
)

:: ---------------------------------------------------------------------------
:: Locate the Visual Studio developer command prompt scripts.
::
:: Two batch files are needed and both live in the same
:: VC\Auxiliary\Build\ directory of any given VS install:
::   * vcvarsamd64_x86.bat  (x64-hosted cross-compiler targeting x86)
::   * vcvarsall.bat		(parametric entry point; called with "x64")
:: ---------------------------------------------------------------------------
set "VCVARS_BAT="
set "VCVARS_X86_BAT="
set "CMAKE_EXE="
set "NMAKE_EXE="

if not defined BUILD_VERSION (
	set "BUILD_VERSION=1.0.0"
)

if defined VS_BUILD_DIR (
	call :_check_bat_existence
)

if not defined VCVARS_BAT if not defined VCVARS_X86_BAT (
	call :_probe_vcvars
)

echo [vcvars] Initialising MSVC amd64_x86 environment from: %VCVARS_X86_BAT%
@echo on
call "%VCVARS_X86_BAT%"
call "%VCVARS_BAT%" x64
if errorlevel 1 (
	echo [ERROR] Failed to initialise MSVC environment.
	endlocal
	exit /b 1
)

:: Check if vcvarsall.bat has been loaded
if "%VisualStudioVersion%"=="" (
	echo Error: vcvarsall.bat has not been loaded. Please run this script in a developer command prompt.
	exit /b 1
)

:: Map Visual Studio versions to CMake Generator version
set "CMAKE_VS_ARCH=-A x64"
if "%VisualStudioVersion%"=="18.0" (
	set "CMAKE_VS_GENERATOR=Visual Studio 18 2026"
) else if "%VisualStudioVersion%"=="17.0" (
	set "CMAKE_VS_GENERATOR=Visual Studio 17 2022"
) else if "%VisualStudioVersion%"=="16.0" (
	set "CMAKE_VS_GENERATOR=Visual Studio 16 2019"
) else if "%VisualStudioVersion%"=="15.0" (
	set "CMAKE_VS_GENERATOR=Visual Studio 15 2017 Win64"
	set "CMAKE_VS_ARCH="
) else (
	 :: Generic guess for older or future generators
	 set "CMAKE_VS_GENERATOR=Visual Studio %VisualStudioVersion%"
 )

set "v=%VCToolsVersion%"
if defined v (
    set "BOOST_TOOLSET=vc%v:~0,2%%v:~3,1%"
    set "BOOST_B2_TOOLSET=msvc-%v:~0,2%.%v:~3,1%"
    set "CMAKE_VS_TOOLSET=v%v:~0,2%%v:~3,1%"
)

:: 17.0 maps to v143 for both 14.3x and 14.4x tool versions.
if "%VisualStudioVersion%"=="17.0" (
    set "BOOST_TOOLSET=vc143"
    set "BOOST_B2_TOOLSET=msvc-14.3"
    set "CMAKE_VS_TOOLSET=v143"
)

echo ===================================================
echo MSVC Full Toolset Version:  %VCToolsVersion%
echo Visual Studio IDE Version:  %VSCMD_VER%
echo Target Architecture:        %VSCMD_ARG_TGT_ARCH%
echo Windows SDK Version:        %WindowsSDKVersion%
echo BOOST_TOOLSET               %BOOST_TOOLSET%
echo BOOST_B2_TOOLSET            %BOOST_B2_TOOLSET%
echo CMAKE_VS_GENERATOR          %CMAKE_VS_GENERATOR%
echo CMAKE_VS_TOOLSET            %CMAKE_VS_TOOLSET%
echo CMake generator             %CMAKE_VS_GENERATOR%  %CMAKE_VS_ARCH%  (toolset %CMAKE_VS_TOOLSET%)
echo ===================================================

set "VS_INSTALL_ROOT=!VS_BUILD_DIR!\..\..\.."
set "CMAKE_EXE=!VS_INSTALL_ROOT!\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
:probe_cmake_exe
if not exist "!CMAKE_EXE!" call :_prompt_tool_exe CMAKE_EXE_DIR cmake.exe "C++ CMake tools for Windows"
if defined CMAKE_EXE_DIR set "CMAKE_EXE=!CMAKE_EXE_DIR!\cmake.exe"
if not exist "!CMAKE_EXE!" (
	echo [ERROR] cmake.exe does not exists in path: !CMAKE_EXE_DIR!
	set "CMAKE_EXE="
)
if not defined CMAKE_EXE goto :probe_cmake_exe

set "NMAKE_EXE=!VS_INSTALL_ROOT!\VC\Tools\MSVC\%VCToolsVersion%\bin\Hostx64\x64\nmake.exe"
:probe_nmake_exe
if not exist "!NMAKE_EXE!" call :_prompt_tool_exe NMAKE_EXE_DIR nmake.exe "C++ NMake tools for Windows"
if defined NMAKE_EXE_DIR set "NMAKE_EXE=!NMAKE_EXE_DIR!\nmake.exe"
if not exist "!NMAKE_EXE!" (
	echo [ERROR] nmake.exe does not exists in path: !NMAKE_EXE_DIR!
	set "NMAKE_EXE="
)
if not defined NMAKE_EXE goto :probe_nmake_exe

echo [vcvars] VS install root  : %VS_INSTALL_ROOT%
echo [vcvars] cmake.exe		: %CMAKE_EXE%
echo [vcvars] nmake.exe		: %NMAKE_EXE%
echo [vcvars] Build scripts dir : %VS_BUILD_DIR%
echo [vcvars] vcvarsall.bat	 : %VCVARS_BAT%
echo [vcvars] vcvarsamd64_x86.bat: %VCVARS_X86_BAT%

if not exist "%dependencies_dir%" mkdir "%dependencies_dir%"
cd /d "%dependencies_dir%"
set boost_version_string=%boost.version:.=_%
:: ====== openssl ======
If Defined openssl.version (
	If exist openssl_%openssl.version%_windows_x64 (
		If Defined always_build (
			set openssl_exists=0
		) else (
			set openssl_exists=1
		)
	)
	If !openssl_exists!==0 (
		call :build_openssl
		if errorlevel 1 exit /b 1
	)
)

:: ====== libspdm ======
If Defined libspdm.version (
	If exist libspdm_%libspdm.version%_windows_x64 (
		If Defined always_build (
			set libspdm_exists=0
		) else (
			set libspdm_exists=1
		)
	)
	If !libspdm_exists!==0 (
		echo building libspdm...
		If not exist "openssl_%openssl.version%_windows_x64" (
			call :build_openssl
            if errorlevel 1 exit /b 1
		)
		if exist libspdm @RD /S /Q libspdm
		if exist libspdm_%libspdm.version%_windows_x64 @RD /S /Q libspdm_%libspdm.version%_windows_x64
		call :_fetch_and_verify "libspdm-!libspdm.version!.tar.gz" "!libspdm.url!" "!libspdm.sha256!" "!libspdm.tarball!"
		if errorlevel 1 exit /b 1
		mkdir "libspdm"
		tar -xzf "libspdm-!libspdm.version!.tar.gz" -C "libspdm" --strip-components=1
		if errorlevel 1 (
			echo [ERROR] Failed to unpack libspdm-!libspdm.version!.tar.gz
			exit /b 1
		)
		cd "libspdm"
		if errorlevel 1 (
			echo [ERROR] Extracted libspdm directory libspdm not found.
			exit /b 1
		)
		mkdir build
		cd build
		set "custom_defines=-DLIBSPDM_MAX_MESSAGE_BUFFER_SIZE=20000 -DLIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN=15000 -DLIBSPDM_MAX_CERT_CHAIN_SIZE=18000 -DLIBSPDM_MAX_MEASUREMENT_RECORD_SIZE=15000"
		set "algorithms_enabled=-DLIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT=1"
		set "algorithms_disabled=-DLIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_CSR_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_PSK_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_CHAL_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP=0"
		set openssl_include_dir="%dependencies_dir%\openssl_%openssl.version%_windows_x64\include"
		"%CMAKE_EXE%" -G"NMake Makefiles" -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -DARCH=x64 -DTOOLCHAIN=VS2015 -DTARGET=Release -DDISABLE_TESTS=1 -DCRYPTO=openssl -DCMAKE_C_FLAGS="!custom_defines! !algorithms_enabled! !algorithms_disabled! -I!openssl_include_dir! /GL- /wd4565" -DENABLE_BINARY_BUILD=1 -DCOMPILED_LIBCRYPTO_PATH="%current_dir%\openssl_%openssl.version%_windows_x64\lib_static\libcrypto_static.lib" -DCOMPILED_LIBSSL_PATH="%current_dir%\openssl_%openssl.version%_windows_x64\lib_static\libssl_static.lib" ..
		if errorlevel 1 echo libspdm cmake configure failed
		if errorlevel 1 exit /b 1
		"%NMAKE_EXE%"
		if errorlevel 1 echo libspdm nmake build failed
		if errorlevel 1 exit /b 1
		cd /d "%dependencies_dir%"
		xcopy libspdm\include libspdm_%libspdm.version%_windows_x64\include /E /Y /I || exit /b 1
		xcopy libspdm\build\lib libspdm_%libspdm.version%_windows_x64\lib /E /Y /I || exit /b 1
		for %%f in (debuglib_null.lib, debuglib.lib, malloclib.lib, memlib.lib, platform_lib_null.lib, platform_lib.lib, rnglib.lib, spdm_common_lib.lib, spdm_crypt_lib.lib, spdm_requester_lib.lib, spdm_secured_message_lib.lib, spdm_transport_mctp_lib.lib, cryptlib_openssl.lib, spdm_device_secret_lib_null.lib) do xcopy libspdm\build\lib\%%f libspdm_%libspdm.version%_windows_x64\lib_static\ /E /Y /I || exit /b 1
		powershell Compress-Archive -Path libspdm_%libspdm.version%_windows_x64\* -DestinationPath libspdm-%libspdm.version%-windows-x64.zip
		set libspdm_exists=1
	)
)

:: ====== libcurl ======
If Defined libcurl.version (
	If exist libcurl_%libcurl.version%_windows_x64 (
		If Defined always_build (
			set libcurl_exists=0
		) else (
			set libcurl_exists=1
		)
	)
	If !libcurl_exists!==0 (
		echo building libcurl...
		If not exist "openssl_%openssl.version%_windows_x64" (
			call :build_openssl
			if errorlevel 1 exit /b 1
		)
		if exist curl @RD /S /Q curl
		if exist libcurl_%libcurl.version%_windows_x64 @RD /S /Q libcurl_%libcurl.version%_windows_x64
		call :_fetch_and_verify "curl-!libcurl.version!.tar.gz" "!libcurl.url!" "!libcurl.sha256!" "!libcurl.tarball!"
		if errorlevel 1 exit /b 1
		mkdir "curl"
		tar -xzf "curl-!libcurl.version!.tar.gz" -C "curl" --strip-components=1
		if errorlevel 1 (
			echo [ERROR] Failed to unpack curl-!libcurl.version!.tar.gz
			exit /b 1
		)
		cd curl
		mkdir build
		cd build
		cmake -G "NMake Makefiles" ^
			-DCMAKE_BUILD_TYPE=Release ^
			-DBUILD_SHARED_LIBS=ON ^
			-DBUILD_CURL_EXE=OFF ^
			-DENABLE_MANUAL=OFF ^
			-DBUILD_LIBCURL_DOCS=OFF ^
			-DBUILD_MISC_DOCS=OFF ^
			-DCURL_USE_OPENSSL=ON ^
			-DOPENSSL_ROOT_DIR=%dependencies_dir%\openssl_%openssl.version%_windows_x64 ^
			-DCURL_USE_SCHANNEL=OFF ^
			-DENABLE_IPV6=ON ^
			-DCURL_USE_LIBPSL=OFF ^
			-DIMPORT_LIB_SUFFIX= ^
			-DCMAKE_INSTALL_PREFIX=%dependencies_dir%\libcurl_%libcurl.version%_windows_x64 ^
			..
		if errorlevel 1 echo cmake generation failed
		if errorlevel 1 exit /b 1
		cmake --build . --config Release
		if errorlevel 1 echo cmake build failed
		if errorlevel 1 exit /b 1
		cmake --install . --config Release
		if errorlevel 1 echo cmake install failed
		if errorlevel 1 exit /b 1
		if exist %dependencies_dir%\libcurl_%libcurl.version%_windows_x64\bin\libcurl.dll xcopy /Y %dependencies_dir%\libcurl_%libcurl.version%_windows_x64\bin\libcurl.dll %dependencies_dir%\libcurl_%libcurl.version%_windows_x64\lib\
		if exist %dependencies_dir%\libcurl_%libcurl.version%_windows_x64\lib\libcurl_imp.lib copy /Y %dependencies_dir%\libcurl_%libcurl.version%_windows_x64\lib\libcurl_imp.lib %dependencies_dir%\libcurl_%libcurl.version%_windows_x64\lib\libcurl.lib
		cd /d "%dependencies_dir%"
		powershell Compress-Archive -Path libcurl_%libcurl.version%_windows_x64\* -DestinationPath libcurl-%libcurl.version%-windows-x64.zip
		set libcurl_exists=1
	)
)

:: ====== boost ======
If Defined boost.version (
	If exist boost_%boost.version%_windows_x64 (
		If Defined always_build (
			set boost_exists=0
		) else (
			set boost_exists=1
		)
	)
	If !boost_exists!==0 (
		echo building boost...
		if exist boost @RD /S /Q boost
		if exist boost_%boost.version%_windows_x64 @RD /S /Q boost_%boost.version%_windows_x64
		call :_fetch_and_verify "boost-!boost_version_string!.tar.gz" "!boost.url!" "!boost.sha256!" "!boost.tarball!"
		if errorlevel 1 exit /b 1
		mkdir "boost"
		tar -xzf "boost-!boost_version_string!.tar.gz" -C "boost" --strip-components=1
		if errorlevel 1 (
			echo [ERROR] Failed to unpack boost_!boost_version_string!.tar.gz
			exit /b 1
		)
		cd "boost"
		if errorlevel 1 (
			echo [ERROR] Extracted Boost directory boost not found.
			exit /b 1
		)
		cmd /c .\bootstrap.bat %BOOST_TOOLSET% || exit /b 1
        set "BKPS_BOOST_PROJECT_CONFIG=%TEMP%\bkps-boost-project-config-!RANDOM!-!RANDOM!.jam"
        powershell -NoProfile -Command "$setup = $env:VCVARS_BAT.Replace('\', '/'); @('import option ;', ('using msvc : 14.3 : : <setup>' + [char]34 + $setup + [char]34 + ' ;'), 'option.set keep-going : false ;') | Set-Content -LiteralPath $env:BKPS_BOOST_PROJECT_CONFIG -Encoding ASCII" || exit /b 1
        cmd /c .\b2.exe --project-config="!BKPS_BOOST_PROJECT_CONFIG!" --with-container --with-json --toolset=%BOOST_B2_TOOLSET% architecture=x86 address-model=64 runtime-link=shared link=static variant=release threading=multi install --prefix=output/x64 --layout=system -j4
        set "BKPS_B2_EXIT=!ERRORLEVEL!"
        del /f /q "!BKPS_BOOST_PROJECT_CONFIG!" >nul 2>&1
        if not "!BKPS_B2_EXIT!"=="0" exit /b !BKPS_B2_EXIT!
        cd /d "%dependencies_dir%"
		xcopy boost\output\x64\include boost_%boost.version%_windows_x64\include /E /Y /I || exit /b 1
		mkdir "boost_%boost.version%_windows_x64\lib" 2>nul
		copy /Y boost\output\x64\lib\libboost_container.lib boost_%boost.version%_windows_x64\lib\libboost_container-%BOOST_TOOLSET%-mt-x64-%boost_version_string:~0,-2%.lib || exit /b 1
		copy /Y boost\output\x64\lib\libboost_json.lib boost_%boost.version%_windows_x64\lib\libboost_json-%BOOST_TOOLSET%-mt-x64-%boost_version_string:~0,-2%.lib || exit /b 1
		powershell Compress-Archive -Path boost_%boost.version%_windows_x64\* -DestinationPath boost-%boost.version%-windows-x64.zip
		set boost_exists=1
	)
)

If Defined gtest.version (
	If exist googletest_%gtest.version%_windows_x64 (
		If Defined always_build (
			set gtest_exists=0
		) else (
			set gtest_exists=1
		)
	)
	If !gtest_exists!==0 (
		echo building gtest...
		if exist googletest @RD /S /Q googletest
		if exist googletest_%gtest.version%_windows_x64 @RD /S /Q googletest_%gtest.version%_windows_x64
		call :_fetch_and_verify "gtest-!gtest.version!.tar.gz" "!gtest.url!" "!gtest.sha256!" "!gtest.tarball!"
		if errorlevel 1 exit /b 1
		mkdir "googletest"
		tar -xzf "gtest-!gtest.version!.tar.gz" -C "googletest" --strip-components=1
		if errorlevel 1 (
			echo [ERROR] Failed to unpack gtest-!gtest.version!.tar.gz
			exit /b 1
		)
		cd "googletest"
		if errorlevel 1 (
			echo [ERROR] Extracted googletest directory googletest not found.
			exit /b 1
		)
		"%CMAKE_EXE%" -G"NMake Makefiles" -DBUILD_GMOCK=ON
		call "%NMAKE_EXE%"
		cd /d "%dependencies_dir%"
		xcopy googletest\googletest\include googletest_%gtest.version%_windows_x64\include /E /Y /I || exit /b 1
		xcopy googletest\googlemock\include googletest_%gtest.version%_windows_x64\include /E /Y /I || exit /b 1
		xcopy googletest\lib googletest_%gtest.version%_windows_x64\lib /E /Y /I || exit /b 1
		powershell Compress-Archive -Path googletest_%gtest.version%_windows_x64\* -DestinationPath googletest-%gtest.version%-windows-x64.zip
		set gtest_exists=1
	)
)

if /i not "%BUILD_SELECTION%"=="bkp_only" if !openssl_exists! == 1 if !libcurl_exists! == 1 if !boost_exists! == 1 if !gtest_exists! == 1 (
	::build bkpprogrammer
	echo buiding bkpprogrammer...
	cd /d %bkpprogrammer_dir%
	if exist dependencies @RD /S /Q dependencies
	if exist build @RD /S /Q build
	xcopy "%dependencies_dir%\openssl_%openssl.version%_windows_x64" dependencies\openssl /E /Y /I || exit /b 1
	xcopy "%dependencies_dir%\boost_%boost.version%_windows_x64" dependencies\boost /E /Y /I || exit /b 1
	xcopy "%dependencies_dir%\libcurl_%libcurl.version%_windows_x64" dependencies\libcurl /E /Y /I || exit /b 1
	xcopy "%dependencies_dir%\googletest_%gtest.version%_windows_x64" dependencies\gtest /E /Y /I || exit /b 1
	mkdir build
	cd build
	"%CMAKE_EXE%" -D DISABLE_TESTS:BOOL=ON -D DISABLE_BKP_APP:BOOL=ON -DCMAKE_RULE_MESSAGES:BOOL=OFF -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -D CMAKE_BUILD_TYPE:STRING=Release -G "%CMAKE_VS_GENERATOR%" %CMAKE_VS_ARCH% -T "%CMAKE_VS_TOOLSET%" ..
	"%CMAKE_EXE%" --build . --config Release
)

if !libspdm_exists! == 1 if !openssl_exists! == 1 (
	::build spdm_wrapper
	echo buiding spdm_wrapper...
	cd /d %spdm_wrapper_dir%
	if exist dependencies @RD /S /Q dependencies
	if exist build @RD /S /Q build
	xcopy "%dependencies_dir%\openssl_%openssl.version%_windows_x64" dependencies\openssl /E /Y /I || exit /b 1
	xcopy "%dependencies_dir%\libspdm_%libspdm.version%_windows_x64" dependencies\libspdm /E /Y /I || exit /b 1
	mkdir build
	cd build
	"%CMAKE_EXE%" -G "%CMAKE_VS_GENERATOR%" %CMAKE_VS_ARCH% ..
	"%CMAKE_EXE%" --build . --config Release
)

::Java Gradle build
cd "%current_dir%"
If exist "%KEYSTORE_TRUSTSTORE_PATH%" (
	echo List dummy keys...
	@echo on
	%KEYTOOL_EXE% -list -keystore "%KEYSTORE_TRUSTSTORE_PATH%" -storepass donotchange -alias dummy
)

If not exist "%KEYSTORE_TRUSTSTORE_PATH%" (
	echo Generate dummy key...
	%KEYTOOL_EXE% -genkey -keyalg RSA -keystore "%KEYSTORE_TRUSTSTORE_PATH%" -keysize 2048 -keypass donotchange -storepass donotchange -dname "CN=Developer, OU=Department, O=Company, L=City, ST=State, C=CA" -alias dummy
)
set KEYSTORE_DUMMY_ALIAS=dummy
del /f /q "%current_dir%\bkps\bkps-%BUILD_VERSION%.sql"
del /f /q "%current_dir%\bkps\changelog-bkps-%BUILD_VERSION%.csv"
if /i "%BUILD_SELECTION%"=="full" (
	:: Windows integration fixtures use Linux-only /tmp paths; run unit tests + assemble.
	call gradlew.bat clean test assemble -Pversion=%BUILD_VERSION% -Dversion=%BUILD_VERSION% || exit /b 1
) else (
	call gradlew.bat clean :bkps:bootJar -Pversion=%BUILD_VERSION% -Dversion=%BUILD_VERSION% || exit /b 1
)
call gradlew.bat -Pprod -Paws -Pversion=%BUILD_VERSION% -Dversion=%BUILD_VERSION% :bkps:liquibaseGenerateSql || exit /b 1


::Copy result files
:: -----------------------------------------------------------------
::   out\
::	   Verifier-<ver>.jar
::	   workload-<ver>.jar
::	   bkps-<ver>.jar
::	   bkps-<ver>.sql
::	   config.properties
::	   spdm_wrapper\wrapper\libspdm_wrapper.dll
::	   bkpprogrammer\
::		   <other bkpprogrammer runtime DLLs>
:: -----------------------------------------------------------------
if exist "%output_dir%" @RD /S /Q "%output_dir%"
mkdir "%output_dir%"

:: --- Java artifacts (jars): flatten into %output_dir% ----------------
call xcopy bkps\build\libs\*.jar							"%output_dir%" /E /Y /I || exit /b 1
if /i "%BUILD_SELECTION%"=="full" (
	call xcopy Verifier\build\libs\*.jar						"%output_dir%" /E /Y /I || exit /b 1
	call xcopy workload\build\libs\*.jar						"%output_dir%" /E /Y /I || exit /b 1
	call xcopy Verifier\src\main\resources\config.properties				"%output_dir%" /E /Y /I || exit /b 1
)

:: --- SQL schema: flatten into %output_dir% ---------------------------
call xcopy bkps\*.sql						   "%output_dir%" /E /Y /I || exit /b 1

:: --- SPDM wrapper native library ----
if not exist "%output_dir%\spdm_wrapper\wrapper" mkdir "%output_dir%\spdm_wrapper\wrapper"
call xcopy spdm_wrapper\build\wrapper\Release\*.dll		 "%output_dir%\spdm_wrapper\wrapper" /E /Y /I || exit /b 1

:: --- BKPS Programmer native artifacts ------
if /i not "%BUILD_SELECTION%"=="bkp_only" (
	if not exist "%output_dir%\bkpprogrammer" mkdir "%output_dir%\bkpprogrammer"
	call xcopy bkpprogrammer\build\Release\*.dll				"%output_dir%\bkpprogrammer" /E /Y /I || exit /b 1
)

echo.
echo ============================================================
echo  Generated Files Summary
echo ============================================================
echo Output folder:
echo   %output_dir%
echo.
dir /b /s "%output_dir%"
echo ============================================================

endlocal
EXIT /B %ERRORLEVEL%

:build_openssl
echo building openssl...
if exist openssl @RD /S /Q openssl
if exist openssl_%openssl.version%_windows_x64 @RD /S /Q openssl_%openssl.version%_windows_x64
call :_fetch_and_verify "openssl-!openssl.version!.tar.gz" "!openssl.url!" "!openssl.sha256!" "!openssl.tarball!"
if errorlevel 1 exit /b 1
mkdir "openssl"
tar -xzf "openssl-!openssl.version!.tar.gz" -C "openssl" --strip-components=1
if errorlevel 1 (
	echo [ERROR] Failed to unpack openssl-!openssl.version!.tar.gz
	exit /b 1
)
cd "openssl"
if errorlevel 1 (
	echo [ERROR] Extracted OpenSSL directory openssl not found.
	exit /b 1
)
if not exist "C:\Strawberry\perl\bin\perl.exe" (
	echo [ERROR] Strawberry Perl not found at C:\Strawberry\perl\bin\perl.exe
	echo         Required for MSVC OpenSSL Configure ^(VC-WIN64A^).
	exit /b 1
)
:: Use Configure ^(capital C^). Lowercase "configure" can pick up the wrong file.
C:\Strawberry\perl\bin\perl.exe Configure VC-WIN64A no-asm
if errorlevel 1 (
	echo [ERROR] OpenSSL Configure VC-WIN64A failed.
	exit /b 1
)
"%NMAKE_EXE%"
if errorlevel 1 (
	echo [ERROR] OpenSSL nmake failed.
	echo         If you previously used wrapper-only / MSYS2, open a FRESH cmd
	echo         window so MSYS sh/make/echo are not ahead of Windows tools on PATH.
	exit /b 1
)
cd /d "%dependencies_dir%"
xcopy openssl\include openssl_%openssl.version%_windows_x64\include /E /Y /I || exit /b 1
xcopy openssl\libcrypto-3-x64.dll openssl_%openssl.version%_windows_x64\lib\ /E /Y /I || exit /b 1
xcopy openssl\libcrypto.lib openssl_%openssl.version%_windows_x64\lib\ /E /Y /I || exit /b 1
xcopy openssl\libssl-3-x64.dll openssl_%openssl.version%_windows_x64\lib\  /E /Y /I  || exit /b 1
xcopy openssl\libssl.lib openssl_%openssl.version%_windows_x64\lib\ /E /Y /I  || exit /b 1
xcopy openssl\libcrypto_static.lib openssl_%openssl.version%_windows_x64\lib\ /E /Y /I || exit /b 1
xcopy openssl\libssl_static.lib openssl_%openssl.version%_windows_x64\lib\ /E /Y /I || exit /b 1
powershell Compress-Archive -Path openssl_%openssl.version%_windows_x64\* -DestinationPath openssl-%openssl.version%-windows-x64.zip
set openssl_exists=1
exit /b 0

:print_usage
echo Usage: build-dependencies-ext.bat [VS Build Directory] [version] [options]
echo.
echo Build selection:
echo   --full                       Build every module (default).
echo   --bkp-with-bkpprogrammer     Build BKPS (JAR, SQL, SPDM wrapper) and BKPProgrammer.
echo   --bkp-only                   Build only the BKPS JAR, SQL schema and SPDM wrapper.
exit /b 1

:: ============================================================
:: :_load_config <file>
:: Read dotted key=value pins. Skip blank lines and # comments.
:: Does not override variables already set in the environment.
:: ============================================================
:_load_config
if not exist "%~1" exit /b 0
echo [pins] Loading %~1
for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%~1") do (
	if not "%%~A"=="" (
		if not defined %%A set "%%A=%%B"
	)
)

call :_resolve_urls
if errorlevel 1 exit /b 1

echo [pins] openssl !openssl.version!  sha256=!openssl.sha256!
echo [pins] libspdm !libspdm.version!  sha256=!libspdm.sha256!
echo [pins] boost   !boost.version!    sha256=!boost.sha256!
echo [pins] libcurl !libcurl.version!  sha256=!libcurl.sha256!
echo [pins] gtest   !gtest.version!    sha256=!gtest.sha256!
exit /b 0

:_resolve_urls
if defined openssl.version set "openssl.url=https://www.openssl.org/source/openssl-!openssl.version!.tar.gz"
if defined libspdm.version set "libspdm.url=https://github.com/DMTF/libspdm/archive/refs/tags/!libspdm.version!.tar.gz"
if defined boost.version (
	set "_boost_us=!boost.version:.=_!"
	set "boost.url=https://archives.boost.io/release/!boost.version!/source/boost_!_boost_us!.tar.gz"
)
if defined libcurl.version set "libcurl.url=https://curl.se/download/curl-!libcurl.version!.tar.gz"
if defined gtest.version set "gtest.url=https://github.com/google/googletest/archive/refs/tags/v!gtest.version!.tar.gz"
exit /b 0

:: ============================================================
:: :_fetch_and_verify <dest> <url> <sha256> [local_tarball]
:: Copy a customer/internal tarball or download from <url>, then
:: compare SHA256 and fail closed before the caller runs tar.
:: ============================================================
:_fetch_and_verify
set "_dest=%~1"
set "_url=%~2"
set "_sha=%~3"
set "_local=%~4"
set "_sha=!_sha: =!"
if "!_sha!"=="" (
	echo [ERROR] SHA256 not provided for !_dest! — refuse to unpack
	exit /b 1
)
if not "!_local!"=="" (
	for %%I in ("!_local!") do set "_local=%%~fI"
	if not exist "!_local!" (
		echo [ERROR] Local tarball not found: !_local!
		exit /b 1
	)
	echo Using local tarball: !_local!
	copy /Y "!_local!" "!_dest!" >nul
	if errorlevel 1 (
		echo [ERROR] Failed to copy !_local! to !_dest!
		exit /b 1
	)
) else if not exist "!_dest!" (
	if "!_url!"=="" (
		echo [ERROR] Download URL not provided for !_dest!
		exit /b 1
	)
	echo Downloading !_dest! from !_url!
	curl.exe -L --ssl-no-revoke --fail --retry 3 -o "!_dest!" "!_url!"
	if errorlevel 1 (
		echo [ERROR] Failed to download !_dest!
		exit /b 1
	)
) else (
	echo Package already present: !_dest!
)
if not exist "!_dest!" (
	echo [ERROR] Tarball missing after fetch: !_dest!
	exit /b 1
)
echo Verifying SHA256 of !_dest!
set "_got="
for /f "usebackq delims=" %%H in (`powershell -NoProfile -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath '!_dest!').Hash.ToLower()"`) do set "_got=%%H"
if "!_got!"=="" (
	echo [ERROR] Failed to compute SHA256 for !_dest!
	exit /b 1
)
if /I not "!_got!"=="!_sha!" (
	echo [ERROR] SHA256 mismatch for !_dest!
	echo         expected: !_sha!
	echo         actual:      !_got!
	exit /b 1
)
echo SHA256 OK: !_dest!
exit /b 0

:_prompt_nonempty
set "%~1="
:_prompt_nonempty_loop
set /p "%~1=%~2"
call set "_tmp=%%%~1%%"
set "_tmp=!_tmp:"=!"
set "%~1=!_tmp!"
set "_tmp="
if not defined %~1 (
	echo		 [warn] Empty input is not allowed. Please enter a value.
	goto :_prompt_nonempty_loop
)
exit /b 0

:_prompt_vs_script_path
echo [vcvars] Visual Studio was not found automatically.
echo		 Enter the full parent path to %~2 and %~3,
echo		 e.g. "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build"
echo		 Tip: set %~1=... in your environment to skip this prompt next time.
call :_prompt_nonempty %~1 "%~2 and %~3 path: "
exit /b 0

:_prompt_tool_exe
echo [vcvars] WARNING: VS-bundled %~2 not found at:
echo		 !%~1!
echo		 Install the "%~3" component in the
echo		 Visual Studio Installer to bundle %~2 with your VS install.
echo		 Enter the full path that contains %~2
call :_prompt_nonempty %~1 "%~2 path: "
exit /b 0

:_check_bat_existence
if exist "!VS_BUILD_DIR!\vcvarsall.bat" (
	set "VCVARS_BAT=!VS_BUILD_DIR!\vcvarsall.bat"
) else (
	echo [ERROR] vcvarsall.bat not found at: !VS_BUILD_DIR!
	set "VCVARS_BAT="
)

if exist "!VS_BUILD_DIR!\vcvarsamd64_x86.bat" (
	set "VCVARS_X86_BAT=!VS_BUILD_DIR!\vcvarsamd64_x86.bat"
) else (
	echo [ERROR] vcvarsamd64_x86.bat not found at: !VS_BUILD_DIR!
	set "VCVARS_X86_BAT="
)
exit /b 0

:_probe_vcvars
if defined VCVARS_BAT (
	 if defined VCVARS_X86_BAT (
		echo [vcvars] Detected at well-known path: !VCVARS_BAT! !VCVARS_X86_BAT!
		echo [vcvars] vcvarsall.bat: !VCVARS_BAT!
		echo [vcvars] vcvarsamd64_x86.bat: !VCVARS_X86_BAT!
	) else (
		call :_prompt_vs_script_path VS_BUILD_DIR vcvarsall.bat vcvarsamd64_x86.bat
	)
) else (
	call :_prompt_vs_script_path VS_BUILD_DIR vcvarsall.bat vcvarsamd64_x86.bat
)

if defined VS_BUILD_DIR (
	call :_check_bat_existence
)
if not defined VCVARS_BAT goto :_probe_vcvars
if not defined VCVARS_X86_BAT goto :_probe_vcvars
exit /b 0

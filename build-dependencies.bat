@echo off
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
set "VS_BUILD_DIR=%~1"
set "BUILD_VERSION=%~2"
:: Use command build-dependencies.bat <Visual Studio Build Directory> <Optional: BKPS/Verifier Output Build Version>
for /f "delims=" %%x in (config.txt) do (
	set "%%x"
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

 :: Auto detect toolset used as a visual studio version can have non-unique toolset
 for /f "tokens=1,2 delims=." %%A in ("%VCToolsVersion%") do (
 	set "_minor=%%B"

	:: Enable local environment manipulation to slice the string safely
	setlocal enabledelayedexpansion
	set "_first_minor=!_minor:~0,1!"

	:: Pass the variables cleanly past the endlocal boundary
	for /f "tokens=1,2" %%X in ("!_first_minor! %%A") do (
		endlocal
		set "BOOST_TOOLSET=vc%%Y%%X"
		set "BOOST_B2_TOOLSET=msvc-%%Y.%%X"
		set "CMAKE_VS_TOOLSET=v%%Y%%X"
	)
 )

echo ===================================================
echo MSVC Full Toolset Version:  %VCToolsVersion%
echo Visual Studio IDE Version:  %VSCMD_VER%
echo Target Architecture:		%VSCMD_ARG_TGT_ARCH%
echo Windows SDK Version:		%WindowsSDKVersion%
echo BOOST_TOOLSET			   %BOOST_TOOLSET%
echo BOOST_B2_TOOLSET			%BOOST_B2_TOOLSET%
echo CMAKE_VS_GENERATOR		  %CMAKE_VS_GENERATOR%
echo CMAKE_VS_TOOLSET			%CMAKE_VS_TOOLSET%
echo CMake generator			 %CMAKE_VS_GENERATOR%  %CMAKE_VS_ARCH%  (toolset %CMAKE_VS_TOOLSET%)
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
cd "%dependencies_dir%"
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
		:build_openssl
		echo building openssl...
		@RD /S /Q openssl
		@RD /S /Q openssl_%openssl.version%_windows_x64
		git clone https://github.com/openssl/openssl.git
		cd openssl
		git pull
		git fetch --all --tags
		git checkout tags/openssl-%openssl.version%
		call C:\Strawberry\perl\bin\perl.exe configure VC-WIN64A no-asm
		call "%NMAKE_EXE%"
		cd "%dependencies_dir%"
		xcopy openssl\include openssl_%openssl.version%_windows_x64\include /E /Y /I || exit /b 1
		xcopy openssl\libcrypto-3-x64.dll openssl_%openssl.version%_windows_x64\lib\ /E /Y /I || exit /b 1
		xcopy openssl\libcrypto.lib openssl_%openssl.version%_windows_x64\lib\ /E /Y /I || exit /b 1
		xcopy openssl\libssl-3-x64.dll openssl_%openssl.version%_windows_x64\lib\  /E /Y /I  || exit /b 1
		xcopy openssl\libssl.lib openssl_%openssl.version%_windows_x64\lib\ /E /Y /I  || exit /b 1
		xcopy openssl\libcrypto_static.lib openssl_%openssl.version%_windows_x64\lib\ /E /Y /I || exit /b 1
		xcopy openssl\libssl_static.lib openssl_%openssl.version%_windows_x64\lib\ /E /Y /I || exit /b 1
		powershell Compress-Archive -Path openssl_%openssl.version%_windows_x64\* -DestinationPath openssl-%openssl.version%-windows-x64.zip
		set openssl_exists=1
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
		@RD /S /Q libspdm
		@RD /S /Q libspdm_%libspdm.version%_windows_x64
		If not exist "openssl" goto build_openssl
		git clone https://github.com/DMTF/libspdm.git
		cd libspdm
		git pull
		git fetch --all --tags
		git checkout tags/%libspdm.version%
		git submodule update --init unit_test/cmockalib/cmocka
		mkdir build
		cd build
		set "custom_defines=-DLIBSPDM_MAX_MESSAGE_BUFFER_SIZE=20000 -DLIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN=15000 -DLIBSPDM_MAX_CERT_CHAIN_SIZE=18000 -DLIBSPDM_MAX_MEASUREMENT_RECORD_SIZE=15000"
		set "algorithms_enabled=-DLIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT=1"
		set "algorithms_disabled=-DLIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_CSR_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_HBEAT_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_PSK_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_CHAL_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP=0"
		set openssl_include_dir="%dependencies_dir%\openssl_%openssl.version%_windows_x64\include"
		"%CMAKE_EXE%" -G"NMake Makefiles" -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -DARCH=x64 -DTOOLCHAIN=VS2015 -DTARGET=Release -DDISABLE_TESTS=1 -DCRYPTO=openssl -DCMAKE_C_FLAGS="!custom_defines! !algorithms_enabled! !algorithms_disabled! -I!openssl_include_dir! /GL- /wd4565" -DENABLE_BINARY_BUILD=1 -DCOMPILED_LIBCRYPTO_PATH="%current_dir%\openssl_%openssl.version%_windows_x64\lib_static\libcrypto_static.lib" -DCOMPILED_LIBSSL_PATH="%current_dir%\openssl_%openssl.version%_windows_x64\lib_static\libssl_static.lib" ..
		"%NMAKE_EXE%"
		cd "%dependencies_dir%"
		xcopy libspdm\include libspdm_%libspdm.version%_windows_x64\include /E /Y /I || exit /b 1
		xcopy libspdm\build\lib libspdm_%libspdm.version%_windows_x64\lib /E /Y /I || exit /b 1
		for %%f in (debuglib_null.lib, debuglib.lib, malloclib.lib, memlib.lib, platform_lib_null.lib, platform_lib.lib, rnglib.lib, spdm_common_lib.lib, spdm_crypt_lib.lib, spdm_requester_lib.lib, spdm_secured_message_lib.lib, spdm_transport_mctp_lib.lib, cryptlib_openssl.lib, spdm_device_secret_lib_null.lib) do xcopy libspdm\build\lib\%%f libspdm_%libspdm.version%_windows_x64\lib_static\ /E /Y /I || exit /b 1
		cd "%dependencies_dir%"
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
		@RD /S /Q curl-%libcurl.version%
		@RD /S /Q libcurl_%libcurl.version%_windows_x64
		If not exist "openssl" goto build_openssl
		curl --ssl-no-revoke https://curl.se/download/curl-%libcurl.version%.tar.gz --output curl-%libcurl.version%.tar.gz
		tar -xzf curl-%libcurl.version%.tar.gz
		cd curl-%libcurl.version%
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
			-DCMAKE_INSTALL_PREFIX=%dependencies_dir%\libcurl_%libcurl.version%_windows_x64 ^
			..
		cmake --build . --config Release
		cmake --install . --config Release
		if exist %dependencies_dir%\libcurl_%libcurl.version%_windows_x64\bin\libcurl.dll xcopy /Y %dependencies_dir%\libcurl_%libcurl.version%_windows_x64\bin\libcurl.dll %dependencies_dir%\libcurl_%libcurl.version%_windows_x64\lib\
		if exist %dependencies_dir%\libcurl_%libcurl.version%_windows_x64\lib\libcurl_imp.lib copy /Y %dependencies_dir%\libcurl_%libcurl.version%_windows_x64\lib\libcurl_imp.lib %dependencies_dir%\libcurl_%libcurl.version%_windows_x64\lib\libcurl.lib
		cd "%dependencies_dir%"
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
		@RD /S /Q boost-%boost.version%
		@RD /S /Q boost_%boost.version%_windows_x64
		curl -L --ssl-no-revoke https://github.com/boostorg/boost/releases/download/boost-%boost.version%/boost-%boost.version%.tar.gz --output boost_%boost.version%.tar.gz
		tar -xzf boost_%boost.version%.tar.gz
		cd boost-%boost.version%
		cmd /c .\bootstrap.bat %BOOST_TOOLSET%
		cmd /c .\b2.exe --toolset=%BOOST_B2_TOOLSET% architecture=x86 address-model=64 runtime-link=shared link=static variant=release threading=multi install --prefix=output/x64 --layout=system -j4
		cd "%dependencies_dir%"
		xcopy boost-%boost.version%\output\x64\include boost_%boost.version%_windows_x64\include /E /Y /I || exit /b 1
		mkdir "boost_%boost.version%_windows_x64\lib" 2>nul
		copy /Y boost-%boost.version%\output\x64\lib\libboost_container.lib boost_%boost.version%_windows_x64\lib\libboost_container-%BOOST_TOOLSET%-mt-x64-%boost_version_string:~0,-2%.lib || exit /b 1
		copy /Y boost-%boost.version%\output\x64\lib\libboost_json.lib boost_%boost.version%_windows_x64\lib\libboost_json-%BOOST_TOOLSET%-mt-x64-%boost_version_string:~0,-2%.lib || exit /b 1
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
		@RD /S /Q googletest
		@RD /S /Q googletest_%gtest.version%_windows_x64
		git clone https://github.com/google/googletest.git
		cd googletest
		git pull
		git fetch --all --tags
		git checkout tags/v%gtest.version%
		"%CMAKE_EXE%" -G"NMake Makefiles" -DBUILD_GMOCK=ON
		call "%NMAKE_EXE%"
		cd "%dependencies_dir%"
		xcopy googletest\googletest\include googletest_%gtest.version%_windows_x64\include /E /Y /I || exit /b 1
		xcopy googletest\googlemock\include googletest_%gtest.version%_windows_x64\include /E /Y /I || exit /b 1
		xcopy googletest\lib googletest_%gtest.version%_windows_x64\lib /E /Y /I || exit /b 1
		powershell Compress-Archive -Path googletest_%gtest.version%_windows_x64\* -DestinationPath googletest-%gtest.version%-windows-x64.zip
		set gtest_exists=1
	)
)

::build bkpprogrammer
echo buiding bkpprogrammer...
cd "%bkpprogrammer_dir%"
@RD /S /Q dependencies
@RD /S /Q build
xcopy "%dependencies_dir%\openssl_%openssl.version%_windows_x64" dependencies\openssl /E /Y /I || exit /b 1
xcopy "%dependencies_dir%\boost_%boost.version%_windows_x64" dependencies\boost /E /Y /I || exit /b 1
xcopy "%dependencies_dir%\libcurl_%libcurl.version%_windows_x64" dependencies\libcurl /E /Y /I || exit /b 1
xcopy "%dependencies_dir%\googletest_%gtest.version%_windows_x64" dependencies\gtest /E /Y /I || exit /b 1
mkdir build
cd build
"%CMAKE_EXE%" -D DISABLE_TESTS:BOOL=ON -D DISABLE_BKP_APP:BOOL=ON -DCMAKE_RULE_MESSAGES:BOOL=OFF -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -D CMAKE_BUILD_TYPE:STRING=Release -G "%CMAKE_VS_GENERATOR%" %CMAKE_VS_ARCH% -T "%CMAKE_VS_TOOLSET%" ..
"%CMAKE_EXE%" --build . --config Release

::build spdm_wrapper
echo buiding spdm_wrapper...
cd "%spdm_wrapper_dir%"
@RD /S /Q dependencies
@RD /S /Q build
xcopy "%dependencies_dir%\openssl_%openssl.version%_windows_x64" dependencies\openssl /E /Y /I || exit /b 1
xcopy "%dependencies_dir%\libspdm_%libspdm.version%_windows_x64" dependencies\libspdm /E /Y /I || exit /b 1
mkdir build
cd build
"%CMAKE_EXE%" -G "%CMAKE_VS_GENERATOR%" %CMAKE_VS_ARCH% ..
"%CMAKE_EXE%" --build . --config Release

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
call gradlew.bat  clean build -Pversion=%BUILD_VERSION% -Dversion=%BUILD_VERSION%
call gradlew.bat -Pprod -Paws -Pversion=%BUILD_VERSION% -Dversion=%BUILD_VERSION% :bkps:liquibaseGenerateSql

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
@RD /S /Q "%output_dir%"
mkdir "%output_dir%"

:: --- Java artifacts (jars): flatten into %output_dir% ----------------
call xcopy bkps\build\libs\*.jar							"%output_dir%" /E /Y /I || exit /b 1
call xcopy Verifier\build\libs\*.jar						"%output_dir%" /E /Y /I || exit /b 1
call xcopy workload\build\libs\*.jar						"%output_dir%" /E /Y /I || exit /b 1

:: --- SQL schema: flatten into %output_dir% ---------------------------
call xcopy bkps\*.sql						   "%output_dir%" /E /Y /I || exit /b 1

:: --- Verifier runtime config.properties ------------------------------
call xcopy Verifier\src\main\resources\config.properties				"%output_dir%" /E /Y /I || exit /b 1

:: --- SPDM wrapper native library ----
if not exist "%output_dir%\spdm_wrapper\wrapper" mkdir "%output_dir%\spdm_wrapper\wrapper"
call xcopy spdm_wrapper\build\wrapper\Release\*.dll		 "%output_dir%\spdm_wrapper\wrapper" /E /Y /I || exit /b 1

:: --- BKPS Programmer native artifacts ------
if not exist "%output_dir%\bkpprogrammer" mkdir "%output_dir%\bkpprogrammer"
call xcopy bkpprogrammer\build\Release\*.dll				"%output_dir%\bkpprogrammer" /E /Y /I || exit /b 1

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

@echo off
setlocal

if /I not "%~1"=="query" (
    1>&2 echo ERROR: The BKPS registry compatibility shim only supports read-only REG QUERY operations.
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0reg_query.ps1" %*
exit /b %errorlevel%

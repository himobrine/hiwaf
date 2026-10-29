@echo off
setlocal
REM One-click installer entry for Windows. All logic lives in install.ps1.
REM Keep this file ASCII-only (see SETUP.md pitfall 12).
REM
REM   install.bat -NoRust -NoStart
REM   install.bat -Verify
REM
REM Set WAF_NO_PAUSE=1 to skip the final "press any key" (CI / scripted use).

set "ROOT=%~dp0"
if not exist "%ROOT%install.ps1" (
    echo [x] install.ps1 not found next to install.bat: %ROOT%
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ROOT%install.ps1" %*
set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" echo [x] installation failed with exit code %RC%

if not defined WAF_NO_PAUSE (
    echo.
    pause
)
exit /b %RC%

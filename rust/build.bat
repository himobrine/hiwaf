@echo off
setlocal
REM Portable build wrapper: locate MSVC (vcvars64) + cargo, then call cargo.
REM Keep this file ASCII-only: Chinese REM lines with LF endings are parsed as commands by cmd.

if not defined LOCALAPPDATA set "LOCALAPPDATA=%USERPROFILE%\AppData\Local"

REM 1) MSVC environment. Prefer vswhere, then this repo's historical D:\visual_studio,
REM    then the default VS 2022 install roots.
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSINSTALL="
if exist "%VSWHERE%" for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%i"
if defined VSINSTALL if exist "%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat" call "%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if not defined VSCMD_ARG_TGT_ARCH if exist "D:\visual_studio\VC\Auxiliary\Build\vcvars64.bat" call "D:\visual_studio\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if not defined VSCMD_ARG_TGT_ARCH if exist "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" call "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if not defined VSCMD_ARG_TGT_ARCH if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if not defined VSCMD_ARG_TGT_ARCH if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" call "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if not defined VSCMD_ARG_TGT_ARCH if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" call "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

REM 2) cargo: add rustup's default bin dir when it is not on PATH.
where cargo >nul 2>&1
if errorlevel 1 if exist "%USERPROFILE%\.cargo\bin\cargo.exe" set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
where cargo >nul 2>&1
if errorlevel 1 (
  echo [build] cargo not found. Install Rust from https://rustup.rs and retry.
  exit /b 1
)

REM 3) Shared build cache. Prefer E:\waf-target when E: exists (this repo's machine),
REM    otherwise use a per-user cache so a fresh Windows box works without E:.
if not defined WAF_CARGO_TARGET (
  if exist E:\ (
    set "WAF_CARGO_TARGET=E:\waf-target"
  ) else (
    set "WAF_CARGO_TARGET=%LOCALAPPDATA%\waf-cargo-target"
  )
)
set "CARGO_TARGET_DIR=%WAF_CARGO_TARGET%"

cargo %*
exit /b %ERRORLEVEL%

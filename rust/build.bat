@echo off
REM Build wrapper: set up MSVC + Windows SDK environment, then call cargo.
REM Keep this file ASCII-only: Chinese REM lines with LF endings get parsed as commands by cmd
REM (which then silently skips the "set" lines below).
call "D:\visual_studio\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set "PATH=C:\Users\lenovo\.cargo\bin;%PATH%"

REM F: is nearly full, and the ort/ONNX-Runtime tree is huge. Put the build cache on E:
REM and SHARE it with proxy/ (set the same WAF_CARGO_TARGET there) so that ort is compiled
REM once instead of once per crate. Override WAF_CARGO_TARGET to change the location.
if not defined WAF_CARGO_TARGET set "WAF_CARGO_TARGET=E:\waf-target"
set "CARGO_TARGET_DIR=%WAF_CARGO_TARGET%"

cargo %*

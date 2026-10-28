@echo off
REM Build wrapper for the collector data plane. Same pattern as rust\build.bat and proxy_spike\build.bat.
REM NOTE: keep this file ASCII-only - Chinese REM lines + LF endings get parsed as commands by cmd,
REM which silently skips the "set" lines below and produces bogus cmake/generator errors.
call "D:\visual_studio\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set "PATH=C:\Users\lenovo\.cargo\bin;%PATH%"

REM pingora -> flate2(zlib-ng) -> libz-ng-sys invokes cmake; cmake-rs detects "Visual Studio 18 2026"
REM which cmake 4.1.2 does not know. Use the Ninja generator instead.
set "CMAKE_GENERATOR=Ninja"

REM Share the build cache with rust/ (see rust\build.bat): F: is nearly full and the
REM ort/ONNX-Runtime tree must be compiled once, not once per crate.
if not defined WAF_CARGO_TARGET set "WAF_CARGO_TARGET=E:\waf-target"
set "CARGO_TARGET_DIR=%WAF_CARGO_TARGET%"

cargo %*

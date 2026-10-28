@echo off
REM S4 spike build wrapper: same idea as rust\build.bat - set up MSVC env, then call cargo.
call "D:\visual_studio\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set "PATH=C:\Users\lenovo\.cargo\bin;%PATH%"

REM Local gotcha: pingora -> flate2(zlib-ng) -> libz-ng-sys invokes cmake, and cmake-rs
REM auto-detects this box as "Visual Studio 18 2026", which cmake 4.1.2 does not know:
REM     CMake Error: Could not create named generator Visual Studio 18 2026
REM Use the Ninja generator instead (ninja is on PATH; works with vcvars cl.exe).
set "CMAKE_GENERATOR=Ninja"

cargo %*

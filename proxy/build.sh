#!/usr/bin/env bash
# Portable build wrapper for the collector data plane. Mirrors proxy/build.bat.
#
#   ./build.sh build --release
#   ./build.sh run --release -- --listen 127.0.0.1:6188 --upstream 127.0.0.1:80
#
# Pingora -> flate2(zlib-ng) -> libz-ng-sys invokes cmake. Ninja is the
# generator verified in this repo (cmake 4.x does not know VS 18/2026).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v cargo >/dev/null 2>&1; then
    if [ -x "$HOME/.cargo/bin/cargo" ]; then
        export PATH="$HOME/.cargo/bin:$PATH"
    else
        echo "[build] cargo not found. Install Rust from https://rustup.rs and retry." >&2
        exit 1
    fi
fi

for tool in cmake ninja; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "[build] $tool not found. Install it first (e.g. apt install cmake ninja-build)." >&2
        exit 1
    fi
done

export CMAKE_GENERATOR="${CMAKE_GENERATOR:-Ninja}"
export CARGO_TARGET_DIR="${WAF_CARGO_TARGET:-$HOME/.cache/waf-cargo-target}"

set +e
cargo "$@"
rc=$?
set -e

# `cargo build --release` also publishes the collector to <repo>/bin so the
# console resolves a project-local binary instead of a machine-specific cache.
if [ "$rc" -eq 0 ]; then
    want_build=0
    want_release=0
    for arg in "$@"; do
        if [ "$arg" = "build" ]; then want_build=1; fi
        if [ "$arg" = "--release" ]; then want_release=1; fi
    done
    if [ "$want_build" -eq 1 ] && [ "$want_release" -eq 1 ]; then
        src="$CARGO_TARGET_DIR/release/waf-collector"
        dest="$PWD/../bin/waf-collector"
        if [ ! -x "$src" ]; then
            echo "[build] warning: $src not found; skip publishing to bin" >&2
        else
            mkdir -p "$(dirname "$dest")"
            if cp -f "$src" "$dest" 2>/dev/null; then
                chmod +x "$dest"
                echo "[build] published $dest"
            else
                echo "[build] warning: cannot write $dest" >&2
                echo "[build] stop the collector first, then rebuild" >&2
            fi
        fi
    fi
fi

exit "$rc"

#!/usr/bin/env bash
# Portable build wrapper for the Rust engine. Mirrors rust/build.bat.
#
#   ./build.sh build --release
#   ./build.sh run --release
#   ./build.sh test --release --lib
#
# Build cache: WAF_CARGO_TARGET (default ~/.cache/waf-cargo-target).
# The console's proxy_manager also looks in this default location.
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

export CARGO_TARGET_DIR="${WAF_CARGO_TARGET:-$HOME/.cache/waf-cargo-target}"
exec cargo "$@"

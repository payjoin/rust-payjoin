#!/usr/bin/env bash
set -euo pipefail

# Standalone iOS build test for the React Native bindings.
#
# Builds the payjoin-ffi static framework for iOS device + simulator and
# generates the JSI Turbo Module, then typechecks the generated TypeScript.
# Requires Xcode and the iOS Rust targets; only runs on macOS.

OS=$(uname -s)
if [[ $OS != "Darwin" ]]; then
    echo "Error: iOS builds require macOS (found $OS)." >&2
    exit 1
fi

cd "$(dirname "$0")/.."

# See scripts/generate_bindings.sh for why this is set.
export CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback

if command -v rustup >/dev/null 2>&1 &&
    rustup show active-toolchain >/dev/null 2>&1; then
    rustup target add \
        aarch64-apple-ios \
        aarch64-apple-ios-sim \
        x86_64-apple-ios
fi

echo "==> Building iOS framework and generating Turbo Module..."
npm run ubrn:ios

echo "==> Typechecking generated bindings..."
npm run typecheck

echo "iOS build test complete."

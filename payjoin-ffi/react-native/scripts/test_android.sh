#!/usr/bin/env bash
set -euo pipefail

# Standalone Android build test for the React Native bindings.
#
# Builds the payjoin-ffi .so for every Android ABI and generates the JSI Turbo
# Module, then typechecks the generated TypeScript. Requires the Android NDK
# and cargo-ndk.
#
# Export these before running (adjust the NDK version to what is installed):
#   export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools
#   export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.1.12297006"

cd "$(dirname "$0")/.."

if [[ -z ${ANDROID_NDK_HOME:-} ]]; then
    echo "Error: ANDROID_NDK_HOME is not set. See the comment at the top of" >&2
    echo "this script for the values to export." >&2
    exit 1
fi
if [[ ! -f "$ANDROID_NDK_HOME/source.properties" ]]; then
    echo "Error: ANDROID_NDK_HOME=$ANDROID_NDK_HOME does not look like an" >&2
    echo "NDK install (no source.properties)." >&2
    exit 1
fi

if ! command -v cargo-ndk >/dev/null 2>&1; then
    echo "Error: cargo-ndk not found. Install with: cargo install cargo-ndk" >&2
    exit 1
fi

# See scripts/generate_bindings.sh for why this is set.
export CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback

if command -v rustup >/dev/null 2>&1 &&
    rustup show active-toolchain >/dev/null 2>&1; then
    rustup target add \
        aarch64-linux-android \
        armv7-linux-androideabi \
        i686-linux-android \
        x86_64-linux-android
fi

echo "==> Building Android libraries and generating Turbo Module..."
npm run ubrn:android

echo "==> Typechecking generated bindings..."
npm run typecheck

echo "Android build test complete."

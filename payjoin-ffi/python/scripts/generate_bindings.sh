#!/usr/bin/env bash
set -euo pipefail

OS=$(uname -s)

echo "Running on $OS"

# Install Rust targets if on macOS
if [[ $OS == "Darwin" ]]; then
    LIBNAME=libpayjoin_ffi.dylib
elif [[ $OS == "Linux" ]]; then
    LIBNAME=libpayjoin_ffi.so
else
    echo "Unsupported os: $OS"
    exit 1
fi

uv run python --version

# rustup target add is a no-op against a nix-provided toolchain
# (no rustup home, targets baked into the nix derivation instead).
ensure_target() {
    if command -v rustup >/dev/null 2>&1 &&
        rustup show active-toolchain >/dev/null 2>&1; then
        rustup target add "$@"
    fi
}

# Keep parity with other language test scripts: include _test-utils by default.
PAYJOIN_FFI_FEATURES=${PAYJOIN_FFI_FEATURES-_test-utils}
PAYJOIN_FFI_PROFILE=${PAYJOIN_FFI_PROFILE:-dev}
if [[ $PAYJOIN_FFI_PROFILE == "dev" ]]; then
    TARGET_PROFILE_DIR=debug
else
    TARGET_PROFILE_DIR=$PAYJOIN_FFI_PROFILE
fi
FEATURE_ARGS=()
if [[ -n $PAYJOIN_FFI_FEATURES ]]; then
    FEATURE_ARGS=(--features "$PAYJOIN_FFI_FEATURES")
fi

cd ../
cargo build "${FEATURE_ARGS[@]}" --profile "$PAYJOIN_FFI_PROFILE"
cargo run "${FEATURE_ARGS[@]}" --profile dev --bin uniffi-bindgen generate --library "../target/$TARGET_PROFILE_DIR/$LIBNAME" --language python --out-dir python/src/payjoin/

if [[ $OS == "Darwin" ]]; then
    echo "Generating native binaries..."
    ensure_target aarch64-apple-darwin x86_64-apple-darwin
    cargo build --profile "$PAYJOIN_FFI_PROFILE" --target aarch64-apple-darwin "${FEATURE_ARGS[@]}" &
    aarch64_pid=$!
    cargo build --profile "$PAYJOIN_FFI_PROFILE" --target x86_64-apple-darwin "${FEATURE_ARGS[@]}" &
    x86_64_pid=$!
    # A bare `wait` always returns 0; wait on each build so a failure
    # cannot slip through to lipo, which would happily reuse a stale
    # library from an earlier build.
    wait "$aarch64_pid"
    wait "$x86_64_pid"

    echo "Building macos fat library"
    lipo -create -output python/src/payjoin/$LIBNAME \
        "../target/aarch64-apple-darwin/$TARGET_PROFILE_DIR/$LIBNAME" \
        "../target/x86_64-apple-darwin/$TARGET_PROFILE_DIR/$LIBNAME"

else
    echo "Generating native binaries..."
    ensure_target x86_64-unknown-linux-gnu
    cargo build --profile "$PAYJOIN_FFI_PROFILE" --target x86_64-unknown-linux-gnu "${FEATURE_ARGS[@]}"

    echo "Copying payjoin_ffi binary"
    cp "../target/x86_64-unknown-linux-gnu/$TARGET_PROFILE_DIR/$LIBNAME" python/src/payjoin/$LIBNAME
fi

echo "All done!"

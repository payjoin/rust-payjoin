#!/usr/bin/env bash
set -euo pipefail

OS=$(uname -s)

echo "Running on $OS"

# Install Rust targets if on macOS
if [[ "$OS" == "Darwin" ]]; then
    LIBNAME=libpayjoin_ffi.dylib
    python3 --version
elif [[ "$OS" == "Linux" ]]; then
    LIBNAME=libpayjoin_ffi.so
    PYBIN=$(dirname $(which python))
    PYBIN="$PYBIN" 
    ${PYBIN}/python --version
else
    echo "Unsupported os: $OS"
    exit 1
fi

cd ../
# This is a test script the actual release should not include the test utils feature
cargo build --features _test-utils --profile dev 
cargo run --features _test-utils --profile dev --bin uniffi-bindgen generate --library ../target/debug/$LIBNAME --language python --out-dir python/src/payjoin/

if [[ "$OS" == "Darwin" ]]; then
    echo "Generating native binaries..."
    # This is a test script the actual release should not include the test utils feature
    cargo build --profile dev --target aarch64-apple-darwin --features _test-utils &
    cargo build --profile dev --target x86_64-apple-darwin --features _test-utils &
    wait

    echo "Building macos fat library"
    lipo -create -output python/src/payjoin/$LIBNAME \
        ../target/aarch64-apple-darwin/debug/$LIBNAME \
        ../target/x86_64-apple-darwin/debug/$LIBNAME

else
    echo "Generating native binaries..."
    # This is a test script the actual release should not include the test utils feature
    cargo build --profile dev --target x86_64-unknown-linux-gnu --features _test-utils

    echo "Copying payjoin_ffi binary"
    cp ../target/x86_64-unknown-linux-gnu/debug/$LIBNAME python/src/payjoin/$LIBNAME
fi

echo "All done!"

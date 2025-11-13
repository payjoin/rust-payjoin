#!/usr/bin/env bash
set -euo pipefail

OS=$(uname -s)
echo "Running on $OS"

dart --version
dart pub get

# Install Rust targets if on macOS
if [[ "$OS" == "Darwin" ]]; then
    LIBNAME=libpayjoin_ffi.dylib
elif [[ "$OS" == "Linux" ]]; then
    LIBNAME=libpayjoin_ffi.so
else
    echo "Unsupported os: $OS"
    exit 1
fi

cd ../
echo "Generating payjoin dart..."
cargo build --features dart,_test-utils --profile dev
cargo run --features dart,_test-utils --profile dev --bin uniffi-bindgen -- --library ../target/debug/$LIBNAME --language dart --out-dir dart/lib/

if [[ "$OS" == "Darwin" ]]; then
    echo "Generating native binaries..."
    rustup target add aarch64-apple-darwin x86_64-apple-darwin
    # This is a test script the actual release should not include the test utils feature
    cargo build --profile dev --target aarch64-apple-darwin --features dart,_test-utils &
    cargo build --profile dev --target x86_64-apple-darwin --features dart,_test-utils &
    wait

    echo "Building macos fat library"
    lipo -create -output dart/$LIBNAME \
        ../target/aarch64-apple-darwin/debug/$LIBNAME \
        ../target/x86_64-apple-darwin/debug/$LIBNAME
else
    echo "Generating native binaries..."
    rustup target add x86_64-unknown-linux-gnu
    # This is a test script the actual release should not include the test utils feature
    cargo build --profile dev --target x86_64-unknown-linux-gnu --features dart,_test-utils

    echo "Copying payjoin_ffi binary"
    cp ../target/x86_64-unknown-linux-gnu/debug/$LIBNAME dart/$LIBNAME
fi

echo "All done!"

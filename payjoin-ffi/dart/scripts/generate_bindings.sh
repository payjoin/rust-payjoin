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
cargo build --features _test-utils --profile release
cargo run --features _test-utils --profile release --bin uniffi-bindgen -- --library target/release/$LIBNAME --language dart --out-dir dart/lib/

if [[ "$OS" == "Darwin" ]]; then
    echo "Generating native binaries..."
    rustup target add aarch64-apple-darwin x86_64-apple-darwin
    # This is a test script the actual release should not include the test utils feature
    cargo build --profile release-smaller --target aarch64-apple-darwin --features _test-utils &
    cargo build --profile release-smaller --target x86_64-apple-darwin --features _test-utils &
    wait

    echo "Building macos fat library"
    lipo -create -output dart/$LIBNAME \
        target/aarch64-apple-darwin/release-smaller/$LIBNAME \
        target/x86_64-apple-darwin/release-smaller/$LIBNAME
else
    echo "Generating native binaries..."
    rustup target add x86_64-unknown-linux-gnu
    # This is a test script the actual release should not include the test utils feature
    cargo build --profile release-smaller --target x86_64-unknown-linux-gnu --features _test-utils

    echo "Copying payjoin_ffi binary"
    cp target/x86_64-unknown-linux-gnu/release-smaller/$LIBNAME dart/$LIBNAME
fi

echo "All done!"

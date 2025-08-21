#!/usr/bin/env bash
set -euo pipefail

MAC_LIBNAME=libpayjoin_ffi.dylib
LINUX_LIBNAME=libpayjoin_ffi.so

OS=$(uname -s)
ARCH=$(uname -m)
echo "Running on $OS / $ARCH"

dart --version
dart pub get

# Install Rust targets if on macOS
if [[ "$OS" == "Darwin" ]]; then
    LIBNAME=$MAC_LIBNAME
elif [[ "$OS" == "Linux" ]]; then
    LIBNAME=$LINUX_LIBNAME
else
    echo "Unsupported os: $OS"
    exit 1
fi

# Build native binary
if [[ "$OS" == "Darwin" ]]; then
    if [[ "$ARCH" == "arm64" ]]; then
        echo "Generating native binaries..."
        rustup target add aarch64-apple-darwin
        # This is a test script the actual release should not include the test utils feature
        cargo build --profile release-smaller --target aarch64-apple-darwin --features _test-utils
        echo "Done building aarch64-apple-darwin"
    elif [[ "$ARCH" == "x86_64" ]]; then
        echo "Generating native binaries..."
        rustup target add x86_64-apple-darwin
        # This is a test script the actual release should not include the test utils feature
        cargo build --profile release-smaller --target x86_64-apple-darwin --features _test-utils
        echo "Done building x86_64-apple-darwin"
    fi
else
    # Generate Python bindings
    echo "Generating payjoin dart..."
    cd ../
    # This is a test script the actual release should not include the test utils feature
    cargo build --features _test-utils --profile release 
    cargo run --features _test-utils --profile release --bin uniffi-bindgen -- --library target/release/$LIBNAME --language dart --out-dir dart/lib/



    echo "Generating native binaries..."
    rustup target add x86_64-unknown-linux-gnu
    # This is a test script the actual release should not include the test utils feature
    cargo build --profile release-smaller --target x86_64-unknown-linux-gnu --features _test-utils

    echo "Copying payjoin_ffi binary"
    cp target/x86_64-unknown-linux-gnu/release-smaller/$LIBNAME dart/$LIBNAME
fi

echo "All done!"


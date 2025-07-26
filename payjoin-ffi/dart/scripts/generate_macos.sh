#!/usr/bin/env bash

set -euo pipefail
LIBNAME=libpayjoin_ffi.dylib

echo "Generating payjoin_ffi.dart..."
cd ../
# This is a test script the actual release should not include the test utils feature
cargo build --features _test-utils --profile release
cargo run --features _test-utils --profile release --bin uniffi-bindgen -- --library target/release/$LIBNAME --language dart --out-dir dart/lib/

echo "Generating native binaries..."
rustup target add aarch64-apple-darwin x86_64-apple-darwin

# This is a test script the actual release should not include the test utils feature
cargo build --profile release-smaller --target aarch64-apple-darwin --features _test-utils
echo "Done building aarch64-apple-darwin"

# This is a test script the actual release should not include the test utils feature
cargo build --profile release-smaller --target x86_64-apple-darwin --features _test-utils
echo "Done building x86_64-apple-darwin"

echo "Building macos fat library"

lipo -create -output dart/$LIBNAME \
        target/aarch64-apple-darwin/release-smaller/$LIBNAME \
        target/x86_64-apple-darwin/release-smaller/$LIBNAME

echo "All done!"

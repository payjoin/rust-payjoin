#!/usr/bin/env bash
set -euo pipefail
LIBNAME=libpayjoin_ffi.so
LINUX_TARGET=x86_64-unknown-linux-gnu

echo "Generating payjoin_ffi.dart..."
cd ../
# This is a test script the actual release should not include the test utils feature
cargo build --profile release --features uniffi,_test-utils
cargo run --profile release --features uniffi,_test-utils --bin uniffi-bindgen -- --library target/release/$LIBNAME --language dart --out-dir dart/lib/

echo "Generating native binaries..."
rustup target add $LINUX_TARGET
# This is a test script the actual release should not include the test utils feature
cargo build --profile release-smaller --target $LINUX_TARGET --features uniffi,_test-utils

echo "Copying linux payjoin_ffi.so"
cp target/$LINUX_TARGET/release-smaller/$LIBNAME dart/$LIBNAME

echo "All done!"

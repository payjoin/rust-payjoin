#!/usr/bin/env bash

set -euo pipefail
python3 --version
pip install -r requirements.txt -r requirements-dev.txt

echo "Generating payjoin_ffi.py..."
cd ../
# This is a test script the actual release should not include the test utils feature
cargo build --features _test-utils --profile release
cargo run --features _test-utils --profile release --bin uniffi-bindgen -- --library target/release/$LIBNAME --language dart --out-dir dart/lib/

echo "Building macos fat library"

lipo -create -output python/src/payjoin/libpayjoin_ffi.dylib \
        target/aarch64-apple-darwin/release-smaller/libpayjoin_ffi.dylib \
        target/x86_64-apple-darwin/release-smaller/libpayjoin_ffi.dylib

echo "All done!"

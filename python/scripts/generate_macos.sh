#!/usr/bin/env bash

set -euo pipefail
python3 --version
pip install --user -r requirements.txt

echo "Generating payjoin_ffi.py..."
cd ../
cargo run --bin uniffi-bindgen generate src/payjoin_ffi.udl --language python --out-dir python/src/payjoin/ --no-format
LIBNAME=libpayjoin_ffi.dylib
echo "Generating native binaries..."
rustup target add aarch64-apple-darwin x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
echo "Done building aarch64-apple-darwin"

cargo build --release --target x86_64-apple-darwin
echo "Done building x86_64-apple-darwin"

echo "Building macos fat library"

lipo -create -output python/src/payjoin/$LIBNAME \
        target/aarch64-apple-darwin/release/$LIBNAME \
        target/x86_64-apple-darwin/release/$LIBNAME


echo "All done!"
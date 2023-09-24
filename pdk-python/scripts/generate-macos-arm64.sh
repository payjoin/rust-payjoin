#!/usr/bin/env bash

set -euo pipefail
python3 --version
pip install --user -r requirements.txt

echo "Generating pdk_ffi.py..."
cd ../
cargo run --bin uniffi-bindgen generate src/pdk_ffi.udl --language python --out-dir pdk-python/src/pdkpython/ --no-format

echo "Generating native binaries..."
rustup target add aarch64-apple-darwin
cargo build --release --target aarch64-apple-darwin

echo "Copying libraries libpdk_ffi.dylib..."
cp target/aarch64-apple-darwin/release/libpdk_ffi.dylib pdk-python/src/pdkpython/libpdk_ffi.dylib

echo "All done!"
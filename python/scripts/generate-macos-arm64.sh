#!/usr/bin/env bash

set -euo pipefail
python3 --version
pip install --user -r requirements.txt

echo "Generating payjoin_ffi.py..."
cd ../
cargo run --bin uniffi-bindgen generate src/payjoin_ffi.udl --language python --out-dir python/src/payjoin/ --no-format

echo "Generating native binaries..."
rustup target add aarch64-apple-darwin
cargo build --release --target aarch64-apple-darwin

echo "Copying libraries libpayjoin_ffi.dylib..."
cp target/aarch64-apple-darwin/release/libpayjoin_ffi.dylib python/src/payjoin/libpayjoin_ffi.dylib

echo "All done!"
#!/usr/bin/env bash

set -euo pipefail
python3 --version
pip install --user -r requirements.txt

LIBNAME=libpayjoin_ffi.so


echo "Generating payjoin_ffi.py..."
cd ../
cargo run --bin uniffi-bindgen generate src/payjoin_ffi.udl --language python --out-dir python/src/payjoin/


echo "Generating native binaries..."
rustup target add x86_64-unknown-linux-gnu
cargo build  --profile release-smaller --target x86_64-unknown-linux-gnu --features uniffi

echo "Copying linux payjoin_ffi.so"
cp target/$LINUX_TARGET/release-smaller/$LIBNAME python/src/payjoin/$LIBNAME

echo "All done!"
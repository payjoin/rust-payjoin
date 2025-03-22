#!/usr/bin/env bash
set -euo pipefail
${PYBIN}/python --version
${PYBIN}/pip install -r requirements.txt -r requirements-dev.txt
LIBNAME=libpayjoin_ffi.so
LINUX_TARGET=x86_64-unknown-linux-gnu

echo "Generating payjoin_ffi.py..."
cd ../
cargo build --profile release --features uniffi
cargo run --profile release --features uniffi --bin uniffi-bindgen generate --library target/release/$LIBNAME --language python --out-dir python/src/payjoin/

echo "Generating native binaries..."
rustup target add $LINUX_TARGET
cargo build  --profile release-smaller --target $LINUX_TARGET --features uniffi

echo "Copying linux payjoin_ffi.so"
cp target/$LINUX_TARGET/release-smaller/$LIBNAME python/src/payjoin/$LIBNAME

echo "All done!"
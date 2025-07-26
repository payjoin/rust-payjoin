#!/usr/bin/env bash
set -euo pipefail
${PYBIN}/python --version
${PYBIN}/pip install -r requirements.txt -r requirements-dev.txt
LIBNAME=libpayjoin_ffi.so
LINUX_TARGET=x86_64-unknown-linux-gnu

echo "Generating payjoin_ffi.py..."
cd ../
# This is a test script the actual release should not include the test utils feature
cargo build --profile release --features _test-utils
cargo run --profile release --features _test-utils --bin uniffi-bindgen generate --library target/release/$LIBNAME --language python --out-dir python/src/payjoin/

echo "Generating native binaries..."
rustup target add $LINUX_TARGET
# This is a test script the actual release should not include the test utils feature
cargo build  --profile release-smaller --target $LINUX_TARGET --features _test-utils

echo "Copying linux payjoin_ffi.so"
cp target/$LINUX_TARGET/release-smaller/$LIBNAME python/src/payjoin/$LIBNAME

echo "All done!"

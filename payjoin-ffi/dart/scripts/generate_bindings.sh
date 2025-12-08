#!/usr/bin/env bash
set -euo pipefail

OS=$(uname -s)
echo "Running on $OS"

dart --version
dart pub get

# Install Rust targets if on macOS
if [[ $OS == "Darwin" ]]; then
    LIBNAME=libpayjoin_ffi.dylib
elif [[ $OS == "Linux" ]]; then
    LIBNAME=libpayjoin_ffi.so
else
    echo "Unsupported os: $OS"
    exit 1
fi

cd ../
echo "Generating payjoin dart..."
cargo build --features dart,_test-utils --profile dev
cargo run --features dart,_test-utils --profile dev --bin uniffi-bindgen -- --library ../target/debug/$LIBNAME --language dart --out-dir dart/lib/

echo "All done!"

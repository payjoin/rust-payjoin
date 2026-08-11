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
# Keep parity with other language test scripts: include _test-utils by default.
PAYJOIN_FFI_FEATURES=${PAYJOIN_FFI_FEATURES-_test-utils}
PAYJOIN_FFI_PROFILE=${PAYJOIN_FFI_PROFILE:-dev}
if [[ $PAYJOIN_FFI_PROFILE == "dev" ]]; then
    TARGET_PROFILE_DIR=debug
else
    TARGET_PROFILE_DIR=$PAYJOIN_FFI_PROFILE
fi
GENERATOR_FEATURES="dart"
if [[ -n $PAYJOIN_FFI_FEATURES ]]; then
    GENERATOR_FEATURES="$GENERATOR_FEATURES,$PAYJOIN_FFI_FEATURES"
fi

cargo build --features "$GENERATOR_FEATURES" --profile "$PAYJOIN_FFI_PROFILE"
cargo run --features "$GENERATOR_FEATURES" --profile dev --bin uniffi-bindgen -- --library "../target/$TARGET_PROFILE_DIR/$LIBNAME" --language dart --out-dir dart/lib/

echo "All done!"

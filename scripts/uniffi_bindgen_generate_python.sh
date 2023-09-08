#!/bin/bash
BINDINGS_DIR="../bindings/python"
UNIFFI_BINDGEN_BIN="cargo run --bin uniffi-bindgen"

cargo build --release  || exit 1
$UNIFFI_BINDGEN_BIN generate ../bindings/pdk_ffi.udl --language python -o "$BINDINGS_DIR" --no-format || exit 1
cp ../target/release/libpdk_ffi.dylib "$BINDINGS_DIR"/libpdk_ffi.dylib || exit 1
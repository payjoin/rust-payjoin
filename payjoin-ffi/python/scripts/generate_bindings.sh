#!/usr/bin/env bash
set -euo pipefail

OS=$(uname -s)

echo "Running on $OS"

# TODO: is this necessary if we're reliant on nix for the env?
# Or should we keep this and make nix optional?
# FIXME: pin the versions between the darwin and linux

# let nix handle the deps?
# Install Rust targets if on macOS
if [[ "$OS" == "Darwin" ]]; then
  LIBNAME=libpayjoin_ffi.dylib
  # FIXME: why does darwin not assume pybin has been set?
  # are we just assuming the python3 binary is installed on the system?
elif [[ "$OS" == "Linux" ]]; then
  # sudo apt update
  # sudo apt install -y build-essential python3-dev
  LIBNAME=libpayjoin_ffi.so
else
  echo "Unsupported os: $OS"
  exit 1
fi

# FIXME: change to uv style
uv pip install -r requirements.txt -r requirements-dev.txt

# FIXME: should we not use pushd and popd to ensure robustness here
cd ../
# This is a test script the actual release should not include the test utils feature
cargo build --features _test-utils --profile release
cargo run --features _test-utils --profile release --bin uniffi-bindgen generate \
  --library target/release/$LIBNAME --language python --out-dir python/src/payjoin/

if [[ "$OS" == "Darwin" ]]; then
  echo "Generating native binaries..."
  rustup target add aarch64-apple-darwin x86_64-apple-darwin
  # This is a test script the actual release should not include the test utils feature
  cargo build --profile release-smaller --target aarch64-apple-darwin --features _test-utils &
  cargo build --profile release-smaller --target x86_64-apple-darwin --features _test-utils &
  wait

  echo "Building macos fat library"
  # NOTE: requires xcode?
  lipo -create -output python/src/payjoin/$LIBNAME \
    target/aarch64-apple-darwin/release-smaller/$LIBNAME \
    target/x86_64-apple-darwin/release-smaller/$LIBNAME
else
  echo "Generating native binaries..."
  # rustup target add x86_64-unknown-linux-gnu
  # This is a test script the actual release should not include the test utils feature
  cargo build --profile release-smaller --target x86_64-unknown-linux-gnu --features _test-utils

  echo "Copying payjoin_ffi binary"
  # FIXME: only works on x86_64 arch's?
  # TODO: is there a tool for creating universal linux binaries like lipo with mac?
  cp target/x86_64-unknown-linux-gnu/release-smaller/$LIBNAME python/src/payjoin/$LIBNAME
fi

echo "All done!"

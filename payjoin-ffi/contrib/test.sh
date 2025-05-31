#!/usr/bin/env bash
set -e

RUST_VERSION=$(rustc --version | awk '{print $2}')

if [[ ! "$RUST_VERSION" =~ ^1\.63\. ]]; then
  cargo test --package payjoin-ffi --verbose --features=_test-utils
else
  echo "Skipping payjoin-ffi tests for Rust version $RUST_VERSION (MSRV)"
fi

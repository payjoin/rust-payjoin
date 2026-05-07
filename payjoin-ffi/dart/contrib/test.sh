#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Cleaning nested Cargo.lock..."
rm -f native/Cargo.lock

echo "==> Generating FFI bindings..."
bash ./scripts/generate_bindings.sh

echo "==> Running dart tests..."
dart test

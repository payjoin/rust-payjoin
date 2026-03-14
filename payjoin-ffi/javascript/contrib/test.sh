#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Installing JavaScript dependencies..."
npm ci

echo "==> Generating FFI bindings..."
bash ./scripts/generate_bindings.sh

echo "==> Running JavaScript tests..."
npm test

#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Generating FFI bindings..."
bash ./scripts/generate_bindings.sh

echo "==> Running C# tests..."
dotnet test --logger "console;verbosity=minimal"

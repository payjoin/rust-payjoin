#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Syncing Python dependencies with uv..."
uv sync --all-extras

echo "==> Generating FFI bindings..."
bash ./scripts/generate_bindings.sh

echo "==> Building wheel..."
uv build --wheel

echo "==> Installing wheel..."
uv pip install ./dist/*.whl --force-reinstall

echo "==> Running tests..."
uv run python -m unittest --verbose

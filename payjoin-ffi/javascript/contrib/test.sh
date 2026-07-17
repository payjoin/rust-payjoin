#!/usr/bin/env bash
set -euo pipefail

# Build against the maintained lockfile instead of resolving the dependency
# graph fresh on every run. use_lockfile copies Cargo-recent.lock into place
# and restores the previous state when this script exits.
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
source contrib/lockfile.sh
use_lockfile Cargo-recent.lock

cd "$REPO_ROOT/payjoin-ffi/javascript"

echo "==> Installing JavaScript dependencies..."
npm ci

echo "==> Generating FFI bindings..."
bash ./scripts/generate_bindings.sh

echo "==> Running JavaScript tests..."
npm test

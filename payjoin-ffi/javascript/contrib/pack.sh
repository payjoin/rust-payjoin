#!/usr/bin/env bash
set -euo pipefail

# Build the production package and pack the npm tarball into artifacts/.
# The tarball ships only dist/ (wasm + compiled TypeScript), which is
# platform-independent, so a single pack is the entire release build.

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
PAYJOIN_JS_BUILD_TEST_UTILS=0 bash ./scripts/generate_bindings.sh

echo "==> Packing npm tarball..."
rm -rf artifacts
mkdir -p artifacts
npm pack --pack-destination artifacts

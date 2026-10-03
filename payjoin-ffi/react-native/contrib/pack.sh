#!/usr/bin/env bash
set -euo pipefail

# Build the production package and pack the npm tarball into artifacts/.
#
# Unlike the javascript sibling, whose tarball ships only platform-independent
# wasm + JS, this tarball ships prebuilt native artifacts (the iOS xcframework
# and Android libraries). generate_bindings.sh builds the iOS half only on
# macOS, so run this from a macOS host; check_artifacts.sh aborts otherwise.

# Build against the maintained lockfile instead of resolving the dependency
# graph fresh on every run. use_lockfile copies Cargo-recent.lock into place
# and restores the previous state when this script exits.
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
source contrib/lockfile.sh
use_lockfile Cargo-recent.lock

cd "$REPO_ROOT/payjoin-ffi/react-native"

echo "==> Installing React Native dependencies..."
npm ci

echo "==> Generating FFI bindings..."
bash ./scripts/generate_bindings.sh

# npm pack runs the prepack hook (scripts/check_artifacts.sh), which aborts
# if any native output is missing, so no separate verification step here.
echo "==> Packing npm tarball..."
rm -rf artifacts
mkdir -p artifacts
npm pack --pack-destination artifacts

#!/usr/bin/env bash
set -euo pipefail

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

# On-device/simulator tests require the (deferred) example app plus an iOS
# simulator or Android emulator. Until then, typechecking the generated
# bindings is the strongest signal we can produce in a headless environment.
echo "==> Typechecking bindings..."
npm run typecheck

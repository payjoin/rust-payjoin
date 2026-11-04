#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
source contrib/lockfile.sh
use_lockfile Cargo-recent.lock

cd "$REPO_ROOT/payjoin-ffi/java"

echo "==> Generating FFI bindings..."
bash ./scripts/generate_bindings.sh

echo "==> Running Java tests..."
./gradlew --no-daemon test

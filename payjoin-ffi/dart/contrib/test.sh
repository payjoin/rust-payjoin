#!/usr/bin/env bash
set -euo pipefail

# Build against the maintained workspace lockfile instead of resolving the
# workspace dependency graph fresh on every run. The nested native lockfile is
# a separate production lock and must remain tracked for consumer builds.
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
source contrib/lockfile.sh
use_lockfile Cargo-recent.lock

cd "$REPO_ROOT/payjoin-ffi/dart"

echo "==> Checking production native Cargo.lock..."
test -f native/Cargo.lock
if grep -n 'path = ' native/Cargo.lock; then
    echo "Production native Cargo.lock contains a path dependency" >&2
    exit 1
fi

echo "==> Generating FFI bindings..."
bash ./scripts/generate_bindings.sh

echo "==> Running dart tests..."
export PAYJOIN_FFI_ENABLE_TEST_UTILS=1
dart test

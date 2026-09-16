#!/usr/bin/env bash
set -euo pipefail

# Build against the maintained lockfile instead of resolving the dependency
# graph fresh on every run. use_lockfile copies Cargo-recent.lock into place
# and restores the previous state when this script exits.
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
source contrib/lockfile.sh
use_lockfile Cargo-recent.lock

cd "$REPO_ROOT/payjoin-ffi/dart"

echo "==> Testing the contrib checkers..."
bash ./contrib/check_production_lock_test.sh
bash ./contrib/check_reproducible_test.sh

echo "==> Checking the production native Cargo.lock..."
bash ./contrib/check_production_lock.sh native/Cargo.toml native/Cargo.lock

echo "==> Generating FFI bindings..."
bash ./scripts/generate_bindings.sh

# The hook builds through .cargo/config.local.toml here, which redirects
# payjoin-ffi to the workspace. That graph is not the one the production
# lockfile pins, so Cargo has to resolve its own and would overwrite the
# tracked file. Keep it aside for the run instead of losing it.
echo "==> Running dart tests..."
production_lock=$(mktemp "${TMPDIR:-/tmp}/payjoin-native-lock.XXXXXX")
cp native/Cargo.lock "$production_lock"
rm -f native/Cargo.lock
status=0
dart test || status=$?
cat "$production_lock" >native/Cargo.lock
rm -f "$production_lock"
exit "$status"

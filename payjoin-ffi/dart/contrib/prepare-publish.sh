#!/usr/bin/env bash
set -euo pipefail

# Prepare the package for publishing to pub.dev and verify the archive with
# a dry run. The archive ships Dart source plus the native/ wrapper crate;
# consumers compile the Rust themselves via hook/build.dart, so no binaries
# are packed here. Publishing itself stays a separate step so this script
# can run anywhere, including on pull requests.

# Build against the maintained lockfile instead of resolving the dependency
# graph fresh on every run. use_lockfile copies Cargo-recent.lock into place
# and restores the previous state when this script exits.
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
source contrib/lockfile.sh
use_lockfile Cargo-recent.lock

cd "$REPO_ROOT/payjoin-ffi/dart"

echo "==> Generating production FFI bindings..."
PAYJOIN_FFI_FEATURES="" bash ./scripts/generate_bindings.sh

# The archive ships native/Cargo.lock so consumers resolve the same graph
# the release was tested against, and hook/build.dart builds it with
# --locked. A lockfile resolved against the .cargo/config.local.toml path
# overlay would pin a workspace they do not have.
echo "==> Checking the production native Cargo.lock..."
bash ./contrib/check_production_lock.sh native/Cargo.toml native/Cargo.lock

echo "==> Verifying the publish archive..."
# The dry run exits 65 whenever validation reports anything, and one
# warning is unavoidable: the generated bindings carry analyzer warnings
# (unused imports in uniffi-dart output, and the .pubignore'd
# lib/test_utils.dart references test-only APIs that production bindings
# omit). The real publish runs with --force, which proceeds over
# warnings, so anything beyond that known finding has to fail here.
status=0
report="$(dart pub publish --dry-run 2>&1)" || status=$?
printf '%s\n' "$report"
if [[ $status -ne 0 && $status -ne 65 ]]; then
    exit "$status"
fi
unexpected="$(grep '^\* ' <<<"$report" | grep -v "^\* \`dart analyze\` found" || true)"
if [[ -n $unexpected ]]; then
    echo "Unexpected validation findings; fix them before publishing:" >&2
    printf '%s\n' "$unexpected" >&2
    exit 1
fi

# The dry run prints the archive as a tree, so assert on its entries rather
# than on paths. `.pubignore` decides both of these: it withholds `.cargo/`,
# and it must keep withholding it once the overlay is only a development
# aid, while native/Cargo.lock has to stay out of that list.
contents="$(grep -- '── ' <<<"$report" || true)"
if ! grep -q 'Cargo\.lock' <<<"$contents"; then
    echo "The archive is missing native/Cargo.lock:" >&2
    printf '%s\n' "$contents" >&2
    exit 1
fi
if grep -q '\.cargo' <<<"$contents"; then
    echo "The archive carries the development Cargo overlay:" >&2
    printf '%s\n' "$contents" >&2
    exit 1
fi

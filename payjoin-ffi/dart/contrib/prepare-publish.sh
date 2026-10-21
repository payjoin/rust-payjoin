#!/usr/bin/env bash
set -euo pipefail
[ "$#" -eq 1 ] || {
    echo "usage: prepare-publish.sh <new-package-dir>" >&2
    exit 1
}
# Resolve before changing directories; the destination must not exist.
stage="$(realpath -m "$1")"

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

revision="$(git rev-parse HEAD)"
mkdir "$stage"
# Include generated bindings while excluding development Cargo overlays,
# then pin the native crate to the checkout that generated them.
rsync -a --exclude=.git --exclude-from=.pubignore ./ "$stage/"
sed -i "s/rev = \"[0-9a-f]*\"/rev = \"$revision\"/" "$stage/native/Cargo.toml"
grep -Fq "rev = \"$revision\"" "$stage/native/Cargo.toml" || {
    echo "Could not pin the staged native crate to $revision" >&2
    exit 1
}

# payjoin-ffi and payjoin-test-utils come from the pinned revision, but the
# release crates they require, payjoin and payjoin-mailroom, come from
# crates.io. Between a version bump of one of those and its crates.io
# release, the lock below could not resolve it. Take such a crate from the
# pinned revision instead so pull requests can still stage, and leave a
# marker that publish.sh refuses: a published package must build against
# crates its consumers can get from crates.io.
source "$REPO_ROOT/contrib/release/crates.sh"
# crates.io answers 404 for a version it does not have. Any other failure,
# such as a rate limit or an outage, must stop here rather than read as
# unpublished, or a release run would stage a package publish.sh refuses.
crates_io_status() {
    curl -sL --retry 3 -o /dev/null -w '%{http_code}' \
        -H "User-Agent: rust-payjoin release tooling" \
        "https://crates.io/api/v1/crates/$1/$2" || true
}
siblings="$(sibling_deps payjoin-ffi && sibling_deps payjoin-test-utils)"
[[ $siblings == *payjoin$'\t'* ]] || {
    echo "Could not read the payjoin version payjoin-ffi requires" >&2
    exit 1
}
while IFS=$'\t' read -r dep req; do
    version="${req#^}"
    version="${version#=}"
    status="$(crates_io_status "$dep" "$version")"
    case $status in
        200) continue ;;
        404) ;;
        *)
            echo "Could not check $dep $version on crates.io (HTTP $status)" >&2
            exit 1
            ;;
    esac
    echo "==> $dep $version is not on crates.io; staging it from $revision"
    cat >>"$stage/native/Cargo.toml" <<EOF

# Added by prepare-publish.sh: $dep $version is not on crates.io yet.
[patch.crates-io.$dep]
git = "https://github.com/payjoin/rust-payjoin.git"
rev = "$revision"
EOF
    printf '%s %s comes from %s, not crates.io\n' "$dep" "$version" \
        "$revision" >>"$stage/UNPUBLISHED_CORE"
done < <(sort -u <<<"$siblings")

# Ship the dependency graph this release was tested against; hook/build.dart
# builds it with --locked. Seeding from the maintained lockfile keeps every
# pin that still applies, so cargo resolves only what differs from the
# workspace, chiefly payjoin-ffi coming from the pinned revision.
echo "==> Locking the staged native crate..."
cp "$REPO_ROOT/Cargo-recent.lock" "$stage/native/Cargo.lock"
cargo update --workspace --manifest-path "$stage/native/Cargo.toml"
cd "$stage"

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
# Skipping ahead of the last published version is a release decision made
# when the shared binding version is bumped, so pub's reminder of the
# previous version is not a finding.
unexpected="$(grep -v '^\* The previous version is ' <<<"$unexpected" || true)"
if [[ -n $unexpected ]]; then
    echo "Unexpected validation findings; fix them before publishing:" >&2
    printf '%s\n' "$unexpected" >&2
    exit 1
fi

#!/usr/bin/env bash
#
# Prepare a release crate's bump commit. Sets the crate's version, rewrites
# every workspace member's version requirement on it, renames the
# "## Unreleased" changelog section to the new version and opens a fresh
# empty one above it, regenerates both lock files, then runs
# check-invariants. Leaves the changes uncommitted for review.
#
# usage: bump.sh [--no-lock] <crate> <version>
#   --no-lock   skip contrib/update-lock-files.sh (then check-invariants
#               reports the stale lock files, as it should)
#
# Needs jq, and without --no-lock a rustup nightly toolchain, which the
# lock file script calls as `cargo +nightly`.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=contrib/release/crates.sh
source "$DIR/crates.sh"
cd "$REPO_ROOT"

lock=1
if [ "${1:-}" = "--no-lock" ]; then
    lock=0
    shift
fi
[ "$#" -eq 2 ] || {
    sed -n '2,14p' "$0" >&2
    exit 1
}
crate="$1"
new="$2"
die() {
    echo "bump: $*" >&2
    exit 1
}

case " $RELEASE_CRATES " in
    *" $crate "*) ;;
    *) die "$crate is not a release crate ($RELEASE_CRATES)" ;;
esac
[[ $new =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "$new is not a semver version"
[ -z "$(git status --porcelain --untracked-files=no)" ] || die "commit or discard your changes first"

RELEASE_METADATA="$(cargo_metadata)"
old="$(manifest_version "$crate")"
[ "$old" != "$new" ] || die "$crate is already $new"
echo "Bumping $crate $old -> $new"

# The crate's own version: the first line-anchored `version =` in its manifest.
sed -i "0,/^version = \"$old\"/s//version = \"$new\"/" "$crate/Cargo.toml"
[ "$(sed -n 's/^version = "\(.*\)"/\1/p' "$crate/Cargo.toml" | head -1)" = "$new" ] ||
    die "could not set version in $crate/Cargo.toml"

# Every workspace member that requires it by version. Members use the
# single-line table form `crate = { version = "x", ... }`.
while IFS= read -r manifest; do
    [ -f "$manifest" ] || continue
    if grep -q "^$crate = { version = \"$old\"" "$manifest"; then
        sed -i "s/^\($crate = { version = \"\)$old\"/\1$new\"/" "$manifest"
        echo "  $manifest: requirement on $crate -> $new"
    fi
done < <(cargo_metadata | jq -r '.packages[].manifest_path')

changelog="$crate/CHANGELOG.md"
grep -qx '## Unreleased' "$changelog" ||
    die "$changelog has no '## Unreleased' section; add the lines for this release under one first"
sed -i "0,/^## Unreleased$/s//## Unreleased\n\n## $new/" "$changelog"
echo "  $changelog: '## Unreleased' -> '## $new', fresh Unreleased section added"

if [ "$lock" -eq 1 ]; then
    echo "Regenerating lock files (contrib/update-lock-files.sh)"
    ./contrib/update-lock-files.sh
fi

"$DIR/check-invariants.sh" "$crate"
echo
echo "Review the '## $new' section of $changelog, then commit as:"
echo "  git commit -am 'Bump $crate version to $new'"

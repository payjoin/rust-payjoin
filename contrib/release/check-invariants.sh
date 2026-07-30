#!/usr/bin/env bash
#
# Check that each release crate is internally consistent: every dependent's
# version requirement on it matches its manifest version, both tracked lock
# files record that version, and its CHANGELOG.md has a section for it.
# Offline, a few seconds. Checks all release crates, or the ones named.
set -euo pipefail
# shellcheck source=contrib/release/crates.sh
source "$(dirname "${BASH_SOURCE[0]}")/crates.sh"

crates="${*:-$RELEASE_CRATES}"
RELEASE_METADATA="$(cargo_metadata)"
status=0
problem() {
    echo "$*" >&2
    status=1
}

# Print a crate's version as recorded in a Cargo lock file.
lockfile_version() {
    grep -A1 "^name = \"$2\"\$" "$1" | sed -n 's/^version = "\(.*\)"/\1/p'
}

echo "Checking version requirements on: $crates"
# Version requirements that do not match the depended-on crate's version.
mismatches="$(cargo_metadata | jq -r --argjson t "$(printf '%s' "$crates" | jq -R 'split(" ")')" '
    (.packages | map({key: .name, value: .version}) | from_entries) as $ver
    | .packages[] as $p
    | $p.dependencies[]
    | select(.path == null and (.name | IN($t[])))
    | select((.req | ltrimstr("^") | ltrimstr("=")) != $ver[.name])
    | "\($p.name) requires \(.name) \(.req), expected \($ver[.name])"
')"
[ -z "$mismatches" ] || problem "$mismatches"

for crate in $crates; do
    version="$(manifest_version "$crate")"
    echo "Checking $crate $version: lock files and CHANGELOG.md"
    for lock in Cargo-minimal.lock Cargo-recent.lock; do
        recorded="$(lockfile_version "$REPO_ROOT/$lock" "$crate")"
        [ "$recorded" = "$version" ] || problem "$lock records $crate ${recorded:-<missing>}, expected $version"
    done
    grep -qxF "## $version" "$REPO_ROOT/$crate/CHANGELOG.md" || problem "$crate/CHANGELOG.md has no ## $version section"
done

[ "$status" -eq 0 ] && echo "Release invariants hold for: $crates"
exit "$status"

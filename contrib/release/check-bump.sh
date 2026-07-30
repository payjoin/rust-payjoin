#!/usr/bin/env bash
#
# Pull request check. For each release crate whose version changed relative
# to the base commit, confirm the bump is consistent (check-invariants) and
# the crate still publishes (cargo publish --dry-run). No-ops when no release
# version changed. A sibling release crate not yet on crates.io is skipped,
# not failed, since a PR may bump two crates at once.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=contrib/release/crates.sh
source "$DIR/crates.sh"
cd "$REPO_ROOT"
# shellcheck source=contrib/lockfile.sh
source contrib/lockfile.sh

[ "$#" -eq 1 ] || {
    echo "usage: check-bump.sh <base-sha>" >&2
    exit 1
}
base="$1"

# A crate's [package] version at a git ref (the only line-anchored `version`).
version_at() {
    git show "$1:$2/Cargo.toml" 2>/dev/null | sed -n 's/^version = "\(.*\)"/\1/p' | head -1
}

RELEASE_METADATA="$(cargo_metadata)"
echo "Comparing release crate versions against $base"
changed=()
for crate in $RELEASE_CRATES; do
    [ "$(version_at "$base" "$crate")" = "$(manifest_version "$crate")" ] || changed+=("$crate")
done

if [ "${#changed[@]}" -eq 0 ]; then
    echo "No release crate version changed"
    exit 0
fi

echo "Version changed for: ${changed[*]}"
"$DIR/check-invariants.sh" "${changed[@]}"

use_lockfile Cargo-recent.lock
for crate in "${changed[@]}"; do
    unpublished=""
    while IFS=$'\t' read -r dep req; do
        [ -n "$dep" ] || continue
        v="${req#^}"
        v="${v#=}"
        crate_published "$dep" "$v" || unpublished="$unpublished $dep $v"
    done < <(sibling_deps "$crate")
    if [ -n "$unpublished" ]; then
        echo "Skipping $crate dry-run; sibling not on crates.io yet:$unpublished"
        continue
    fi
    echo "Dry-run publishing $crate"
    cargo publish --dry-run --locked -q -p "$crate"
    echo "$crate packages and publishes cleanly"
done

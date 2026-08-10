#!/usr/bin/env bash
#
# Pull request check. For each release crate whose version changed relative
# to the base commit, confirm the bump is consistent (check-invariants), the
# crate still publishes (cargo publish --dry-run), and the bump is large
# enough for the API changes since the base version (cargo semver-checks).
# No-ops when no release version changed. A sibling release crate not yet on
# crates.io is skipped, not failed, since a PR may bump two crates at once.
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

# Semver only binds between stable releases: any comparison involving a
# pre-release is classified as a major bump, which permits everything, so
# running the tool there proves nothing. Only payjoin is checked for now;
# payjoin-cli has no library API and payjoin-mailroom's is not yet stable.
for crate in "${changed[@]}"; do
    [ "$crate" = "payjoin" ] || continue
    new_version="$(manifest_version "$crate")"
    baseline="$(version_at "$base" "$crate")"
    if is_prerelease "$new_version" || is_prerelease "$baseline"; then
        echo "Skipping $crate semver check for pre-release ($baseline -> $new_version)"
        continue
    fi
    if ! crate_published "$crate" "$baseline"; then
        echo "Skipping $crate semver check; baseline $baseline not on crates.io"
        continue
    fi
    echo "Checking $crate $new_version API against $baseline"
    cargo semver-checks --package "$crate" --baseline-version "$baseline"
done

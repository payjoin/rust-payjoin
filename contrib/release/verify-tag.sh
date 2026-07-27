#!/usr/bin/env bash
#
# Release gate. Confirms a `<crate>-<version>` tag is annotated, signed by a
# key in contrib/release/keys/, an ancestor of origin/master, matches the
# crate's manifest version and the release invariants, and that its sibling
# release-crate dependencies are already on crates.io.
#
# Checks against the working tree, so run it at the tagged commit, which the
# release workflow does.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=contrib/release/crates.sh
source "$DIR/crates.sh"

[ "$#" -eq 1 ] || {
    echo "usage: verify-tag.sh <tag>" >&2
    exit 1
}
tag="$1"
die() {
    echo "verify-tag: $*" >&2
    exit 1
}

crate="$(crate_from_tag "$tag")" || die "$tag is not a <crate>-<version> release tag"
version="$(version_from_tag "$tag")"

echo "Verifying $tag as a release of $crate $version"

echo "Checking the tag is annotated"
[ "$(git -C "$REPO_ROOT" cat-file -t "$tag" 2>/dev/null)" = tag ] ||
    die "$tag is not an annotated tag"

echo "Checking the tag is signed by a key in contrib/release/keys/"
# The throwaway keyring holds only trusted keys, so a successful
# verification against it proves the signer is trusted.
home="$(mktemp -d)"
trap 'rm -rf "$home"' EXIT
gpg --homedir "$home" --batch --quiet --import "$REPO_ROOT"/contrib/release/keys/*.asc 2>/dev/null ||
    die "no importable keys in contrib/release/keys/"
GNUPGHOME="$home" git -C "$REPO_ROOT" verify-tag "$tag" >/dev/null 2>&1 ||
    die "$tag is not signed by a trusted key"

echo "Checking the tag is an ancestor of origin/master"
git -C "$REPO_ROOT" merge-base --is-ancestor "$tag" origin/master 2>/dev/null ||
    die "$tag is not an ancestor of origin/master"

echo "Checking the $crate manifest version is $version"
RELEASE_METADATA="$(cargo_metadata)"
manifest="$(manifest_version "$crate")"
[ "$manifest" = "$version" ] || die "$crate manifest version is $manifest, tag says $version"

"$DIR/check-invariants.sh" "$crate" || die "release invariants fail for $crate"

echo "Checking sibling release-crate dependencies are on crates.io"
while IFS=$'\t' read -r dep req; do
    [ -n "$dep" ] || continue
    v="${req#^}"
    v="${v#=}"
    crate_published "$dep" "$v" || die "$dep $v is not on crates.io yet; publish it before $crate"
done < <(sibling_deps "$crate")

echo "$tag is cleared for release"

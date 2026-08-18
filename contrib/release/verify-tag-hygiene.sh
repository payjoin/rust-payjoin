#!/usr/bin/env bash
#
# Generic release-tag gate shared by the crate and language-binding release
# workflows. Confirms a tag is annotated, signed by a key in
# contrib/release/keys/, and an ancestor of origin/master.
#
# Checks the tag object and repo history only, so it carries no assumption
# about what is being released; ecosystem-specific checks (manifest versions,
# publishability) belong to the caller.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DIR/../.." && pwd)"

[ "$#" -eq 1 ] || {
    echo "usage: verify-tag-hygiene.sh <tag>" >&2
    exit 1
}
tag="$1"
die() {
    echo "verify-tag-hygiene: $*" >&2
    exit 1
}

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

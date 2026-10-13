#!/usr/bin/env bash
#
# Sign the release tags for HEAD. For each release crate (and, with
# --bindings, the shared language-binding release) whose manifest version
# has no tag yet, confirm the release invariants hold and HEAD is on
# payjoin/rust-payjoin's master, then create a signed annotated tag named
# <crate>-<version> with the message "Release <crate>-<version>". Prints
# the push command and never pushes.
#
# usage: tag.sh [--dry-run] [--bindings] [--key <gpg-key-id>] [name...]
#   name   limit to payjoin, payjoin-cli, payjoin-mailroom, or payjoin-ffi
#          (every language binding, from one tag)
#
# Run it in the release devShell, which pins jq, gpg and cargo:
#   nix develop .#release -c contrib/release/tag.sh [...]
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=contrib/release/crates.sh
source "$DIR/crates.sh"
cd "$REPO_ROOT"

dry_run=0
bindings=0
key=""
names=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run) dry_run=1 ;;
        --bindings) bindings=1 ;;
        --key)
            key="$2"
            shift
            ;;
        -h | --help)
            sed -n '2,15p' "$0"
            exit 0
            ;;
        *) names+=("$1") ;;
    esac
    shift
done
die() {
    echo "tag: $*" >&2
    exit 1
}

# Master is fetched from the canonical repository by URL rather than read
# from a remote-tracking ref: a maintainer's origin is often a fork, and any
# local ref can be stale.
RELEASE_REPO="payjoin/rust-payjoin"

[ -z "$(git status --porcelain --untracked-files=no)" ] ||
    die "working tree has uncommitted changes; tags apply to HEAD"
git fetch --quiet "https://github.com/$RELEASE_REPO.git" master ||
    die "could not fetch master from github.com/$RELEASE_REPO"
master="$(git rev-parse FETCH_HEAD)"
git merge-base --is-ancestor HEAD "$master" ||
    die "HEAD is not on $RELEASE_REPO master, so verify-tag-hygiene would reject the tag; check out the merged commit"

RELEASE_METADATA="$(cargo_metadata)"
explicit=0
if [ "${#names[@]}" -gt 0 ]; then
    explicit=1
    want=("${names[@]}")
else
    read -r -a want <<<"$RELEASE_CRATES"
    [ "$bindings" -eq 0 ] || want+=(payjoin-ffi)
fi

tags=()
crates=()
for name in "${want[@]}"; do
    if [[ " $RELEASE_CRATES " == *" $name "* ]]; then
        version="$(manifest_version "$name")"
    elif [ "$name" = payjoin-ffi ]; then
        # One tag releases every language binding at this version.
        version="$("$DIR/bindings-version.sh")" || die "binding versions disagree"
    else
        die "unknown name $name; use payjoin-ffi to release the language bindings"
    fi
    prefix="$name"
    [ -n "$version" ] || die "could not read a version for $name"
    tag="$prefix-$version"
    if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
        at="$(git rev-list -n1 "$tag")"
        if [ "$at" = "$(git rev-parse HEAD)" ]; then
            echo "$tag already tagged at HEAD, skipping"
        elif [ "$explicit" -eq 1 ]; then
            die "$tag already exists at ${at:0:9}, not HEAD; bump the version first"
        else
            echo "$name is at $version, released at ${at:0:9}; not bumped, skipping"
        fi
        continue
    fi
    tags+=("$tag")
    crates+=("$name")
done
[ "${#tags[@]}" -gt 0 ] || {
    echo "Nothing to tag: every manifest version is already tagged"
    exit 0
}

"$DIR/check-invariants.sh" "${crates[@]}"
# Dart consumers build the bindings from source against the wrapped payjoin
# on crates.io, so the bindings cannot ship before it.
case " ${crates[*]} " in
    *" payjoin-ffi "*)
        core="$(manifest_version payjoin)"
        crate_published payjoin "$core" ||
            die "payjoin $core is not on crates.io; publish it before tagging payjoin-ffi"
        ;;
esac

sign=(--sign)
[ -z "$key" ] || sign+=(--local-user "$key")
for tag in "${tags[@]}"; do
    if [ "$dry_run" -eq 1 ]; then
        echo "would run: git tag ${sign[*]} --annotate $tag -m 'Release $tag' HEAD"
        continue
    fi
    git tag "${sign[@]}" --annotate "$tag" -m "Release $tag" HEAD
    RELEASE_MASTER="$master" "$DIR/verify-tag-hygiene.sh" "$tag" >/dev/null ||
        die "$tag failed hygiene after creation; delete it with: git tag -d $tag"
    echo "created $tag"
done

[ "$dry_run" -eq 0 ] || exit 0
# Name the remote that points at the canonical repository, whatever it is
# called locally, or fall back to its URL.
remote="$(git remote -v | awk -v repo="$RELEASE_REPO" \
    '$3 == "(push)" && $2 ~ ("[:/]" repo "(\\.git)?/?$") { print $1; exit }')"
[ -n "$remote" ] || remote="https://github.com/$RELEASE_REPO.git"
echo
echo "Push when ready; each tag starts its release workflow and the release environment prompt:"
printf '  git push %s' "$remote"
printf ' %s' "${tags[@]}"
echo

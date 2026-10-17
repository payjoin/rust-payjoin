#!/usr/bin/env bash
#
# Check that every binding package carries the shared payjoin-ffi version
# and print it: the version a payjoin-ffi-<version> release tag names.
# With --tag <tag>, also require that exact tag.
#
# The manifests hold the bare version; the wrapped payjoin release is
# recorded in payjoin-ffi/CHANGELOG.md, and payjoin-ffi's own requirement
# on it must match the payjoin manifest. Python spells a -rc.N pre-release
# as rcN (PEP 440).
#
# usage: bindings-version.sh [--tag <tag>]
set -euo pipefail
# shellcheck source=contrib/release/crates.sh
source "$(dirname "${BASH_SOURCE[0]}")/crates.sh"
cd "$REPO_ROOT"

tag=""
case "${1:-}" in
    "") ;;
    --tag) tag="${2:?usage: bindings-version.sh [--tag <tag>]}" ;;
    *)
        echo "usage: bindings-version.sh [--tag <tag>]" >&2
        exit 1
        ;;
esac
die() {
    echo "bindings-version: $*" >&2
    exit 1
}

RELEASE_METADATA="$(cargo_metadata)"
ffi="$(manifest_version payjoin-ffi)"
core="$(manifest_version payjoin)"
[[ $ffi =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] ||
    die "payjoin-ffi version $ffi must be MAJOR.MINOR.PATCH, optionally followed by -rc.N"
python="${ffi/-rc./rc}"

status=0
expect() { # <what> <expected> <actual>
    [ "$2" = "$3" ] || {
        echo "bindings-version: $1 is ${3:-missing}, expected $2" >&2
        status=1
    }
}
expect "payjoin-ffi's payjoin requirement" "$core" \
    "$(cargo_metadata | jq -r '.packages[] | select(.name == "payjoin-ffi")
        | .dependencies[] | select(.name == "payjoin")
        | .req | ltrimstr("^") | ltrimstr("=")')"
expect "python/pyproject.toml version" "$python" \
    "$(sed -n 's/^version = "\(.*\)"$/\1/p' payjoin-ffi/python/pyproject.toml | head -1)"
expect "javascript/package.json version" "$ffi" \
    "$(jq -r .version payjoin-ffi/javascript/package.json)"
expect "dart/pubspec.yaml version" "$ffi" \
    "$(sed -n 's/^version: *//p' payjoin-ffi/dart/pubspec.yaml)"
expect "csharp/Payjoin.csproj Version" "$ffi" \
    "$(sed -n 's/.*<Version>\(.*\)<\/Version>.*/\1/p' payjoin-ffi/csharp/Payjoin.csproj | head -1)"
[ -z "$tag" ] || expect "release tag" "payjoin-ffi-$ffi" "$tag"
[ "$status" -eq 0 ] || exit 1
printf '%s\n' "$ffi"

#!/usr/bin/env bash
#
# Write SHA256SUMS over every file in a release asset directory. With
# ARCHIVE_GLOBS and MEMBER_GLOBS set, also open each asset matching
# ARCHIVE_GLOBS and append the hash of each member matching MEMBER_GLOBS,
# under its in-archive path, so files nested inside a package can be
# verified individually. Both variables are whitespace-separated glob
# lists and must be set together. Archives must be zip format, which
# every current package with nested libraries is (.nupkg, .whl).
set -euo pipefail

[ "$#" -eq 1 ] || {
    echo "usage: [ARCHIVE_GLOBS=... MEMBER_GLOBS=...] generate-sha256sums.sh <asset-dir>" >&2
    exit 1
}
die() {
    echo "generate-sha256sums: $*" >&2
    exit 1
}

cd "$1"
# shellcheck disable=SC2094 # find excludes SHA256SUMS, so it is never read
find . -type f ! -name SHA256SUMS -printf '%P\0' | sort -z |
    xargs -0 -r sha256sum >SHA256SUMS

archive_globs="${ARCHIVE_GLOBS:-}"
member_globs="${MEMBER_GLOBS:-}"
if [ -z "$archive_globs" ] && [ -z "$member_globs" ]; then
    exit 0
fi
{ [ -n "$archive_globs" ] && [ -n "$member_globs" ]; } ||
    die "ARCHIVE_GLOBS and MEMBER_GLOBS must be set together"

read -ra members <<<"$member_globs"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
shopt -s nullglob
archives=()
# shellcheck disable=SC2086 # unquoted so the shell expands the caller's globs
for archive in $archive_globs; do
    archives+=("$archive")
done
[ "${#archives[@]}" -gt 0 ] || die "no files match ARCHIVE_GLOBS ($archive_globs)"

# unzip matches the member globs itself and fails when an archive
# contains no match, or is not a zip.
for archive in "${archives[@]}"; do
    unzip -q "$archive" -d "$tmp" "${members[@]}"
done

(cd "$tmp" && find . -type f -printf '%P\0' | sort -z | xargs -0 -r sha256sum) >>SHA256SUMS

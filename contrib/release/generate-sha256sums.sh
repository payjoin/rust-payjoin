#!/usr/bin/env bash
#
# Write SHA256SUMS over every file in a release asset directory.
set -euo pipefail

[ "$#" -eq 1 ] || {
    echo "usage: generate-sha256sums.sh <asset-dir>" >&2
    exit 1
}

cd "$1"
# shellcheck disable=SC2094 # find excludes SHA256SUMS, so it is never read
find . -type f ! -name SHA256SUMS -printf '%P\0' | sort -z |
    xargs -0 -r sha256sum >SHA256SUMS

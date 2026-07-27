#!/usr/bin/env bash
#
# Print a crate's CHANGELOG.md section for a version: the lines between the
# `## <version>` heading and the next `## `, with blank edges trimmed. Used
# to fill the GitHub release body.
set -euo pipefail
# shellcheck source=contrib/release/crates.sh
source "$(dirname "${BASH_SOURCE[0]}")/crates.sh"

[ "$#" -eq 2 ] || {
    echo "usage: extract-changelog.sh <crate> <version>" >&2
    exit 1
}

# awk matches the heading exactly (a version has regex-special dots); sed
# drops leading blank lines and the command substitution drops trailing ones.
section="$(awk -v h="## $2" '
    $0 == h { inside = 1; next }
    inside && /^## / { exit }
    inside
' "$REPO_ROOT/$1/CHANGELOG.md" | sed '/./,$!d')"

[ -n "$section" ] || {
    echo "extract-changelog: no ## $2 section in $1/CHANGELOG.md" >&2
    exit 1
}
printf '%s\n' "$section"

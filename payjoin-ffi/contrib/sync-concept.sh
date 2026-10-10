#!/usr/bin/env bash
set -euo pipefail

# Sync the shared payjoin concept text (payjoin-ffi/CONCEPT.md) into the
# marked block of each package README, so every package describes payjoin
# in the same words. Pass --check to fail on drift instead of rewriting.

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONCEPT="$REPO_ROOT/payjoin-ffi/CONCEPT.md"
READMES=(
    "payjoin-ffi/README.md"
    "payjoin-ffi/python/README.md"
    "payjoin-ffi/dart/README.md"
    "payjoin-ffi/javascript/README.md"
    "payjoin-ffi/csharp/README.md"
)
BEGIN_MARKER='<!-- concept:begin (synced from payjoin-ffi/CONCEPT.md; edit there and run payjoin-ffi/contrib/sync-concept.sh) -->'
END_MARKER='<!-- concept:end -->'

CHECK=0
if [[ ${1:-} == "--check" ]]; then
    CHECK=1
fi

status=0
for readme in "${READMES[@]}"; do
    path="$REPO_ROOT/$readme"
    if ! grep -qF "$BEGIN_MARKER" "$path" || ! grep -qF "$END_MARKER" "$path"; then
        echo "error: $readme is missing the concept markers" >&2
        exit 1
    fi
    tmp="$(mktemp)"
    awk -v begin="$BEGIN_MARKER" -v end="$END_MARKER" -v concept="$CONCEPT" '
        $0 == begin {
            print
            # prettier pads HTML comments in markdown with blank lines, so
            # emit the same shape to keep sync and nix fmt at a fixpoint
            print ""
            while ((getline line < concept) > 0) print line
            close(concept)
            print ""
            skipping = 1
            next
        }
        $0 == end { skipping = 0 }
        !skipping { print }
    ' "$path" >"$tmp"
    if cmp -s "$path" "$tmp"; then
        rm -f "$tmp"
    elif [[ $CHECK -eq 1 ]]; then
        echo "error: $readme is out of sync with payjoin-ffi/CONCEPT.md;" \
            "run payjoin-ffi/contrib/sync-concept.sh" >&2
        rm -f "$tmp"
        status=1
    else
        mv "$tmp" "$path"
        echo "updated $readme"
    fi
done
exit "$status"

#!/usr/bin/env bash
#
# Update the minimal/recent lock file

set -euo pipefail

LOCKFILE="Cargo.lock"
LOCKDIR=".bak"
LOCKFILE_BAK="${LOCKDIR}/${LOCKFILE}"

cleanup() {
    if [ -f "$LOCKFILE_BAK" ]; then
        mv "$LOCKFILE_BAK" "$LOCKFILE"
    fi
    rmdir "$LOCKDIR"
}

if ! mkdir "$LOCKDIR" 2>/dev/null; then
    echo "Another instance is running. If you're sure it's not, remove $LOCKDIR and try again." >&2
    exit 1
fi

trap cleanup EXIT

if [ -f "$LOCKFILE" ]; then
    mv "$LOCKFILE" "$LOCKFILE_BAK"
fi

for file in Cargo-minimal.lock Cargo-recent.lock; do
    cp -f "$file" Cargo.lock
    cargo check
    cp -f Cargo.lock "$file"
done

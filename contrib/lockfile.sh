#!/usr/bin/env bash
set -euo pipefail

LOCKFILE="Cargo.lock"
LOCKDIR=".bak"
LOCKFILE_BAK="${LOCKDIR}/${LOCKFILE}"

_cleanup_lockfile() {
    if [ -f "$LOCKFILE_BAK" ]; then
        mv "$LOCKFILE_BAK" "$LOCKFILE"
    fi
    rmdir "$LOCKDIR" 2>/dev/null || true
}

use_lockfile() {
    local src="$1"
    if ! mkdir "$LOCKDIR" 2>/dev/null; then
        echo "Another instance is running. If you're sure it's not, remove $LOCKDIR and try again." >&2
        exit 1
    fi
    trap _cleanup_lockfile EXIT
    if [ -f "$LOCKFILE" ]; then
        mv "$LOCKFILE" "$LOCKFILE_BAK"
    fi
    cp "$src" "$LOCKFILE"
}

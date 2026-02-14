#!/usr/bin/env bash
set -e

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

DEPS="recent minimal"
CRATES="ohttp-relay payjoin payjoin-cli payjoin-directory payjoin-ffi payjoin-mailroom"

for dep in $DEPS; do
    cargo --version
    rustc --version

    # Some tests require certain toolchain types.
    export NIGHTLY=false
    export STABLE=true
    if cargo --version | grep nightly; then
        STABLE=false
        NIGHTLY=true
    fi
    if cargo --version | grep beta; then
        STABLE=false
    fi

    cp "Cargo-$dep.lock" "$LOCKFILE"

    for crate in $CRATES; do
        (
            cd "$crate"
            ./contrib/test.sh
        )
    done
done

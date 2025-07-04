#!/usr/bin/env bash
set -e

LOCKFILE="Cargo.lock"
LOCKFILE_BAK="cargo.lock.bak"
LOCKFILE_LOCK=".cargo.lock.flock"

# Acquire file lock to prevent concurrent modification
exec 9>"$LOCKFILE_LOCK"
flock 9

# Backup original lockfile
if [ -f "$LOCKFILE" ]; then
    cp "$LOCKFILE" "$LOCKFILE_BAK"
fi

# Restore the original lockfile on exit
trap 'if [ -f "$LOCKFILE_BAK" ]; then mv "$LOCKFILE_BAK" "$LOCKFILE"; fi; flock -u 9' EXIT

DEPS="recent minimal"
CRATES="payjoin payjoin-cli payjoin-directory payjoin-ffi"

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

    cp "Cargo-$dep.lock" Cargo.lock

    for crate in $CRATES; do
        (
            cd "$crate"
            ./contrib/test.sh
        )
    done
done

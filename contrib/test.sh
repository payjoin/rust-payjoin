#!/usr/bin/env bash
set -e

LOCKFILE="Cargo.lock"
LOCKFILE_BAK="Cargo.lock.bak"
LOCKFILE_LOCK=".Cargo.lock.flock"

# Acquire file lock to prevent concurrent modification
# We can't use cargo test --lockfile-path since that doesn't exist in our MSRV
(
    flock 9

    # Backup original lockfile
    if [ -f "$LOCKFILE" ]; then
        mv "$LOCKFILE" "$LOCKFILE_BAK"
    fi

    # Restore the original lockfile on exit
    trap '[ -f "$LOCKFILE_BAK" ] && mv "$LOCKFILE_BAK" "$LOCKFILE"' EXIT

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

) 9>"$LOCKFILE_LOCK"

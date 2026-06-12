#!/usr/bin/env bash
set -e

source contrib/lockfile.sh

use_lockfile Cargo-recent.lock

DEPS="recent minimal"
CRATES="payjoin payjoin-cli payjoin-mailroom"

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

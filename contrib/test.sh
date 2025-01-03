#!/usr/bin/env bash
set -e

DEPS="recent minimal"
CRATES="payjoin payjoin-cli payjoin-directory"

for dep in $DEPS; do
    cargo --version
    rustc --version

    # Some tests require certain toolchain types.
    NIGHTLY=false
    STABLE=true
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
            cd $crate
            ./contrib/test.sh
        )
    done
done

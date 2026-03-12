#!/usr/bin/env bash
set -e

CRATES="payjoin payjoin-cli payjoin-ffi payjoin-mailroom"

cargo --version
rustc --version

for crate in $CRATES; do
    (
        cd "$crate"
        ./contrib/test.sh
    )
done

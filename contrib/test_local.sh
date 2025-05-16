#!/usr/bin/env bash
set -e

CRATES="payjoin payjoin-cli payjoin-directory payjoin-ffi"

cargo --version
rustc --version

for crate in $CRATES; do
    (
        cd "$crate"
        ./contrib/test.sh
    )
done

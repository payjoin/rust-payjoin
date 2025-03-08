#!/usr/bin/env bash
set -e

CRATES="payjoin"

cargo --version
rustc --version

for crate in $CRATES; do
    (
        cd "$crate"
        ./contrib/check.sh
    )
done

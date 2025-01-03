#!/bin/bash
set -e

CRATES="payjoin payjoin-cli payjoin-directory"

cargo --version
rustc --version

for crate in $CRATES; do
    (
        cd "$crate"
        ./contrib/test.sh
    )
done

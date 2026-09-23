#!/usr/bin/env bash
set -e

CRATES="event-log payjoin payjoin-cli payjoin-mailroom"

cargo --version
rustc --version

for crate in $CRATES; do
    (
        cd "$crate"
        ./contrib/test.sh
    )
done

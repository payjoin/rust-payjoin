#!/bin/bash
set -e

CRATES="payjoin payjoin-cli"

cargo --version
rustc --version

for crate in $CRATES
do
    (
        cd $crate
        ./contrib/test.sh
    )
done
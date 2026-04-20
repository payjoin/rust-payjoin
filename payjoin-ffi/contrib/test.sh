#!/usr/bin/env bash
set -e

cd "$(dirname "$0")/.."

cargo test --package payjoin-ffi --verbose --features=_manual-tls,_test-utils

BINDINGS="dart javascript python csharp"

for binding in $BINDINGS; do
    (
        cd "$binding"
        ./contrib/test.sh
    )
done

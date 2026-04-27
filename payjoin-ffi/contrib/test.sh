#!/usr/bin/env bash
set -e

cd "$(dirname "$0")/.."

cargo test --package payjoin-ffi --verbose --features=_manual-tls,_test-utils

BINDINGS="dart javascript python csharp"
pids=()
for binding in $BINDINGS; do
    (
        cd "$binding"
        ./contrib/test.sh
    ) &
    pids+=($!)
done

failed=0
set +e
for pid in "${pids[@]}"; do
    wait "$pid" || failed=1
done
set -e

exit $failed

#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."
cargo test --package payjoin-ffi --verbose --features=_manual-tls,_test-utils
BINDINGS="dart javascript python csharp"
pids=()
tmpfiles=()
for binding in $BINDINGS; do
    tmpfile=$(mktemp)
    tmpfiles+=("$tmpfile")
    (cd "$binding" && ./contrib/test.sh) >"$tmpfile" 2>&1 &
    pids+=($!)
done
failed=0
set +e
i=0
for pid in "${pids[@]}"; do
    binding=$(echo "$BINDINGS" | tr ' ' '\n' | sed -n "$((i + 1))p")
    if ! wait "$pid"; then
        failed=1
        echo ""
        echo "==> FAILED: $binding"
        echo "--- output ---"
        cat "${tmpfiles[$i]}"
        echo "--------------"
    fi
    rm -f "${tmpfiles[$i]}"
    i=$((i + 1))
done
set -e
exit $failed

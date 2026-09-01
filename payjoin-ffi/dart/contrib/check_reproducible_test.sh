#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
CHECKER="$SCRIPT_DIR/check_reproducible.sh"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/payjoin-repro-test.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT

printf 'same artifact\n' >"$work_dir/first.so"
cp "$work_dir/first.so" "$work_dir/second.so"

"$CHECKER" linux-test rustc-test clang-test lld-test \
    "$work_dir/first.so" "$work_dir/second.so" >/dev/null

printf 'different artifact\n' >"$work_dir/second.so"
if "$CHECKER" linux-test rustc-test clang-test lld-test \
    "$work_dir/first.so" "$work_dir/second.so" \
    >/dev/null 2>"$work_dir/error.log"; then
    printf 'Expected divergent artifacts to fail the check\n' >&2
    exit 1
fi

if ! grep -Fq 'artifacts differ byte-for-byte' "$work_dir/error.log"; then
    printf 'Divergence failed for an unexpected reason\n' >&2
    cat "$work_dir/error.log" >&2
    exit 1
fi

printf 'Reproducibility checker tests passed\n'

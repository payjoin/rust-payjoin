#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
CHECKER="$SCRIPT_DIR/check_production_lock.sh"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/payjoin-production-lock-test.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT

pinned=1111111111111111111111111111111111111111
stale=2222222222222222222222222222222222222222

cat >"$work_dir/Cargo.toml" <<EOF
[dependencies]
payjoin-ffi = { git = "https://github.com/payjoin/rust-payjoin.git", rev = "$pinned", features = [
  "dart",
] }
EOF

write_lock() {
    local path=$1 revision=$2 source_line=$3
    cat >"$path" <<EOF
version = 4

[[package]]
name = "payjoin-ffi-wrapper"
version = "0.1.0"
dependencies = [
 "payjoin-ffi",
]

[[package]]
name = "payjoin-ffi"
version = "0.24.0"
EOF
    if [[ $source_line == with-source ]]; then
        printf 'source = "git+https://github.com/payjoin/rust-payjoin.git?rev=%s#%s"\n' \
            "$revision" "$revision" >>"$path"
    fi
}

expect_failure() {
    local lockfile=$1 expected=$2
    if "$CHECKER" "$work_dir/Cargo.toml" "$lockfile" \
        >"$work_dir/out.log" 2>"$work_dir/error.log"; then
        printf 'Expected %s to fail the check\n' "$lockfile" >&2
        exit 1
    fi
    if ! grep -Fq "$expected" "$work_dir/error.log"; then
        printf 'Failed for an unexpected reason, wanted %s\n' "$expected" >&2
        cat "$work_dir/error.log" >&2
        exit 1
    fi
}

write_lock "$work_dir/good.lock" "$pinned" with-source
"$CHECKER" "$work_dir/Cargo.toml" "$work_dir/good.lock" >/dev/null

# A lockfile resolved through the path overlay: no `path` key anywhere, the
# patched package simply loses its source.
write_lock "$work_dir/overlay.lock" "$pinned" without-source
expect_failure "$work_dir/overlay.lock" 'resolves packages from a local path'

write_lock "$work_dir/stale.lock" "$stale" with-source
expect_failure "$work_dir/stale.lock" "does not pin payjoin-ffi to $pinned"

expect_failure "$work_dir/missing.lock" 'missing.lock is missing'

printf 'Production lockfile checker tests passed\n'

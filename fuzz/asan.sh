#!/usr/bin/env bash

# Replay fuzz corpora once under AddressSanitizer, without fuzzing. Long
# fuzzing runs go without a sanitizer for throughput; this catches memory
# errors in the inputs they found. Crashing inputs are written to
# artifacts/ as usual.
#
# Takes an optional target name (e.g. ffi-roundtrip-v2) and replays every
# target's corpus when it is omitted. The build is the cargo-fuzz default,
# so it is shared with fuzz.sh.
#
# This will break if it is run at the same time that cmin is minimizing
# the corpus while this tries to make an ASan run.

set -euo pipefail

TARGET="${1:-}"

REPO_DIR=$(git rev-parse --show-toplevel)

# can't find the file because of the ENV var
# shellcheck source=/dev/null
source "$REPO_DIR/fuzz/fuzz-util.sh"

if [[ -z ${TARGET:-} ]]; then
    targetNames=""
    for targetFile in $(listTargetFiles); do
        targetNames+="$(targetFileToName "$targetFile") "
    done
else
    targetNames="$TARGET"
fi

failed=()
for targetName in $targetNames; do
    echo "Replaying $targetName corpus under ASan"
    if ! cargo fuzz run "$targetName" -- -runs=0; then
        failed+=("$targetName")
    fi
done

if [[ ${#failed[@]} -gt 0 ]]; then
    echo "ASan replay failed for: ${failed[*]}"
    exit 1
fi

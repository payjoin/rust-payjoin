#!/usr/bin/env bash

# Continuously cycle over fuzz targets running each for 1 hour.
# It uses chrt SCHED_IDLE so that other process takes priority.
# A number of concurrent forks can be applied for parallelization. Be sure to leave one or two available CPUs open for the OS.
# Targets are fuzzed without a sanitizer for throughput. Pass `true` as the second argument to replay each target's
# corpus under AddressSanitizer (asan.sh) after it is fuzzed.
#
# Usage: ./cycle.sh [FORKS] [ASAN]
#
# For cargo-fuzz usage see https://github.com/rust-fuzz/cargo-fuzz?tab=readme-ov-file#usage

set -euo pipefail

FORKS=${1:-1}
ASAN=${2:-false}
REPO_DIR=$(git rev-parse --show-toplevel)
# can't find the file because of the ENV var
# shellcheck source=/dev/null
source "$REPO_DIR/fuzz/fuzz-util.sh"

NO_SANITIZER_TARGET_DIR="$REPO_DIR/target/fuzz-no-sanitizer"

while :; do
    for targetFile in $(listTargetFiles); do
        targetName=$(targetFileToName "$targetFile")
        echo "Fuzzing target $targetName ($targetFile)"
        # fuzz for one hour, in a separate target dir so switching to the
        # ASan build used by fuzz.sh and asan.sh does not rebuild everything
        cargo +nightly fuzz run "$targetName" -s none --target-dir "$NO_SANITIZER_TARGET_DIR" \
            -- -max_total_time=3600 -fork="$FORKS"
        # minimize the corpus
        cargo +nightly fuzz cmin "$targetName" -s none --target-dir "$NO_SANITIZER_TARGET_DIR"
        if [[ $ASAN == true ]]; then
            "$REPO_DIR/fuzz/asan.sh" "$targetName"
        fi
    done
done

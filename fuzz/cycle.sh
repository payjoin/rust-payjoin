#!/usr/bin/env bash

# Continuously cycle over fuzz targets running each for 1 hour.
# It uses chrt SCHED_IDLE so that other process takes priority.
# A number of concurrent forks can be applied for parallelization. Be sure to leave one or two available CPUs open for the OS.
#
# For cargo-fuzz usage see https://github.com/rust-fuzz/cargo-fuzz?tab=readme-ov-file#usage

set -euo pipefail

FORKS=${1:-1}
REPO_DIR=$(git rev-parse --show-toplevel)
# can't find the file because of the ENV var
# shellcheck source=/dev/null
source "$REPO_DIR/fuzz/fuzz-util.sh"

while :; do
    for targetFile in $(listTargetFiles); do
        targetName=$(targetFileToName "$targetFile")
        echo "Fuzzing target $targetName ($targetFile)"
        # fuzz for one hour
        cargo +nightly fuzz run "$targetName" -- -max_total_time=3600 -fork="$FORKS"
        # minimize the corpus
        cargo +nightly fuzz cmin "$targetName"
    done
done

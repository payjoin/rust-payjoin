#!/usr/bin/env bash

# This script is used to briefly fuzz every target when no target is provided. Otherwise, it will briefly fuzz the provided target
# When fuzzing with a specific target a number of concurrent forks can be applied. Be sure to leave one or two available CPUs open for the OS.

set -euo pipefail

TARGET=""
FORKS=1

if [[ $# -gt 0 ]]; then
    TARGET="$1"
    shift
fi

if [[ $# -gt 0 ]]; then
    FORKS="$1"
    shift
fi

REPO_DIR=$(git rev-parse --show-toplevel)

# can't find the file because of the ENV var
# shellcheck source=/dev/null
source "$REPO_DIR/fuzz/fuzz-util.sh"

if [[ -z ${TARGET:-} ]]; then
    targetFiles="$(listTargetFiles)"
else
    targetFiles=fuzz_targets/"${TARGET}".rs
fi

for targetFile in $targetFiles; do
    targetName=$(targetFileToName "$targetFile")
    echo "Fuzzing target $targetName ($targetFile)"
    cargo fuzz run "$targetName" -- -max_total_time=30 -fork="$FORKS"
done

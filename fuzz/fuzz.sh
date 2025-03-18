#!/usr/bin/env bash

# This script is used to briefly fuzz every target when no target is provided. Otherwise, it will briefly fuzz the provided target

set -euo pipefail

TARGET=""

if [[ $# -gt 0 ]]; then
    TARGET="$1"
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
    cargo fuzz run "$targetName" -- -max_total_time=30
done

#!/usr/bin/env bash

# This script is used to briefly fuzz every target when no target is provided. Otherwise, it will briefly fuzz the provided target

set -euox pipefail

ENGINE="fuzz"
TARGET=""

if [[ ${1:-} == "hfuzz" || ${1:-} == "fuzz" || ${1:-} == "afl" ]]; then
    ENGINE="$1"
    shift
fi

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

cargo --version
rustc --version

if [[ $ENGINE == "hfuzz" ]]; then
    export HFUZZ_BUILD_ARGS="--features honggfuzz_fuzz"
    for targetFile in $targetFiles; do
        targetName=$(targetFileToName "$targetFile")
        echo "Fuzzing target $targetName ($targetFile)"
        if [ -d "hfuzz_input/$targetName" ]; then
            HFUZZ_INPUT_ARGS="-f hfuzz_input/$targetName/input"
        else
            HFUZZ_INPUT_ARGS=""
        fi
        HFUZZ_RUN_ARGS="--run_time 30 --exit_upon_crash -v $HFUZZ_INPUT_ARGS" cargo hfuzz run "$targetName"

        checkhfuzzReport "$targetName"
    done
elif [[ $ENGINE == "afl" ]]; then
    for targetFile in $targetFiles; do
        targetName=$(targetFileToName "$targetFile")
        echo "Fuzzing target $targetName ($targetFile)"
        cargo afl build --bin "$targetName" --features afl_fuzz
        cargo afl fuzz -i fuzz_targets -o afl_target -V 30 target/debug/"$targetName" --features afl_fuzz
    done
else
    for targetFile in $targetFiles; do
        targetName=$(targetFileToName "$targetFile")
        cargo +nightly fuzz run "$targetName" --features libfuzzer_fuzz -- -max_total_time=30

        checkReport "$targetName"
    done
fi

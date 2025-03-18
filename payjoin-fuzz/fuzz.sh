#!/usr/bin/env bash

# This script is used to briefly fuzz every target when no target is provided. Otherwise, it will briefly fuzz the provided target

set -euo pipefail

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
source "$REPO_DIR/payjoin-fuzz/fuzz-util.sh"

if [[ -z ${TARGET:-} ]]; then
    targetFiles="$(listTargetFiles)"
else
    targetFiles=fuzz_targets/"${TARGET}".rs
fi

if [[ $ENGINE == "hfuzz" ]]; then
    export HFUZZ_BUILD_ARGS="--features honggfuzz_fuzz"
    for targetFile in $targetFiles; do
        targetName=$(targetFileToName "$targetFile")
        echo "Fuzzing target $targetName ($targetFile)"
        HFUZZ_INPUT_ARGS="-f corpus/$targetName/"
        export HFUZZ_RUN_ARGS="--run_time 30 --exit_upon_crash -v $HFUZZ_INPUT_ARGS"
        env -u RUSTC_WRAPPER CC=clang RUSTFLAGS="--cfg tokio_unstable" \
            cargo hfuzz run "$targetName"
    done
elif [[ $ENGINE == "afl" ]]; then
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export AFL_SKIP_CPUFREQ=1
    export AFL_BENCH_UNTIL_CRASH=1
    for targetFile in $targetFiles; do
        targetName=$(targetFileToName "$targetFile")
        echo "Fuzzing target $targetName ($targetFile)"
        cargo afl config --build --force
        cargo afl build --bin "$targetName" --features afl_fuzz
        afl-fuzz -i corpus/"$targetName"/ -o afl_target -V 30 ../target/debug/"$targetName" --features afl_fuzz
    done
else
    for targetFile in $targetFiles; do
        targetName=$(targetFileToName "$targetFile")
        echo "Fuzzing target $targetName ($targetFile)"
        cargo fuzz run "$targetName" --fuzz-dir "$REPO_DIR"/payjoin-fuzz/ --features libfuzzer_fuzz -- -max_total_time=30
    done
fi

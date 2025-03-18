#!/usr/bin/env bash

# Continuously cycle over fuzz targets running each for 1 hour.
# It uses chrt SCHED_IDLE so that other process takes priority.
#
# For cargo-fuzz usage see https://github.com/rust-fuzz/cargo-fuzz?tab=readme-ov-file#usage

set -euo pipefail

ENGINE="fuzz"

if [[ ${1:-} == "hfuzz" || ${1:-} == "fuzz" || ${1:-} == "afl" ]]; then
    ENGINE="$1"
    shift
fi

REPO_DIR=$(git rev-parse --show-toplevel)
# can't find the file because of the ENV var
# shellcheck source=/dev/null
source "$REPO_DIR/payjoin-fuzz/fuzz-util.sh"

if [[ $ENGINE == "hfuzz" ]]; then
    export HFUZZ_BUILD_ARGS="--features honggfuzz_fuzz"
    while :; do
        for targetFile in $(listTargetFiles); do
            targetName=$(targetFileToName "$targetFile")
            echo "Fuzzing target $targetName ($targetFile)"
            HFUZZ_INPUT_ARGS="-f corpus/$targetName/"
            # fuzz for one hour
            HFUZZ_RUN_ARGS="--run_time 3600 --exit_upon_crash -v $HFUZZ_INPUT_ARGS" cargo hfuzz run "$targetName"
            # minimize the corpus
            HFUZZ_RUN_ARGS="-i hfuzz_workspace/$targetName/input/ -P -M" chrt -i 0 cargo hfuzz run "$targetName"
        done
    done
elif [[ $ENGINE == "afl" ]]; then
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export AFL_SKIP_CPUFREQ=1
    export AFL_AUTORESUME=1
    while :; do
        for targetFile in $(listTargetFiles); do
            targetName=$(targetFileToName "$targetFile")
            echo "Fuzzing target $targetName ($targetFile)"
            cargo afl config --build --force
            cargo afl build --bin "$targetName" --features afl_fuzz
            # fuzz for one hour
            afl-fuzz -i corpus/"$targetName"/ -o afl_target -V 30 ../target/debug/"$targetName" --features afl_fuzz
            # minimize the corpus
            afl-cmin -i afl_target/default/queue/ -o corpus/minimized/"$targetName"/ -- ../target/debug/"$targetName" --features afl_fuzz
            # overwrite the old corpus
            rm -rf corpus/"$targetName"/*
            mv corpus/minimized/"$targetName"/id:* corpus/"$targetName"/
            rm -rf corpus/minimized/"$targetName"/* corpus/minimized/"$targetName"/.[!.]* corpus/minimized/"$targetName"/..?*
        done
    done
else
    while :; do
        for targetFile in $(listTargetFiles); do
            targetName=$(targetFileToName "$targetFile")
            echo "Fuzzing target $targetName ($targetFile)"
            # fuzz for one hour
            cargo +nightly fuzz run "$targetName" --fuzz-dir "$REPO_DIR"/payjoin-fuzz/ --features libfuzzer_fuzz -- -max_total_time=30
            # minimize the corpus
            cargo +nightly fuzz cmin "$targetName" --fuzz-dir "$REPO_DIR"/payjoin-fuzz/ --features libfuzzer_fuzz
        done
    done
fi

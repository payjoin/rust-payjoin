#!/usr/bin/env bash

# Sort order is affected by locale. See `man sort`.
# > Set LC_ALL=C to get the traditional sort order that uses native byte values.
export LC_ALL=C

REPO_DIR=$(git rev-parse --show-toplevel)

listTargetFiles() {
    pushd "$REPO_DIR/fuzz" >/dev/null || exit 1
    find fuzz_targets/ -type f -name "*.rs" | sort
    popd >/dev/null || exit 1
}

targetFileToName() {
    echo "$1" |
        sed 's/^fuzz_targets\///' |
        sed 's/\.rs$//' |
        sed 's/\//_/g' |
        sed 's/^_//g'
}

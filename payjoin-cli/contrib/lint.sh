#!/usr/bin/env bash
set -e

# Protocol versions and wallet backends are orthogonal; every version must
# build against every backend, so lint them as a matrix.
versions=("v1" "v2")
backends=("bitcoind" "esplora")

for version in "${versions[@]}"; do
    for backend in "${backends[@]}"; do
        # Don't duplicate --all-targets clippy. Clippy end-user code, not tests.
        cargo clippy --no-default-features --features "$version,$backend" -- -D warnings
    done
done

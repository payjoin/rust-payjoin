#!/usr/bin/env bash
set -e

# Individual features with no defaults.
features=("v1" "v2" "directory")

for feature in "${features[@]}"; do
    # Don't duplicate --all-targets clippy. Clippy end-user code, not tests.
    cargo clippy --locked --no-default-features --features "$feature" -- -D warnings
done

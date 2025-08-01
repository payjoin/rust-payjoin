#!/usr/bin/env bash
set -e

# Individual features with no defaults.
features=("_manual-tls" "_test-utils")

for feature in "${features[@]}"; do
  # Don't duplicate --all-targets clippy. Clippy end-user code, not tests.
  cargo clippy --no-default-features --features "$feature" -- -D warnings
done

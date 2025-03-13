#!/usr/bin/env bash
set -e

# Run clippy at top level for crates without feature-specific checks
echo "Running workspace lint..."
cargo clippy --all-targets --keep-going --all-features -- -D warnings

# Lint independent feature sets
FEATURE_CRATES="payjoin payjoin-cli"

for crate in $FEATURE_CRATES; do
    echo "Running independent feature lints for $crate crate..."
    (
        cd "$crate"
        ./contrib/lint.sh
    )
done

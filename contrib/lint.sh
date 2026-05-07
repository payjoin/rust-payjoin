#!/usr/bin/env bash
set -e

# Re-exec inside the nix devshell so the rust toolchain matches CI.
# Skip if already inside (direnv users, CI step that pre-enters).
if [ -z "${IN_NIX_SHELL:-}" ]; then
    exec nix develop --command bash "$0" "$@"
fi

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

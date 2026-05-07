#!/usr/bin/env bash
set -e

# Re-exec inside the nix devshell so the rust toolchain matches CI.
# Skip if already inside (direnv users, CI step that pre-enters).
if [ -z "${IN_NIX_SHELL:-}" ]; then
    exec nix develop --command bash "$0" "$@"
fi

# Individual features with no defaults.
features=("_manual-tls" "_test-utils")

for feature in "${features[@]}"; do
    # Don't duplicate --all-targets clippy. Clippy end-user code, not tests.
    cargo clippy --no-default-features --features "$feature" -- -D warnings
done

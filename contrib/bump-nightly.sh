#!/usr/bin/env bash
#
# Pin rust-toolchain.toml to the latest available nightly, and update the
# matching pinned nightly entries in .github/workflows/rust.yml so CI
# cache keys stay stable between weekly bumps.

set -euo pipefail

TOOLCHAIN_FILE="rust-toolchain.toml"
WORKFLOW_FILE=".github/workflows/rust.yml"
CHANNEL_URL="https://static.rust-lang.org/dist/channel-rust-nightly.toml"

latest=$(curl -fsSL "$CHANNEL_URL" | sed -n 's/^date = "\(.*\)"/\1/p')

if [ -z "$latest" ]; then
    echo "Failed to determine the latest nightly date from $CHANNEL_URL" >&2
    exit 1
fi

sed -i "s/^channel = \"nightly-[0-9-]*\"/channel = \"nightly-${latest}\"/" "$TOOLCHAIN_FILE"
sed -i "s/nightly-[0-9][0-9-]*/nightly-${latest}/g" "$WORKFLOW_FILE"

grep '^channel' "$TOOLCHAIN_FILE"
grep -n 'nightly-[0-9]' "$WORKFLOW_FILE" || echo "No pinned nightly found in $WORKFLOW_FILE" >&2

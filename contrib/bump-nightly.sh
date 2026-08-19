#!/usr/bin/env bash
#
# Pin rust-toolchain.toml to the latest available nightly

set -euo pipefail

TOOLCHAIN_FILE="rust-toolchain.toml"
CHANNEL_URL="https://static.rust-lang.org/dist/channel-rust-nightly.toml"

latest=$(curl -fsSL "$CHANNEL_URL" | sed -n 's/^date = "\(.*\)"/\1/p')

if [ -z "$latest" ]; then
    echo "Failed to determine the latest nightly date from $CHANNEL_URL" >&2
    exit 1
fi

sed -i "s/^channel = \"nightly-[0-9-]*\"/channel = \"nightly-${latest}\"/" "$TOOLCHAIN_FILE"

grep '^channel' "$TOOLCHAIN_FILE"

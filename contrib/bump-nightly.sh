#!/usr/bin/env bash
#
# Pin rust-toolchain.toml to the latest nightly, and update the matching
# pinned nightly entries in .github/workflows/rust.yml so CI cache keys
# stay stable between weekly bumps.
#
# The date is derived from the rust-overlay revision pinned in flake.lock
# (rather than static.rust-lang.org) so the pinned toolchain is guaranteed
# to resolve for every job evaluating the flake with the committed lock.

set -euo pipefail

TOOLCHAIN_FILE="rust-toolchain.toml"
WORKFLOW_FILE=".github/workflows/rust.yml"

nixpkgs_rev=$(jq -r '.nodes.root.inputs.nixpkgs as $id | .nodes[$id].locked.rev' flake.lock)
rust_overlay_rev=$(jq -r '.nodes.root.inputs["rust-overlay"] as $id | .nodes[$id].locked.rev' flake.lock)

latest=$(nix eval --raw --expr "
  let
    np = builtins.getFlake \"github:NixOS/nixpkgs/${nixpkgs_rev}\";
    ro = builtins.getFlake \"github:oxalica/rust-overlay/${rust_overlay_rev}\";
    pkgs = import np { system = \"x86_64-linux\"; overlays = [ ro.overlays.default ]; };
  in builtins.head (builtins.sort (a: b: a > b)
    (builtins.filter (n: n != \"latest\") (builtins.attrNames pkgs.rust-bin.nightly)))
")

if [ -z "$latest" ]; then
    echo "Failed to determine the latest nightly date known to rust-overlay ${rust_overlay_rev}" >&2
    exit 1
fi

sed -i "s/^channel = \"nightly-[0-9-]*\"/channel = \"nightly-${latest}\"/" "$TOOLCHAIN_FILE"
sed -i "s/nightly-[0-9][0-9-]*/nightly-${latest}/g" "$WORKFLOW_FILE"

grep '^channel' "$TOOLCHAIN_FILE"
grep -n 'nightly-[0-9]' "$WORKFLOW_FILE" || echo "No pinned nightly found in $WORKFLOW_FILE" >&2

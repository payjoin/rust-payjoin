#!/usr/bin/env bash
set -e

# Check compilation with individual features
cargo check --package payjoin --no-default-features --features v1
cargo check --package payjoin --no-default-features --features directory
cargo check --package payjoin --no-default-features --features v2
cargo check --package payjoin --no-default-features --features _multiparty

# Check compilation with all features
cargo check --package payjoin --all-features 
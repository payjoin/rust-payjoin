#!/usr/bin/env bash
set -e

features=("v1" "v2")

cargo test --locked --package payjoin --verbose --all-features --lib
cargo test --locked --package payjoin --verbose --all-features --test integration

for feature in "${features[@]}"; do
    cargo test --locked --package payjoin --verbose --no-default-features --features "$feature" --lib
    cargo test --locked --package payjoin --verbose --no-default-features --features "$feature" --test integration
done

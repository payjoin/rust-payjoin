#!/usr/bin/env bash
set -e

features=("v1" "v2")

cargo test --locked --package payjoin --verbose --all-features --lib
cargo test --locked --package payjoin --verbose --all-features --test integration
cargo test --locked --package payjoin --verbose --all-features --test e2e
cargo test --locked --package payjoin --verbose --no-default-features --features alloc,v1 --test e2e

for feature in "${features[@]}"; do
    cargo test --locked --package payjoin --verbose --no-default-features --features "$feature" --lib --no-run
    cargo test --locked --package payjoin --verbose --no-default-features --features "$feature" --test integration --no-run
done

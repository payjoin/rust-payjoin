#!/usr/bin/env bash
set -e

cargo test --locked --package payjoin --verbose --all-features --lib
cargo test --locked --package payjoin --verbose --all-features --test integration

cargo test --locked --package payjoin --verbose --no-default-features --features v1 --lib
cargo test --locked --package payjoin --verbose --no-default-features --features v1 --test integration

cargo test --locked --package payjoin --verbose --no-default-features --features v2 --lib
cargo test --locked --package payjoin --verbose --no-default-features --features v2 --test integration

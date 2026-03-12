#!/usr/bin/env bash
set -e

cargo test --locked --package payjoin-mailroom --verbose --all-features --lib
cargo test --locked --package payjoin-mailroom --verbose --all-features --test integration

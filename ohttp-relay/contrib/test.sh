#!/usr/bin/env bash
set -e

cargo test --locked --package ohttp-relay --verbose --all-features --lib
cargo test --locked --package ohttp-relay --verbose --all-features --test integration

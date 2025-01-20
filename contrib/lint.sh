#!/usr/bin/env bash
set -e

cargo clippy --all-targets --keep-going --no-default-features --features=v1,_danger-local-https -- -D warnings
cargo clippy --all-targets --keep-going --no-default-features --features=v2,_danger-local-https,io -- -D warnings

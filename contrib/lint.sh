#!/usr/bin/env bash
set -e

cargo clippy --all-targets --keep-going --features=send,receive -- -D warnings
cargo clippy --all-targets --keep-going --features=v2,_danger-local-https,io -- -D warnings

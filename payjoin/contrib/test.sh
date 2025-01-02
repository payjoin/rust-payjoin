#!/usr/bin/env bash
set -e

cargo test --locked --package payjoin --verbose --all-features --lib
cargo test --locked --package payjoin --verbose --features=send,receive --test integration
cargo test --locked --package payjoin --verbose --no-default-features --features=send,receive,_danger-local-https,v2,io --test integration

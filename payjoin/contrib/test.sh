#!/bin/bash
set -e

cargo test --locked --package payjoin --verbose --all-features --lib
cargo test --locked --package payjoin --verbose --features=send,receive --test integration
cargo test --locked --package payjoin --verbose --no-default-features --features=send,receive,danger-local-https,v2 --test integration
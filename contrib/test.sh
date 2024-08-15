#!/bin/bash
set -e

# Run tests for the Rust project
echo "Running Rust tests..."
cargo test --package payjoin --verbose --all-features --lib
cargo test --package payjoin --verbose --features=send,receive --test integration
cargo test --package payjoin --verbose --no-default-features --features=send,receive,danger-local-https,v2 --test integration
cargo test --package payjoin-cli --verbose --no-default-features --features=danger-local-https,v2 --test e2e
cargo test --package payjoin-cli --verbose --features=danger-local-https


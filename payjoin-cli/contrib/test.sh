#!/usr/bin/env bash
set -e

cargo test --locked --package payjoin-cli --verbose --no-default-features --features=_danger-local-https,v2 --test e2e
cargo test --locked --package payjoin-cli --verbose --no-default-features --features=v1,_danger-local-https

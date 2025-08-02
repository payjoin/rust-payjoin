#!/usr/bin/env bash
set -e

cargo test --locked --package payjoin --verbose --features v1,v2,_danger-local-https,_multiparty,io --lib
cargo test --locked --package payjoin --verbose --features v1,v2,_danger-local-https,_multiparty,io --test integration

#!/bin/bash

cargo test --locked --package payjoin-cli --verbose --no-default-features --features=danger-local-https,v2 --test e2e
cargo test --locked --package payjoin-cli --verbose --features=danger-local-https
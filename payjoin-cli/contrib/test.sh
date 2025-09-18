#!/usr/bin/env bash
set -e

cargo test --locked --package payjoin-cli --verbose --no-default-features --features "v1,v2,_manual-tls"

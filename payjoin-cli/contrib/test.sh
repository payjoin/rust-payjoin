#!/usr/bin/env bash
set -e

cargo test --locked --package payjoin-cli --verbose --features="_danger-local-https"

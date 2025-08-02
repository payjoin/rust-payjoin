#!/usr/bin/env bash
set -e

cargo test --locked --package payjoin-cli --verbose --features v1,v2,_danger-local-https

#!/usr/bin/env bash
set -e

cargo test --locked --package payjoin-service --verbose --all-features --lib

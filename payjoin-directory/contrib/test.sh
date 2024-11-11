#!/usr/bin/env bash
set -e

cargo test --locked --package payjoin-directory --verbose --all-features --lib

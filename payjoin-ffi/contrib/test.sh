#!/usr/bin/env bash
set -e

cargo test --locked --package payjoin-ffi --verbose --features=_danger-local-https,_test-utils

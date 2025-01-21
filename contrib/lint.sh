#!/usr/bin/env bash
set -e

cargo clippy --all-targets --keep-going --all-features -- -D warnings

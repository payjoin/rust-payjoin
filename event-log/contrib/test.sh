#!/usr/bin/env bash
set -e

cargo test --locked --package event-log --verbose --all-features

#!/usr/bin/env bash
set -e

# https://github.com/taiki-e/cargo-llvm-cov?tab=readme-ov-file#merge-coverages-generated-under-different-test-conditions
cargo llvm-cov clean --workspace # remove artifacts that may affect the coverage results
cargo llvm-cov --no-report --all-features
cargo llvm-cov report --lcov --output-path lcov.info # generate report without tests

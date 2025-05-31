#!/usr/bin/env bash
set -e

# https://github.com/taiki-e/cargo-llvm-cov?tab=readme-ov-file#merge-coverages-generated-under-different-test-conditions
cargo llvm-cov clean --workspace # remove artifacts that may affect the coverage results
cargo llvm-cov --no-report --no-default-features --features=v1,v2,io,_multiparty
cargo llvm-cov --no-report --package payjoin-cli --no-default-features --features=v1 # Explicitly run payjoin-cli v1 e2e tests
cargo llvm-cov report --lcov --output-path lcov.info # generate report without tests

#!/usr/bin/env bash
set -euo pipefail

OS=$(uname -s)
echo "Running on $OS"

npm --version

if [[ $OS == "Darwin" && -z ${IN_NIX_SHELL:-} ]]; then
    # TODO: check if brew & llvm are installed
    LLVM_PREFIX=$(brew --prefix llvm)
    export AR="$LLVM_PREFIX/bin/llvm-ar"
    export CC="$LLVM_PREFIX/bin/clang"
    echo "LLVM flags set: AR=$AR, CC=$CC"
fi

# The ubrn command is compiled from source during the build below, from a
# workspace that ships no lock file, so cargo resolves it fresh every run and
# picks up crates whose MSRV has moved past this shell's toolchain. Ask cargo
# to prefer versions compatible with the rustc in use instead of pinning each
# drifting crate by hand.
export CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback

# rustup target add is a no-op against a nix-provided toolchain
# (no rustup home, targets baked into the nix derivation instead).
if command -v rustup >/dev/null 2>&1 &&
    rustup show active-toolchain >/dev/null 2>&1; then
    rustup target add wasm32-unknown-unknown
fi

npm run build
npm run build:test-utils

echo "All done!"

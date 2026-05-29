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

# Heinous hack to pin a transitive dependency to be MSRV compatible on 1.85
cd node_modules/uniffi-bindgen-react-native
cargo add home@=0.5.11 --package uniffi-bindgen-react-native
cd ../..

# rustup target add is a no-op against a nix-provided toolchain
# (no rustup home, targets baked into the nix derivation instead).
if command -v rustup >/dev/null 2>&1 &&
    rustup show active-toolchain >/dev/null 2>&1; then
    rustup target add wasm32-unknown-unknown
fi

npm run build
npm run build:test-utils

echo "All done!"

#!/usr/bin/env bash
set -euo pipefail

OS=$(uname -s)
echo "Running on $OS"

npm --version

if [[ "$OS" == "Darwin" ]]; then
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

rustup target add wasm32-unknown-unknown

npm run build

echo "All done!"

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

npm run build

echo "All done!"

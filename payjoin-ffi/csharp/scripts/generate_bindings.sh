#!/usr/bin/env bash
set -euo pipefail

OS=$(uname -s)
echo "Running on $OS"

if [[ $OS == "Darwin" ]]; then
    LIBNAME=libpayjoin_ffi.dylib
elif [[ $OS == "Linux" ]]; then
    LIBNAME=libpayjoin_ffi.so
elif [[ $OS == MINGW* || $OS == MSYS* || $OS == CYGWIN* ]]; then
    # Git Bash / MSYS-style shells on Windows
    LIBNAME=payjoin_ffi.dll
else
    echo "Unsupported os: $OS"
    exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Navigate to payjoin-ffi directory (parent of csharp, which is parent of scripts)
cd "$SCRIPT_DIR/../.."

echo "Generating payjoin C#..."
# Include test utilities and manual TLS by default so local test services
# can fetch OHTTP keys over HTTPS with their generated self-signed cert.
PAYJOIN_FFI_FEATURES=${PAYJOIN_FFI_FEATURES:-_test-utils,_manual-tls}
GENERATOR_FEATURES="csharp"
if [[ -n $PAYJOIN_FFI_FEATURES ]]; then
    GENERATOR_FEATURES="$GENERATOR_FEATURES,$PAYJOIN_FFI_FEATURES"
fi

cargo build --features "$GENERATOR_FEATURES" --profile dev -j2

# Clean output directory to prevent duplicate definitions
echo "Cleaning csharp/src/ directory..."
mkdir -p csharp/src
rm -f csharp/src/*.cs

# Use the Cargo-managed C# generator pinned in payjoin-ffi/Cargo.toml.
UNIFFI_BINDGEN_LANGUAGE=csharp cargo run --features "$GENERATOR_FEATURES" --profile dev --bin uniffi-bindgen -- \
    --library ../target/debug/$LIBNAME \
    --out-dir csharp/src/

# Copy native library to csharp/lib/ directory for testing
echo "Copying native library..."
mkdir -p csharp/lib
cp ../target/debug/$LIBNAME csharp/lib/$LIBNAME

echo "All done!"

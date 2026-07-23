#!/usr/bin/env bash
set -euo pipefail

# --native-only builds the native library without regenerating the C# bindings, for callers
# (the per-RID packaging jobs) that consume only the native asset.
NATIVE_ONLY=0
if [[ ${1:-} == "--native-only" ]]; then
    NATIVE_ONLY=1
fi

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
# Keep parity with other language test scripts: include _test-utils by default.
PAYJOIN_FFI_FEATURES=${PAYJOIN_FFI_FEATURES-_test-utils}
PAYJOIN_FFI_PROFILE=${PAYJOIN_FFI_PROFILE:-dev}
if [[ $PAYJOIN_FFI_PROFILE == "dev" ]]; then
    TARGET_PROFILE_DIR=debug
else
    TARGET_PROFILE_DIR=$PAYJOIN_FFI_PROFILE
fi
GENERATOR_FEATURES="csharp"
if [[ -n $PAYJOIN_FFI_FEATURES ]]; then
    GENERATOR_FEATURES="$GENERATOR_FEATURES,$PAYJOIN_FFI_FEATURES"
fi

cargo build --features "$GENERATOR_FEATURES" --profile "$PAYJOIN_FFI_PROFILE" -j2

if [[ $NATIVE_ONLY -eq 0 ]]; then
    # Clean output directory to prevent duplicate definitions
    echo "Cleaning csharp/src/ directory..."
    mkdir -p csharp/src
    rm -f csharp/src/*.cs

    # Use the Cargo-managed C# generator pinned in payjoin-ffi/Cargo.toml.
    UNIFFI_BINDGEN_LANGUAGE=csharp cargo run --features "$GENERATOR_FEATURES" --profile dev --bin uniffi-bindgen -- \
        --library "../target/$TARGET_PROFILE_DIR/$LIBNAME" \
        --out-dir csharp/src/
fi

# Copy native library to csharp/lib/ directory for testing
echo "Copying native library..."
mkdir -p csharp/lib
cp "../target/$TARGET_PROFILE_DIR/$LIBNAME" "csharp/lib/$LIBNAME"

echo "All done!"

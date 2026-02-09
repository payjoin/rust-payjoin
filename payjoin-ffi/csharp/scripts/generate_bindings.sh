#!/usr/bin/env bash
set -euo pipefail

OS=$(uname -s)

echo "Running on $OS"

# Install Rust targets if on macOS
if [[ $OS == "Darwin" ]]; then
    LIBNAME=libpayjoin_ffi.dylib
elif [[ $OS == "Linux" ]]; then
    LIBNAME=libpayjoin_ffi.so
else
    echo "Unsupported os: $OS"
    exit 1
fi


cd ../
# This is a test script the actual release should not include the test utils feature
cargo build --features _test-utils --profile dev
# Generate C# bindings using uniffi-bindgen-cs
if command -v uniffi-bindgen-cs &> /dev/null; then
    uniffi-bindgen-cs --library ../target/debug/$LIBNAME --out-dir csharp/src/payjoin/ --config submodules/rust-payjoin/payjoin-ffi/uniffi.toml
else
    echo "uniffi-bindgen-cs not found. Installing..."
    cargo install uniffi-bindgen-cs --git https://github.com/NordSecurity/uniffi-bindgen-cs --tag v0.10.0+v0.29.4 --locked
    CARGO_BIN_DIR="${CARGO_HOME:-$HOME/.cargo}/bin"
    "${CARGO_BIN_DIR}/uniffi-bindgen-cs" --library ../target/debug/$LIBNAME --out-dir csharp/src/payjoin/ --config submodules/rust-payjoin/payjoin-ffi/uniffi.toml
fi

if [[ $OS == "Darwin" ]]; then
    echo "Generating native binaries..."
    rustup target add aarch64-apple-darwin x86_64-apple-darwin
    # This is a test script the actual release should not include the test utils feature
    cargo build --profile dev --target aarch64-apple-darwin --features _test-utils &
    cargo build --profile dev --target x86_64-apple-darwin --features _test-utils &
    wait

    echo "Building macos fat library"
    lipo -create -output csharp/src/payjoin/$LIBNAME \
        ../target/aarch64-apple-darwin/debug/$LIBNAME \
        ../target/x86_64-apple-darwin/debug/$LIBNAME

else
    echo "Generating native binaries..."
    rustup target add x86_64-unknown-linux-gnu
    # This is a test script the actual release should not include the test utils feature
    cargo build --profile dev --target x86_64-unknown-linux-gnu --features _test-utils

    echo "Copying payjoin_ffi binary"
    cp ../target/x86_64-unknown-linux-gnu/debug/$LIBNAME csharp/src/payjoin/$LIBNAME
fi

echo ""
echo "Fixing generated C# Bindings"
sed -i.bak -e 's/variant_value\.@)/variant_value.@v1)/g' \
    -e 's/public MonitorTransition Monitor\(/public MonitorTransition MonitorTransition(/g' \
    -e 's/MonitorTransition Monitor\(/MonitorTransition MonitorTransition(/g' \
    -e 's/new byte\[]\[(length)\]/new byte[length][]/g' \
    csharp/src/payjoin/payjoin.cs
rm -f csharp/src/payjoin/payjoin.cs.bak

echo "All done!"

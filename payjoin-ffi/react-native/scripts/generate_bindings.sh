#!/usr/bin/env bash
set -euo pipefail

OS=$(uname -s)
echo "Running on $OS"

npm --version

# The ubrn command is compiled from source during the build below, from a
# workspace that ships no lock file, so cargo resolves it fresh every run and
# picks up crates whose MSRV has moved past this shell's toolchain. Ask cargo
# to prefer versions compatible with the rustc in use instead of pinning each
# drifting crate by hand.
export CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback

# rustup target add is a no-op against a nix-provided toolchain (no rustup
# home, targets baked into the nix derivation instead).
if command -v rustup >/dev/null 2>&1 &&
    rustup show active-toolchain >/dev/null 2>&1; then
    rustup target add \
        aarch64-linux-android \
        armv7-linux-androideabi \
        i686-linux-android \
        x86_64-linux-android
    if [[ $OS == "Darwin" ]]; then
        rustup target add \
            aarch64-apple-ios \
            aarch64-apple-ios-sim \
            x86_64-apple-ios
    fi
fi

# Android: build the .so for every ABI and generate the Turbo Module.
# Requires the Android NDK (ANDROID_NDK_HOME) and cargo-ndk.
npm run ubrn:android

# iOS: build the static framework and generate the Turbo Module. Requires
# Xcode, so it is only attempted on macOS.
if [[ $OS == "Darwin" ]]; then
    npm run ubrn:ios
fi

# Compile the generated TypeScript entrypoint into lib/ with
# react-native-builder-bob.
npm run build

echo "All done!"

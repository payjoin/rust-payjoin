# Contributing

Instructions for building and testing the React Native bindings locally.

## Prerequisites

This assumes you already have Rust and Node.js installed.

Native builds additionally require:

- **Android:** the Android NDK (set `ANDROID_NDK_HOME`) and
  [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk) (`cargo install cargo-ndk`).
- **iOS (macOS only):** Xcode and the iOS Rust targets (added automatically by
  the build script when using rustup).

## Build Bindings

Follow these steps to clone the repository and build the bindings.

```shell
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin/payjoin-ffi/react-native

# Clean out stale generated output
npm run clean
rm -rf node_modules

# Install package dependencies
npm install

# Build the native libraries and generate the Turbo Module bindings
bash ./scripts/generate_bindings.sh
```

The script builds Android for all ABIs and, on macOS, iOS for device and
simulator, then compiles the generated TypeScript with
[react-native-builder-bob](https://github.com/callstack/react-native-builder-bob).

## Testing

On-device tests require an example app (not yet included) plus an iOS simulator
or Android emulator. In a headless environment, typecheck the generated
bindings:

```shell
npm run typecheck
```

## Packaging

The published package ships the native build outputs (the iOS
`PayjoinRnFramework.xcframework`, the Android libraries, the generated
`cpp/` glue, and the podspec). These are gitignored and produced by
`scripts/generate_bindings.sh`. Build and pack the tarball with:

```shell
bash ./contrib/pack.sh
```

The script installs dependencies from the lockfile (`npm ci`), generates the
bindings, verifies the artifacts, and writes the tarball to `artifacts/`.
`generate_bindings.sh` builds the iOS artifacts only on macOS, so run this
from a macOS host; on Linux the artifact check aborts rather than shipping a
tarball with no iOS slice.

As a safety net, `prepack` runs `scripts/check_artifacts.sh` on every
`npm pack`/`npm publish`, so an ad-hoc pack that skipped the build fails
instead of shipping a broken tarball.

# Payjoin Dart Bindings

Welcome to the Dart language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/)!

## Using the bindings in your app

Declare the package as a dependency just like any other Dart package. When developing against the repo directly, point at the local path and let `flutter pub get` (or `dart pub get`) run the build hook:

```yaml
dependencies:
  payjoin:
    path: ../rust-payjoin/payjoin-ffi/dart
```

The `hook/build.dart` script drives `native_toolchain_rust` (plus the precompiled-binaries helper) so that `flutter pub get` downloads the verified binaries when available or builds the native crate locally on demand.

If you prefer to inspect or regenerate `payjoin.dart` manually, run the binder script from the `payjoin-ffi/dart` directory:

```bash
bash ./scripts/generate_bindings.sh
```

This produces `lib/payjoin.dart` and the native artifacts under `target/`. These files are not tracked in the repository, so you should regenerate them locally whenever the Rust API changes.

## Precompiled binaries

This package supports downloading signed precompiled binaries or building locally via Dart's Native Assets hook.
If precompiled binaries are attempted but unavailable or verification fails, it falls back to building from source.

### pubspec.yaml configuration

In your app's `pubspec.yaml`, add the `payjoin` section at the top level (next to `dependencies`), like:

```yaml
payjoin:
  precompiled_binaries:
    mode: auto # auto | always | never
```

`mode` controls when the precompiled path is used:
- `auto` prefers local builds if Rust toolchain is detected, otherwise uses precompiled binaries
- `always` requires precompiled binaries and skips local builds
- `never` always builds from source via the build hook

If your tooling must rely on the signed GitHub releases, set `mode: always` and configure `artifact_host`/`public_key` to point at the published assets so `PrecompiledBuilder` can download the `precompiled_<crateHash>` bundles (macOS/iOS + Android builds are published via `.github/workflows/payjoin-dart-precompile-binaries.yml`).

## Running Tests

Follow these steps to clone the repository and run the tests.

```shell
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin/payjoin-ffi/dart

# Generate the bindings
bash ./scripts/generate_bindings.sh

# Run all tests
dart test
```

Maintainers: see `docs/precompiled_binaries.md` for CI details, manual release steps, and configuration.

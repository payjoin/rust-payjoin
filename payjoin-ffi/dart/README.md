# Payjoin Dart Bindings

Welcome to the Dart language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/)!

## Usage

### Install

```shell
dart pub add payjoin
```

### Import

```dart
import 'package:payjoin/payjoin.dart' as payjoin;
```

For OHTTP relay helpers:

```dart
import 'package:payjoin/http.dart' as payjoin_http;
```

### Native build

The package compiles its Rust library on your machine through a Dart
build hook, with the toolchain named in `native/rust-toolchain.toml`.

- **Hosted releases are locked.** A version from pub.dev ships the
  `native/Cargo.lock` it was released with, and the hook builds it with
  `--locked`. Every release compiles the same dependency versions,
  whenever and wherever you build it.
- **Git dependencies are development builds.** A `git:` dependency on
  this repository checks out the monorepo layout, which the hook treats
  as a development build: it builds `payjoin-ffi` from the checkout,
  enables test-only helpers and resolves dependencies afresh, without a
  lockfile. Use a hosted release in production.
- **Cargo config `rustflags` do not apply.** The hook sets
  `CARGO_ENCODED_RUSTFLAGS` to strip build paths from the library, and
  Cargo then ignores `build.rustflags` and `target.*.rustflags` from any
  Cargo config file for this build.

Made with [uniffi-dart](https://github.com/Uniffi-Dart/uniffi-dart)

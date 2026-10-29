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

### Native library

A Dart build hook provides the Rust library. Choose how in your app's
`pubspec.yaml`:

```yaml
hooks:
  user_defines:
    payjoin:
      build: prebuilt # the default, or source
```

#### Prebuilt (default)

The package ships the library the release built for each target, and
the hook bundles the one for yours. The build needs no Rust toolchain
and no network access. Your `pubspec.lock` pins the sha256 of the
package archive, and pub checks it on every download. Each library is
built twice by CI and attested by the release, and
[`VERIFYING.md`](https://github.com/payjoin/rust-payjoin/blob/master/payjoin-ffi/VERIFYING.md)
explains how to compare one with the GitHub release or rebuild it
yourself.

- **No fallback.** A target the package has no library for fails the
  build with a message that says how to switch to `build: source`. It
  never compiles instead.
- **Targets.** Android (arm64, armv7, x86_64) from API 21, iOS 13
  devices and arm64 simulators, macOS 10.15 on x86_64 and 11 on arm64,
  Linux with glibc 2.17 (arm64, x86_64), and Windows (arm64, x86_64).
  The Intel iOS simulator needs `build: source`.

#### Source

The hook compiles the library on your machine with the toolchain named
in `native/rust-toolchain.toml`.

- **Hosted releases are locked.** A version from pub.dev ships the
  `native/Cargo.lock` it was released with, and the hook builds it with
  `--locked`. Every release compiles the same dependency versions,
  whenever and wherever you build it.
- **Use a hosted release.** Only the package on pub.dev has the
  generated bindings, the prebuilt libraries and the pinned lockfile, so
  a `git:` dependency on this repository builds in neither mode.
- **Cargo config `rustflags` do not apply.** The hook sets
  `CARGO_ENCODED_RUSTFLAGS` to strip build paths from the library, and
  Cargo then ignores `build.rustflags` and `target.*.rustflags` from any
  Cargo config file for this build.

Made with [uniffi-dart](https://github.com/Uniffi-Dart/uniffi-dart)

# Contributing

Instructions for building, testing, and publishing the Dart bindings.

## Build Bindings

Follow these steps to clone the repository and run the tests.
This assumes you already have Rust and Dart installed.

```shell
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin/payjoin-ffi/dart

# Install package dependencies
dart pub get

# Generate the bindings
bash ./scripts/generate_bindings.sh
```

## Running Tests

```shell
# Run all tests
dart test
```

## Releasing

Maintainer instructions for publishing to
[pub.dev](https://pub.dev/packages/payjoin).

### Versioning

Starting with 0.25.0, `pubspec.yaml` carries the common `payjoin-ffi`
version shared by every published binding. The wrapped `payjoin` release
is named in the changelog entry rather than in the version, so a release
that only changes the wrapped core still bumps the common version.
Earlier versions carried it as build metadata, for example
`0.2.1+payjoin-1.0.0-rc.8`.

### Publishing

CI is the publish path. On every pull request touching `payjoin-ffi/**`,
the `Build and Test Dart` workflow regenerates the production bindings and
validates the archive with a publish dry run
([`contrib/prepare-publish.sh`](contrib/prepare-publish.sh)).

1. The preparation script stages a separate package and pins its Rust
   dependency to the checkout used to generate production bindings. The
   development pin in `native/Cargo.toml` is replaced only in that staging
   directory. Cargo overlays and local lockfiles are excluded. Both the
   publish dry run and publication use the staged package. For local checks:

   ```shell
   nix develop .#dart -c ./payjoin-ffi/dart/contrib/prepare-publish.sh /tmp/payjoin-pub
   ```

2. Follow the [shared bindings release instructions](../RELEASING.md).
   `pubspec.yaml` carries the common FFI version, for example `0.25.0`.
   One signed `payjoin-ffi-<version>` tag starts all publishers.
3. Configure pub.dev automated publishing with tag pattern
   `payjoin-ffi-{{version}}` and environment `release` before the first
   shared release. Approve the release environment when prompted.
4. Verify the [pub.dev listing](https://pub.dev/packages/payjoin) shows the
   new version and changelog. The staged package's native Rust revision
   must equal the shared tag's commit.

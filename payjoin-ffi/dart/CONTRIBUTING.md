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

Versions take the form `<package version>+payjoin-<crate version>`, for
example `0.2.1+payjoin-1.0.0-rc.8`. The part before the `+` is the package's
own semantic version, and is what consumers write version constraints
against. The build metadata after it records which `payjoin` release the
bindings wrap, so the pub.dev listing names the supported protocol version
without a changelog lookup.

Bump the package version for changes to the Dart API or to packaging. Update
the build metadata whenever the wrapped `payjoin` release changes, which is a
patch bump at minimum, since the same Dart API gets new behavior.

### Publishing

1. Point the `payjoin-ffi` dependency in `native/Cargo.toml` at the commit
   tagged for the `payjoin` release being wrapped. Consumers build from that
   revision. `.cargo/config.toml` redirects it to the local workspace for
   development only, and `.pubignore` withholds that file from the archive.
2. Set the version in `pubspec.yaml` and describe the consumer-visible
   changes under a matching heading in `CHANGELOG.md`.
3. Run the tests: `bash ./contrib/test.sh`.
4. Generate the bindings to be shipped and inspect the archive.

   ```shell
   bash ./scripts/generate_bindings.sh
   dart pub publish --dry-run
   ```

   `.pubignore` replaces `.gitignore` for publishing, so a gitignored file is
   only kept out of the archive if `.pubignore` also lists it. Two build
   artifacts decide the contents here: `lib/payjoin.dart` has to be present
   and current, since it is the binding surface consumers import, and
   `native/Cargo.lock` has to be absent, since publishing one resolved
   against the `.cargo/config.toml` path overlay would hand consumers a
   lockfile pinned to a dependency graph they cannot reproduce. Delete it
   before publishing if a local build left one behind.

5. Publish.

   ```shell
   dart pub publish
   ```

Known limitation: `scripts/generate_bindings.sh` always builds with
`_test-utils`, so the bindings it emits declare test-only APIs such as
`TestServices` and `BitcoindEnv`. Consumers build the native library without
that feature, which leaves those declarations backed by symbols that are
absent at runtime. Every release so far ships them. Giving the script a
production mode, as `payjoin-ffi/csharp` does with `PAYJOIN_FFI_FEATURES`,
remains to be done.

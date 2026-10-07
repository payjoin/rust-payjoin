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

2. Set the version in `pubspec.yaml` and describe the consumer-visible
   changes under a matching heading in `CHANGELOG.md`.
3. Confirm every `Build and Test Dart` job is green on the release commit
   in `master`.
4. Tag that commit with `contrib/release/tag.sh` and push the tag it
   names. The tag is `payjoin-dart-<version>`, where `<version>` is the
   `pubspec.yaml` version exactly (including the `+` build metadata), as
   [`contrib/release-version.sh`](contrib/release-version.sh) prints it.
   tag.sh signs it with your key, which must be in `contrib/release/keys/` for
   `verify-tag` to accept it, refuses a commit that is not on `master`,
   and prints the push command.

   ```shell
   nix develop .#release -c contrib/release/tag.sh dart
   ```

   The tag reruns the tests and the archive verification at the tagged
   commit, then `publish-pub` verifies the tag matches `pubspec.yaml`,
   regenerates the production bindings, and publishes through pub.dev
   [automated publishing] (OIDC), so no long-lived credential is stored
   anywhere. The job runs in the `release` environment: approve the paused
   run before anything reaches the registry.

5. Verify the [pub.dev listing](https://pub.dev/packages/payjoin) shows the
   new version and its changelog.

[automated publishing]: https://dart.dev/tools/pub/automated-publishing

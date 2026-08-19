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

1. Point the `payjoin-ffi` dependency in `native/Cargo.toml` at the commit
   tagged for the `payjoin` release being wrapped. Consumers build from that
   revision. `.cargo/config.toml` redirects it to the local workspace for
   development only, and `.pubignore` withholds that file from the archive.
2. Set the version in `pubspec.yaml` and describe the consumer-visible
   changes under a matching heading in `CHANGELOG.md`.
3. Confirm every `Build and Test Dart` job is green on the release commit
   in `master`.
4. Tag that commit `payjoin-dart-<version>`, where `<version>` is the
   `pubspec.yaml` version exactly (including the `+` build metadata). The
   tag must be annotated and signed by a maintainer key in
   `contrib/release/keys/`, and the tagged commit must be on `master`;
   `verify-tag` refuses to publish otherwise.

   ```shell
   git tag -s 'payjoin-dart-0.2.1+payjoin-1.0.0-rc.8' -m 'payjoin-dart-0.2.1+payjoin-1.0.0-rc.8'
   git push upstream 'payjoin-dart-0.2.1+payjoin-1.0.0-rc.8'
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

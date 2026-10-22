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

### The native build hook

`hook/build.dart` builds the `native/` wrapper crate for the consumer's
target. It takes the presence of `.cargo/config.local.toml` as the sign
that it is running inside this repository rather than from a published
archive, because `.pubignore` withholds `.cargo/` from that archive. In
the repository the overlay redirects `payjoin-ffi` to the workspace and
the hook enables `_test-utils`. From an archive the hook builds the
shipped `native/Cargo.lock` with `--locked`.

This cannot be an environment variable. `hooks_runner` spawns build hooks
with an allowlisted environment (`HOME`, `PATH` and a few toolchain
prefixes), so a project specific variable never reaches the hook.

The hook also passes `--remap-path-prefix` for the package, output, Cargo
and Rustup directories, so the artifact does not record where it was
built. The prefixes go through `CARGO_ENCODED_RUSTFLAGS` rather than
`RUSTFLAGS`, since Cargo splits the latter on whitespace and a consumer's
project path may contain spaces.

### Reproducible native builds

CI builds the staged package twice the way a Dart consumer does, with
`contrib/consumer`, and requires byte-identical host libraries. Each
build gets its own copy of the stage, its own app directory and its own
`HOME`, and with it its own Cargo, rustup and pub homes. The
`reproducible-linux` job in `.github/workflows/dart.yml` lists the
steps.

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
   directory. Cargo overlays are excluded. The staged `native/Cargo.lock`
   is seeded from `Cargo-recent.lock` and resolved against that revision,
   so consumers build the versions CI tested. A dependency fix reaches
   Dart consumers through `Cargo-recent.lock` and a new release. Staging
   fetches the pinned commit from GitHub, so it must be pushed. The
   `payjoin` and `payjoin-mailroom` crates come from crates.io, except
   with `--core-from-revision`, which pull requests use since they may
   change those crates without a version bump. That option takes them
   from the same revision and writes an `UNPUBLISHED_CORE` marker, which
   `contrib/publish.sh` refuses. Both the publish dry run and
   publication use the staged package. For local checks:

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

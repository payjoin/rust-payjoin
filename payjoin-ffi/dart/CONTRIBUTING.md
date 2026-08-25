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
bash ./contrib/test.sh
```

This is what CI runs. It also moves `native/Cargo.lock` aside for the run
and puts it back afterwards, which a bare `dart test` does not: the tracked
lockfile pins the published dependency graph, and the development overlay
resolves a different one, so Cargo would refuse it and then overwrite it.

### The native build hook

`hook/build.dart` builds the `native/` wrapper crate for the consumer's
target. It takes the presence of `.cargo/config.local.toml` as the signal
that it is running inside this repository rather than from a published
archive, because `.pubignore` withholds `.cargo/` from that archive. There
the overlay redirects `payjoin-ffi` to the workspace and the hook enables
`_test-utils`; from an archive the hook builds the tracked production graph
with `--locked` instead.

This cannot be an environment variable. `hooks_runner` spawns build hooks
with an allowlisted environment — `HOME`, `PATH`, a handful of toolchain
names — and a project specific variable never reaches the hook.

The hook also passes `--remap-path-prefix` for the package, output, Cargo,
and Rustup directories, so the artifact does not record where it was built.
Those prefixes go through `CARGO_ENCODED_RUSTFLAGS` rather than `RUSTFLAGS`,
since Cargo splits the latter on whitespace and a consumer's project path
may contain spaces.

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
   tagged for the `payjoin` release being wrapped, then regenerate the
   tracked lockfile consumers build with `--locked` and commit it:

   ```shell
   # from native/, so rustup picks up its pinned toolchain
   (cd native && cargo generate-lockfile)
   bash ./contrib/check_production_lock.sh native/Cargo.toml native/Cargo.lock
   ```

   The checker runs in CI too. It asserts that the lockfile pins the
   revision the manifest asks for, and that the wrapper is the only package
   without a `source`. Nothing greps for a `path` key: a Cargo lockfile has
   none, and a dependency resolved through the `.cargo/config.local.toml`
   overlay is exactly a package that lost its source.

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

## Checking native reproducibility

`contrib/check_reproducible.sh` compares two explicitly built native wrapper
artifacts byte-for-byte. It prints their SHA-256 digests, target, and compiler
toolchain versions, and works on Linux and macOS. Run its lightweight tests
without compiling Rust:

```shell
bash ./contrib/check_reproducible_test.sh
```

The following example fetches the production dependency graph once, copies
the resulting Cargo inputs, and runs two isolated builds in parallel. Set
`PAYJOIN_REPRO_PARENT` to a dedicated directory outside the repository, never
to a shared build directory. It builds the tracked `native/Cargo.lock` with
`--locked`, like a consumer does: the development `.cargo/config.local.toml`
overlay is never read, and `_test-utils` stays off.

```shell
set -euo pipefail
repro_parent="${PAYJOIN_REPRO_PARENT:?Set PAYJOIN_REPRO_PARENT to a dedicated directory}"
work_dir=$(mktemp -d "$repro_parent/payjoin-dart-repro.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT
toolchain_bin=$(dirname "$(rustup which --toolchain 1.85.1 cargo)")
cargo_bin="$toolchain_bin/cargo"
rustc_bin="$toolchain_bin/rustc"
target=$("$rustc_bin" -vV | awk '/^host:/{print $2}')
artifact=libpayjoin_ffi_wrapper.so

if [[ "$(uname -s)" == Darwin ]]; then
  artifact=libpayjoin_ffi_wrapper.dylib
fi

mkdir -p "$work_dir/seed" "$work_dir/cargo-seed" "$work_dir/first" \
  "$work_dir/second" "$work_dir/cargo-first" "$work_dir/cargo-second"
cp -a ./native/. "$work_dir/seed/"
CARGO_HOME="$work_dir/cargo-seed" "$cargo_bin" fetch --locked \
  --manifest-path "$work_dir/seed/Cargo.toml"
cp -a "$work_dir/seed/." "$work_dir/first/"
cp -a "$work_dir/seed/." "$work_dir/second/"
cp -a "$work_dir/cargo-seed/." "$work_dir/cargo-first/"
cp -a "$work_dir/cargo-seed/." "$work_dir/cargo-second/"

# Unit separated, like the hook: these prefixes are absolute paths and
# Cargo splits plain RUSTFLAGS on whitespace.
encode_flags() {
  local copy=$1
  printf '%s\x1f%s\x1f%s' \
    "--remap-path-prefix=$work_dir/$copy=/payjoin/package" \
    "--remap-path-prefix=$work_dir/cargo-$copy=/cargo" \
    "--remap-path-prefix=$work_dir/$copy-target=/payjoin/output"
}

build_copy() {
  local copy=$1
  CARGO_ENCODED_RUSTFLAGS="$(encode_flags "$copy")" RUSTC="$rustc_bin" \
    RUSTC_WRAPPER= CARGO_NET_OFFLINE=true \
    CARGO_HOME="$work_dir/cargo-$copy" "$cargo_bin" build --offline \
    --manifest-path "$work_dir/$copy/Cargo.toml" --release --locked \
    --target "$target" --target-dir "$work_dir/$copy-target"
}

build_copy first >"$work_dir/first-build.log" 2>&1 &
first_pid=$!
build_copy second >"$work_dir/second-build.log" 2>&1 &
second_pid=$!

first_status=0
second_status=0
wait "$first_pid" || first_status=$?
wait "$second_pid" || second_status=$?
((first_status == 0 && second_status == 0))

bash ./contrib/check_reproducible.sh \
  "$target" \
  "$($rustc_bin --version)" \
  "$(clang --version | awk 'NR == 1 {print}')" \
  "$(ld.lld --version | awk 'NR == 1 {print}')" \
  "$work_dir/first-target/$target/release/$artifact" \
  "$work_dir/second-target/$target/release/$artifact"
```

For Android, pass an Android triple as `--target` and read the artifact from
the matching directory. The same lockfile and offline Cargo inputs must be
used. Do not replace `native/Cargo.lock` with one generated through the local
path overlay: `contrib/check_production_lock.sh` rejects that, and consumers
could not resolve it.

### Consumer smoke test

`contrib/smoke_consumer.sh` checks the published binding source in two isolated
Dart consumers. It requires a dedicated writable parent and a read-only seed
Cargo cache; the script copies that cache into per-consumer homes and removes
all generated files from its own temporary directory on exit.

```shell
PAYJOIN_SMOKE_PARENT=/path/to/dedicated/smoke-parent \
PAYJOIN_BINDING_SOURCE=/path/to/published/payjoin.dart \
PAYJOIN_SMOKE_CARGO_HOME=/path/to/dedicated/cargo-cache \
bash ./contrib/smoke_consumer.sh
```

The two runs use separate `CARGO_HOME` values, and each consumer's hook
builds under its own `.dart_tool`, so Cargo already gets a distinct target
directory per run. Setting `CARGO_TARGET_DIR` would change nothing: the hook
passes `--target-dir` explicitly, and the command line wins. Android and
cross-host consumer builds still require the equivalent target and toolchain
smoke coverage described above.

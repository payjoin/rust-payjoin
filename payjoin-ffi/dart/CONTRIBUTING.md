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
   tagged for the `payjoin` release being wrapped. Generate `native/Cargo.lock`
   with the local `.cargo/config.local.toml` absent, verify that it contains the
   intended Git revision and no `path` dependencies, and commit it. Consumers
   build this production graph with `--locked`. The local `.cargo/config.local.toml`
   redirects dependencies to the workspace for development only, and
   `.pubignore` withholds that overlay from the archive.
2. Set the version in `pubspec.yaml` and describe the consumer-visible
   changes under a matching heading in `CHANGELOG.md`.
3. Run the tests: `bash ./contrib/test.sh`.
4. Generate the bindings to be shipped and inspect the archive.

   ```shell
   bash ./scripts/generate_bindings.sh
   dart pub publish --dry-run
   ```

    `.pubignore` replaces `.gitignore` for publishing, so a gitignored file is
    only kept out of the archive if `.pubignore` also lists it. The archive
    must contain both the current `lib/payjoin.dart` binding surface and the
   production `native/Cargo.lock`; it must not contain `.cargo/config.local.toml`.

5. Publish.

   ```shell
   dart pub publish
   ```

Local hook builds enable `_test-utils` only when
`PAYJOIN_FFI_ENABLE_TEST_UTILS=1` is set. The value `1` is the only accepted
opt-in; missing or other values keep the production feature set. The
`contrib/test.sh` script sets this variable because its integration tests use
the test helper bindings.

Known limitation: `scripts/generate_bindings.sh` always builds with
`_test-utils`, so the bindings it emits declare test-only APIs such as
`TestServices` and `BitcoindEnv`. Consumers build the native library without
that feature, which leaves those declarations backed by symbols that are
absent at runtime. Every release so far ships them. Giving the script a
production mode, as `payjoin-ffi/csharp` does with `PAYJOIN_FFI_FEATURES`,
remains to be done.

## Checking native reproducibility

`contrib/check_reproducible.sh` compares two explicitly built native wrapper
artifacts byte-for-byte. It prints their SHA-256 digests, target, and compiler
toolchain versions, and works on Linux and macOS. Run its lightweight tests
without compiling Rust:

```shell
bash ./contrib/check_reproducible_test.sh
```

The following example resolves the production dependency graph once, copies
the resulting Cargo inputs, and runs two isolated builds in parallel. Set
`PAYJOIN_REPRO_PARENT` to a dedicated directory outside the repository, never
to a shared build directory. This avoids relying on the development
`.cargo/config.local.toml` overlay and does not enable `_test-utils`.

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
CARGO_HOME="$work_dir/cargo-seed" "$cargo_bin" generate-lockfile \
  --manifest-path "$work_dir/seed/Cargo.toml"
CARGO_HOME="$work_dir/cargo-seed" "$cargo_bin" fetch --locked \
  --manifest-path "$work_dir/seed/Cargo.toml"
cp -a "$work_dir/seed/." "$work_dir/first/"
cp -a "$work_dir/seed/." "$work_dir/second/"
cp -a "$work_dir/cargo-seed/." "$work_dir/cargo-first/"
cp -a "$work_dir/cargo-seed/." "$work_dir/cargo-second/"

first_flags="--remap-path-prefix=$work_dir/first=/payjoin/package"
first_flags+=" --remap-path-prefix=$work_dir/cargo-first=/cargo"
first_flags+=" --remap-path-prefix=$work_dir/first-target=/payjoin/target"
second_flags="--remap-path-prefix=$work_dir/second=/payjoin/package"
second_flags+=" --remap-path-prefix=$work_dir/cargo-second=/cargo"
second_flags+=" --remap-path-prefix=$work_dir/second-target=/payjoin/target"

(
  RUSTFLAGS="$first_flags" RUSTC="$rustc_bin" RUSTC_WRAPPER= \
    CARGO_NET_OFFLINE=true CARGO_HOME="$work_dir/cargo-first" \
    CARGO_TARGET_DIR="$work_dir/first-target" "$cargo_bin" build --offline \
    --manifest-path "$work_dir/first/Cargo.toml" --release --locked \
    --no-default-features
) > "$work_dir/first-build.log" 2>&1 &
first_pid=$!
(
  RUSTFLAGS="$second_flags" RUSTC="$rustc_bin" RUSTC_WRAPPER= \
    CARGO_NET_OFFLINE=true CARGO_HOME="$work_dir/cargo-second" \
    CARGO_TARGET_DIR="$work_dir/second-target" "$cargo_bin" build --offline \
    --manifest-path "$work_dir/second/Cargo.toml" --release --locked \
    --no-default-features
) > "$work_dir/second-build.log" 2>&1 &
second_pid=$!

first_status=0
second_status=0
wait "$first_pid" || first_status=$?
wait "$second_pid" || second_status=$?
(( first_status == 0 && second_status == 0 ))

bash ./contrib/check_reproducible.sh \
  "$target" \
  "$($rustc_bin --version)" \
  "$(clang --version | awk 'NR == 1 {print}')" \
  "$(ld.lld --version | awk 'NR == 1 {print}')" \
  "$work_dir/first-target/release/$artifact" \
  "$work_dir/second-target/release/$artifact"
```

For Android, pass `--target TARGET` to both `cargo build` commands and use
`$work_dir/{first,second}-target/TARGET/release/ARTIFACT`. The same lockfile
and offline Cargo inputs must be used. The hook uses the tracked production
lockfile with `--locked`; do not replace it with a lock generated through the
local path overlay.

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

The two consumer runs use separate `CARGO_HOME` and `CARGO_TARGET_DIR` values.
Android and cross-host consumer builds still require the equivalent target and
toolchain smoke coverage described above.

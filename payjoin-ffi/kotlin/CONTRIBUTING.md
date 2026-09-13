# Contributing to the Payjoin Kotlin Bindings

Kotlin/JVM bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/), generated from
`payjoin-ffi` with Mozilla UniFFI. This document covers building from source and running tests.

## Development

```shell
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin/payjoin-ffi/kotlin
bash ./scripts/generate_bindings.sh
./gradlew test
```

Generation uses the in-tree `uniffi-bindgen` binary (`--language kotlin`). There is no extra Cargo
feature on `payjoin-ffi`. By default, development generation enables `_test-utils`. For production
bindings, set `PAYJOIN_FFI_FEATURES` to empty:

```shell
PAYJOIN_FFI_FEATURES= bash ./scripts/generate_bindings.sh
```

Protocol `close` is renamed to `closeSession` only in `[bindings.kotlin.rename]` in
`payjoin-ffi/uniffi.toml`, so it does not clash with `AutoCloseable.close()`.

With nix, `nix develop .#kotlin` provides the pinned MSRV Rust toolchain, JDK 21, and
`BITCOIND_EXE` (via `nixpkgs`, with `BITCOIND_SKIP_DOWNLOAD=1`), and is what CI uses. Without
nix, use a local JDK 21+ and the Gradle wrapper; `corepc-node` will download `bitcoind` on
first test run.

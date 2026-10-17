# Contributing to the Payjoin Java Bindings

Java bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/), generated from `payjoin-ffi`
with `uniffi-bindgen-java`. This document covers building from source and running tests.

## Development

```shell
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin/payjoin-ffi/java
bash ./scripts/generate_bindings.sh
./gradlew test
```

Generation builds a small locally-patched copy of `uniffi-bindgen-java` from the exact canonical
upstream commit the `0.4.2` tag points to (see README.md "Generator provenance" for why and
`payjoin-ffi/java/patches/` for the patch itself), cached under
`$CARGO_HOME/uniffi-bindgen-java-<rev>-<patch-hash>/`, then runs it against `payjoin-ffi`'s
compiled library using the in-tree `[bindings.java]` section of `payjoin-ffi/uniffi.toml`. By
default, development generation enables `_test-utils`. For production bindings, set
`PAYJOIN_FFI_FEATURES` to empty:

```shell
PAYJOIN_FFI_FEATURES= bash ./scripts/generate_bindings.sh
```

Protocol `close` is renamed to `closeSession` only in `[bindings.java.rename]` in
`payjoin-ffi/uniffi.toml`, so it does not clash with `AutoCloseable.close()` - the same rename
`[bindings.kotlin.rename]` already applies for Kotlin.

With nix, `nix develop .#java` provides Rust (new enough for both `payjoin-ffi` and the pinned
generator - see flake.nix's `javaDevShell` comment for why one toolchain covers both), JDK 25,
Python 3, and `BITCOIND_EXE` (from `nixpkgs`, with `BITCOIND_SKIP_DOWNLOAD=1` so nothing is
downloaded), and is what CI uses. Without nix, see README.md "Requirements" for what needs to be
on `PATH` yourself; `corepc-node` downloads `bitcoind` on first test run in that case.

# Contributing

Instructions for building and testing the C++ bindings.

## Build Bindings

Use the repo's nix dev shell so the toolchain matches CI:

```shell
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin
nix develop .#cpp

cd payjoin-ffi/cpp

# Generate the bindings
bash ./scripts/generate_bindings.sh
```

The generator is the `uniffi-bindgen-cpp` fork pinned in
`payjoin-ffi/Cargo.toml` behind the `cpp` feature and dispatched through
`payjoin-ffi/uniffi-bindgen.rs`, the same pattern the C# and Dart bindings
use. Generated code lands in `src/` and is not checked in; regenerate after
any change to the FFI surface. Async exports are skipped during generation
(see README).

## Running Tests

```shell
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

Or run everything the way CI does:

```shell
./contrib/test.sh
```

## Formatting

Handwritten C++ under `tests/` is formatted by clang-format via treefmt; run
`nix fmt` before committing.

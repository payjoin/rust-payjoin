# Payjoin C++ Bindings

Welcome to the C++ language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/)!

Payjoin lets the receiver of a Bitcoin transfer contribute inputs to the sender's transaction. The result looks like any other transaction, which preserves privacy by poisoning the common-input-ownership heuristic that chain surveillance depends on, and it lets the receiver batch its own operations into the same transaction. These bindings implement both [BIP 78](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) (synchronous payjoin) and [BIP 77](https://github.com/bitcoin/bips/blob/master/bip-0077.md) (asynchronous payjoin, where sender and receiver exchange the transaction through an untrusted directory and never need to be online at the same time).

## Draft status

These bindings are a draft. They are generated with a
[fork of uniffi-bindgen-cpp](https://github.com/chavic/uniffi-bindgen-cpp)
carrying the in-progress uniffi 0.30/0.31 support
([NordSecurity/uniffi-bindgen-cpp#59](https://github.com/NordSecurity/uniffi-bindgen-cpp/pull/59)),
to be swapped for an upstream release once one supports uniffi 0.31.

Unlike the other language bindings, the async API surface (`save_async`,
`replay_*_event_log_async`, and the async persister interfaces) is not
exposed: uniffi-bindgen-cpp does not support async functions yet
([NordSecurity/uniffi-bindgen-cpp#51](https://github.com/NordSecurity/uniffi-bindgen-cpp/issues/51)),
so generation skips them. The synchronous API is complete.

## Build

Requires a C++20 compiler, CMake >= 3.24, and a Rust toolchain. The tests
additionally need libcurl and nlohmann-json (both provided by the repo's nix
dev shell: `nix develop .#cpp`).

```shell
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin/payjoin-ffi/cpp

# Generate the bindings into src/ and copy the native library into lib/
bash ./scripts/generate_bindings.sh

# Build the payjoin_cpp library and the tests
cmake -S . -B build
cmake --build build
```

Consume the `payjoin_cpp` CMake target: it exposes the generated headers and
links the `payjoin_ffi` cdylib built by cargo.

## Running Tests

```shell
ctest --test-dir build --output-on-failure
```

The integration tests spin up bitcoind and the payjoin test services, so they
need `BITCOIND_EXE` to point at a bitcoind binary (the nix dev shell sets it).

## End to end example

The usage reference is the commented walkthrough in
[`tests/integration_tests.cpp`](tests/integration_tests.cpp):
`test_integration_v2_to_v2` drives a complete payjoin from both sides,
executed by CI on every change so it cannot go stale.

<div align="center">
  <h1>Rust-Payjoin</h1>

  <img src="./static/monad.svg" width="150" />

  <p>
    <strong>Supercharged payment batching to save fees and preserve privacy</strong>
  </p>

  <p>
    <a href="https://crates.io/crates/payjoin"><img alt="Crates" src="https://img.shields.io/crates/v/payjoin.svg?logo=rust"></a>
    <a href="https://docs.rs/payjoin"><img alt="Crates" src="https://img.shields.io/static/v1?logo=read-the-docs&label=docs.rs&message=payjoin&color=f75390"></a>
    <a href="https://github.com/payjoin/rust-payjoin/actions/workflows/rust.yml"><img alt="CI Status" src="https://github.com/payjoin/rust-payjoin/actions/workflows/rust.yml/badge.svg"></a>
    <a href="https://coveralls.io/github/payjoin/rust-payjoin?branch=master"><img src="https://coveralls.io/repos/github/payjoin/rust-payjoin/badge.svg?branch=master"/></a>
    <a href="https://blog.rust-lang.org/2022/08/11/Rust-1.63.0.html"><img alt="Rustc Version 1.63.0+" src="https://img.shields.io/badge/rustc-1.63.0%2B-lightgrey.svg"/></a>
  </p>

  <h4>
    <a href="https://payjoindevkit.org">Project Homepage</a>
  </h4>
</div>

## About

### `payjoin`

The Payjoin Dev Kit `payjoin` library implements both [BIP 78 Payjoin V1](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) and [BIP 77 Payjoin V2](https://github.com/bitcoin/bips/blob/master/bip-0077.md).

### `payjoin-cli`

The [`payjoin-cli`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-cli) crate performs no-frills Payjoin as a reference implementation using Bitcoin Core wallet.

### `payjoin-directory`

The [`payjoin-directory`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-directory) crate implements the Payjoin Directory store-and-forward server required for Payjoin V2's asynchronous operation.

### `payjoin-test-utils`

The [`payjoin-test-utils`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-test-utils) crate provides commonly used testing fixtures such as a local OHTTP relay and payjoin directory, bitcoind node and wallets, and official test vectors.

### `payjoin-ffi`

The [`payjoin-ffi`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-ffi) crate provides language bindings that expose the Rust-based Payjoin implementation to various programming languages.

### Disclaimer ⚠️ WIP

**Use at your own risk. This crate has not yet been reviewed by independent Rust and Bitcoin security professionals.**

While I don't think there is a _huge_ risk running it, be careful relying on its security for now!

Seeking review of the code that verifies there is no overpayment. Contributions are welcome!

### Development status

#### Sender (V1 beta, V2 alpha)

- [x] Basic logic
- [x] Most checks implemented
- [x] Documentation
- [x] Unit test with official test vectors passes
- [x] Many unit tests
- [x] Fee contribution support
- [x] Example client using bitcoind
- [x] Tested and works with BTCPayServer
- [x] Tested and works with JoinMarket
- [x] Minimum fee rate enforcement
- [ ] Independent review
- [x] Independent testing

#### Receiver (V1 beta, V2 alpha)

- [x] Basic logic
- [x] Most checks implemented
- [x] Documentation
- [x] Unit test with official test vectors passes
- [x] Many unit tests
- [x] Fee contribution support
- [x] Example server using bitcoind
- [x] Tested and works with BTCPayServer
- [x] Tested and works with WasabiWallet
- [x] Tested and works with Blue Wallet
- [x] Tested and works with Sparrow
- [x] Tested and works with JoinMarket
- [x] Minimum fee rate enforcement
- [ ] Discount support
- [ ] Independent review
- [ ] Independent testing

#### Code quality

- [x] Idiomatic Rust code
- [x] Newtypes
- [x] Panic-free error handling
- [x] No `unsafe` code or well-tested/analyzed/proven/... `unsafe` code
- [x] Warning-free
- [x] CI
- [x] Integration tests
- [ ] Fuzzing
- [x] Coverage measurement
- [x] Mutation testing

## Minimum Supported Rust Version (MSRV)

The `payjoin` library and `payjoin-cli` should always compile with any combination of features on Rust **1.63.0**.

To build and test with the MSRV you will need to pin the below dependency versions:

### `payjoin`

```shell
cargo update -p cc --precise 1.0.105
cargo update -p regex --precise 1.9.6
cargo update -p reqwest --precise 0.12.4
cargo update -p url --precise 2.5.0
cargo update -p tokio --precise 1.38.1
cargo update -p tokio-util --precise 0.7.11
cargo update -p which --precise 4.4.0
cargo update -p zstd-sys --precise 2.0.8+zstd.1.5.5
```

### `payjoin-cli`

```shell
cargo update -p cc --precise 1.0.105
cargo update -p clap_lex --precise 0.3.0
cargo update -p regex --precise 1.9.6
cargo update -p reqwest --precise 0.12.4
cargo update -p time@0.3.36 --precise 0.3.20
cargo update -p tokio --precise 1.38.1
cargo update -p tokio-util --precise 0.7.11
cargo update -p url --precise 2.5.0
cargo update -p which --precise 4.4.0
cargo update -p zstd-sys --precise 2.0.8+zstd.1.5.5
```

## Contributing

See [`CONTRIBUTING.md`](.github/CONTRIBUTING.md)

## License

MIT

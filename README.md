# Rust-Payjoin

Supercharged payment batching to save you fees and preserve your privacy.

## About

### `payjoin`

The Payjoin Dev Kit `payjoin` library implements both [BIP 78 Payjoin V1](https://github.com/shesek/bips/blob/master/bip-0078.mediawiki) and [BIP 77 Payjoin V2](https://github.com/bitcoin/bips/pull/1483).

The `payjoin` crate is compatible with many wallets like LND in [nolooking](https://github.com/chaincase-app/nolooking) and Bitcoin Dev Kit in [Mutiny Wallet](https://github.com/MutinyWallet/mutiny-node) and in [BitMask](https://github.com/diba-io/bitmask-core)

### `payjoin-cli`

The [`payjoin-cli`](https://github.com/payjoin/rust-payjoin/tree/main/payjoin-cli) crate performs no-frills Payjoin as a reference implementation using Bitcoin Core wallet.

### `payjoin-directory`

The [`payjoin-directory`](https://github.com/payjoin/rust-payjoin/tree/main/payjoin-directory) crate implements the Payjoin Directory store-and-forward server required for Payjoin V2's asynchronous operation.

### Disclaimer ⚠️ WIP

**Use at your own risk. This crate has not yet been reviewed by independent Rust and Bitcoin security professionals.**

While I don't think there is a *huge* risk running it, be careful relying on its security for now!

Seeking review of the code that verifies there is no overpayment. Contributions are welcome!

### Development status

#### Sender (V1 beta, V2 alpha)

- [x] Basic logic
- [x] Most checks implemented
- [x] Documentation
- [x] Unit test with official test vectors passes
- [ ] Many unit tests
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
- [ ] Many unit tests
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
- [ ] Coverage measurement

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
cargo update -p url --precise 2.5.0
cargo update -p which --precise 4.4.0
cargo update -p zstd-sys --precise 2.0.8+zstd.1.5.5
```

## Code Formatting

We use the nightly Rust formatter for this project. Please run `rustfmt` using the nightly toolchain before submitting any changes.

## License

MIT

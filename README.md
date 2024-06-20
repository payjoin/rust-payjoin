# Payjoin implementation in Rust

## About

This is a library and a client binary for bitcoind implementing BIP78 Payjoin.

The library is perfectly IO-agnostic—in fact, it does no IO.
The primary goal of such design is to be easy to unit test.
While not there yet, it already has infinitely more tests than the [Payjoin PR against Electrum](https://github.com/spesmilo/electrum/pull/6804). :P

It doesn't care whether you use `async`, blocking, `tokio`, `sync-std` `hyper`, `actix` or whatever.
There are already too many frameworks in Rust so it's best avoiding directly introducing them into library code.
The library currently only contains sender implementation and a partial receiver.

The payjoin-cli binary performs no-frills Payjoin using Bitcoin Core wallet.
The payjoin crate also supports other wallet software [like LND](https://github.com/chaincase-app/nolooking).

### Disclaimer ⚠️ WIP

**Use at your own risk. this crate has not yet been reviewed by independent Rust and Bitcoin security professionals.**

While I don't think there is a *huge* risk running it, don't rely on its security for now!

Seeking review of the code that verifies there is no overpayment. Contributions are welcome!

### Development status

#### Sender (beta)

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

#### Receiver (beta)

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
cargo update -p regex --precise 1.9.6
cargo update -p url --precise 2.5.0
cargo update -p which --precise 4.4.0
cargo update -p reqwest --precise 0.12.4
```

### `payjoin-cli`

```shell
cargo update -p clap_lex --precise 0.3.0
cargo update -p regex --precise 1.9.6
cargo update -p url --precise 2.5.0
cargo update -p which --precise 4.4.0
cargo update -p time@0.3.36 --precise 0.3.20
cargo update -p reqwest --precise 0.12.4
```

## Code Formatting

We use the nightly Rust formatter for this project. Please run `rustfmt` using the nightly toolchain before submitting any changes.

## License

MIT

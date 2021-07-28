# PayJoin implementation in Rust

## About

### Disclaimer: WIP!

While I don't think there's a *huge* risk running it, don't rely on its security for now!
Please at least review the code that verifies there's no overpayment and let me know you did.

### Development status

- [ ] Sender
      - [x] Basic logic
      - [x] Most checks implemented
      - [x] Documentation
      - [x] Unit test with official test vectors passes
      - [ ] Many unit tests
      - [x] Fee contribution support
      - [x] Example client using bitcoind
      - [x] Tested and works with BTCPayServer
      - [ ] Tested and works with WasabiWallet
      - [ ] Minimum fee rate enforcement
      - [ ] Independent review
      - [ ] Independent testing
- [ ] Receiver
      - [ ] Basic logic
      - [ ] Most checks implemented
      - [ ] Documentation
      - [ ] Unit test with official test vectors passes
      - [ ] Many unit tests
      - [ ] Fee contribution support
      - [ ] Example client using bitcoind
      - [ ] Tested and works with BTCPayServer (short of [BTCPayServer bug](https://github.com/btcpayserver/btcpayserver/issues/2677))
      - [ ] Tested and works with WasabiWallet
      - [ ] Tested and works with Blue Wallet
      - [ ] Minimum fee rate enforcement
      - [ ] Discount support
      - [ ] Independent review
      - [ ] Independent testing
- [ ] Code quality
      - [x] Idiomatic Rust code
      - [x] Newtypes
      - [x] Panic-free error handling
      - [x] No `unsafe` code or well-tested/analyzed/proven/... `unsafe` code
      - [ ] Warning-free
      - [ ] CI
      - [ ] Integration tests
      - [ ] Fuzzing
      - [ ] Coverage measurement

### Description

This is a library and an example binary implementing BIP78 PayJoin.
The library is perfectly IO-agnostic - in fact, it does no IO.
The primary goal of such design is to make it easy to unit test.
While we're not there yet, it already has infinitely more tests than the [PayJoin PR against Electrum](https://github.com/spesmilo/electrum/pull/6804). :P

Additional advantage is it doesn't care whether you use `async`, blocking, `tokio`, `sync-std` `hyper`, `actix` or whatever.
There are already too many frameworks in Rust so it's best avoiding directly introducing them into library code.
The library currently only contains sender implementation but I want to add receiver too.

The provided binary is currently quickly hacked together tool that performs PayJoin using Bitcoin Core wallet.
The intention is to develop it further over time to support other backends (LND internal wallet comes to mind).

Contributions welcome!

## License

MITNFA with disclaimer: if you use this library in production without review you agree to be publicly
shamed and ridiculed for doing so.
The reviewer(s) must demonstrate good knowledge of Rust and relevant Bitcoin protocol details.

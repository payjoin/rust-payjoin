# PayJoin implementation in Rust

This is a library for bitcoind implementing BIP78 PayJoin.

The library is perfectly IO-agnostic—in fact, it does no IO.
The primary goal of such design is to be easy to unit test.
While not there yet, it already has infinitely more tests than the [PayJoin PR against Electrum](https://github.com/spesmilo/electrum/pull/6804). :P

It doesn't care whether you use `async`, blocking, `tokio`, `sync-std` `hyper`, `actix` or whatever.
There are already too many frameworks in Rust so it's best avoiding directly introducing them into library code.
The library currently only contains sender implementation and a partial receiver.

### Disclaimer ⚠️ WIP

**Use at your own risk. this crate has not yet been reviewed by independent Rust and Bitcoin security professionals.**

While I don't think there is a *huge* risk running it, don't rely on its security for now!

Seeking review of the code that verifies there is no overpayment. Contributions are welcome!

### Development status

#### Sender

- [x] Basic logic
- [x] Most checks implemented
- [x] Documentation
- [x] Unit test with official test vectors passes
- [ ] Many unit tests
- [x] Fee contribution support
- [x] Example client using bitcoind
- [x] Tested and works with BTCPayServer
- [ ] Tested and works with JoinMarket
- [x] Minimum fee rate enforcement
- [ ] Independent review
- [ ] Independent testing

#### Receiver

- [ ] Basic logic
- [ ] Most checks implemented
- [ ] Documentation
- [ ] Unit test with official test vectors passes
- [ ] Many unit tests
- [ ] Fee contribution support
- [ ] Example server using bitcoind
- [ ] Tested and works with BTCPayServer
- [ ] Tested and works with WasabiWallet
- [ ] Tested and works with Blue Wallet
- [ ] Minimum fee rate enforcement
- [ ] Discount support
- [ ] Independent review
- [ ] Independent testing

#### Code quality

- [x] Idiomatic Rust code
- [x] Newtypes
- [x] Panic-free error handling
- [x] No `unsafe` code or well-tested/analyzed/proven/... `unsafe` code
- [ ] Warning-free
- [x] CI
- [ ] Integration tests
- [ ] Fuzzing
- [ ] Coverage measurement

## License

MIT

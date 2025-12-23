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
    <a href="https://blog.rust-lang.org/2025/02/20/Rust-1.85.0/"><img alt="Rustc Version 1.85.0+" src="https://img.shields.io/badge/rustc-1.85.0%2B-lightgrey.svg"/></a>
    <a href="https://discord.gg/6rJD9R684h"><img alt="Chat on Discord" src="https://img.shields.io/discord/753336465005608961?logo=discord"></a>
  </p>

  <h4>
    <a href="https://payjoindevkit.org">Project Homepage</a>
  </h4>
</div>

## About

`payjoin/rust-payjoin` contains multiple crates intended to assist the implementation of Payjoin functionality as defined in [BIP 78: Payjoin V1 (Synchronous)](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) and [BIP 77: Payjoin V2 (Asynchronous)](https://github.com/bitcoin/bips/blob/master/bip-0077.md), and the deployment of OHTTP relays and Payjoin directories which facilitate Async Payjoin transactions.

Find the description of each crate below.

### [`payjoin`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin)

The main Payjoin Dev Kit library which provides tools for implementing both Payjoin V2 (Asynchronous) and V1 (Synchronous). For Payjoin V2, the library also contains Payjoin session persistence support and IO utilities for interacting with OHTTP relays.

**Disclaimer: This crate has not been reviewed by independent Rust and Bitcoin security professionals (yet). Use at your own risk.**

### [`payjoin-cli`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-cli)

A CLI tool which performs no-frills Payjoin. It is a reference implementation of the Payjoin Dev Kit which uses a Bitcoin Core wallet.

### [`ohttp-relay`](https://github.com/payjoin/rust-payjoin/tree/master/ohttp-relay)

A Rust implementation of an Oblivious HTTP (OHTTP) relay resource.

**Disclaimer: Both this crate and the [IETF paper](https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html) are undergoing active revision. Use at your own risk.**

### [`payjoin-directory`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-directory)

A reference implementation for a Payjoin directory which stores and forwards HTTP client messages between the sender and the receiver to allow for asynchronous Payjoin transactions. Payjoin V2 clients encapsulate requests using [Oblivious HTTP (OHTTP)](https://www.ietf.org/rfc/rfc9458.html) which allows them to make payjoins without the directory being able to link payjoins to specific client IPs.

### [`payjoin-test-utils`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-test-utils)

The test utilities library which provides commonly used testing fixtures such as a local OHTTP relay and Payjoin directory, bitcoind node and wallets, and official test vectors.

### [`payjoin-ffi`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-ffi)

The language bindings which expose the Rust-based Payjoin implementation to various programming languages.

Currently supported languages:

- Dart
- Javascript
- Python

## About Payjoin

Payjoin is a Bitcoin transaction technique where multiple parties collaboratively build a transaction which contains inputs from more than one party. Unlike traditional Bitcoin transactions where the inputs are provided by a single entity (i.e. the sender), a Payjoin transaction contains inputs from both the sender and the receiver. This obfuscates both the amount being sent from one entity to another, and which input is owned by who. Moreover, by being able to add other inputs and outputs to what would be a traditional Bitcoin transaction, both parties can use a Payjoin transaction for batching payments and thus saving fee costs.

For more information, see [payjoin.org](https://payjoin.org).

## Minimum Supported Rust Version (MSRV)

All crates in this repository should always compile with any combination of features on Rust **1.85.0**.

## Contributing

See [`CONTRIBUTING.md`](.github/CONTRIBUTING.md).

## License

MIT

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

`payjoin/rust-payjoin` contains multiple crates implementing Payjoin as defined in [BIP 77: Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.mediawiki) and [BIP 78: Simple Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0078.md), and associated OHTTP Relay and Payjoin Directory infrastructure.

Find the description of each crate below.

### [`payjoin`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin)

The main Payjoin Dev Kit library which provides tools for implementing both Async and Simple Payjoin. `payjoin` implements Payjoin session persistence support and IO utilities for interacting with OHTTP relays in Async Payjoin integrations.

**Disclaimer: This crate has not been reviewed by independent Rust and Bitcoin security professionals (yet). Use at your own risk.**

### [`payjoin-cli`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-cli)

A CLI tool which performs no-frills Payjoin. It is a reference implementation of the Payjoin Dev Kit which uses a Bitcoin Core wallet.

### [`payjoin-mailroom`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-mailroom)

An [Oblivious HTTP (OHTTP) Relay](https://github.com/payjoin/rust-payjoin/tree/master/ohttp-relay) and a BIP77 [Payjoin Directory](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-directory) combined in one binary.

### [`payjoin-test-utils`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-test-utils)

The test utilities library which provides commonly used testing fixtures such as a local OHTTP relay and Payjoin directory, bitcoind node and wallets, and official test vectors.

### [`payjoin-ffi`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-ffi)

The language bindings which expose the Rust-based Payjoin implementation to [various programming languages](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-ffi#supported-target-languages-and-platforms).

## Minimum Supported Rust Version (MSRV)

All crates in this repository should always compile with any combination of features on Rust **1.85.0**.

## Contributing

See [`CONTRIBUTING.md`](.github/CONTRIBUTING.md).

## License

MIT

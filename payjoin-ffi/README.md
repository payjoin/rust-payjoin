# Payjoin Language Bindings

This repository creates Payjoin libraries for various programming languages, all using the Rust-based [Payjoin Dev Kit](https://github.com/payjoin/rust-payjoin) as the core implementation of BIP-77.

<!-- concept:begin (synced from payjoin-ffi/CONCEPT.md; edit there and run payjoin-ffi/contrib/sync-concept.sh) -->

Payjoin lets Bitcoin senders and receivers interact to make batched
transactions. The cooperating peers choose the inputs and outputs of the
transfer together, so the result looks like any other transaction — which
preserves privacy by poisoning the common-input-ownership heuristic that
chain surveillance depends on — and the receiver can batch its own
operations into the same transaction.

These bindings implement both
[BIP 78 Simple Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki)
and
[BIP 77 Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md),
in which sender and receiver exchange the transaction through an
untrusted directory and never need to be online at the same time.

Learn more at [payjoindevkit.org](https://payjoindevkit.org/).

<!-- concept:end -->

## Supported Target Languages and Platforms

Each supported language is in its own directory. The Rust code in this project is in the `src` directory and is a wrapper around the Payjoin Dev Kit to expose its APIs uniformly using [UniFFI](https://github.com/mozilla/uniffi-rs) for each supported target language.

The directories below include instructions for using, building, and publishing the native language bindings supported by this project.

| Language   | Platform              | Repository                           | Published Package                               |
| ---------- | --------------------- | ------------------------------------ | ----------------------------------------------- |
| Python     | linux, macOS          | [payjoin-ffi/python](python)         | [pypi](https://pypi.org/project/payjoin)        |
| Dart       | linux, macOS          | [payjoin-ffi/dart](dart)             | [pub.dev](https://pub.dev/packages/payjoin)     |
| JavaScript | linux, macOS          | [payjoin-ffi/javascript](javascript) | [npm](https://www.npmjs.com/package/payjoin)    |
| C#         | linux, macOS, windows | [payjoin-ffi/csharp](csharp)         | [nuget](https://www.nuget.org/packages/Payjoin) |
| Kotlin     | linux, macOS          | [payjoin-ffi/kotlin](kotlin)         | (not published)                                 |

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features with Rust 1.85.0.

## Release Status and Disclaimer

This project is in active development and currently in its Alpha stage. **Please proceed with caution**, particularly when using real funds.
We encourage thorough review, testing, and contributions to help improve its stability and security before considering production use.

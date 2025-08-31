# Payjoin Language Bindings

Welcome! This repository creates libraries for various programming languages, all using the Rust-based [Payjoin](https://github.com/payjoin/rust-payjoin) as the core implementation of BIP-77, sourced from the [Payjoin Dev Kit](https://payjoindevkit.org/).

Our mission is to provide developers with cross-language libraries that seamlessly integrate with different platform languages. By offering support for multiple languages, we aim to enhance the accessibility and usability of Payjoin, empowering developers to incorporate this privacy-enhancing feature into their applications, no matter their preferred programming language.

## Supported Target Languages and Platforms

Each supported language is in its own directory. The Rust code in this project is in the `src` directory and is a wrapper around the [Payjoin Dev Kit] to expose its APIs uniformly using the [mozilla/uniffi-rs] bindings generator for each supported target language.

The directories below include instructions for using, building, and publishing the native language bindings for [Payjoin Dev Kit] supported by this project.

| Language   | Platform     | Repository                           | Published Package                            |
| ---------- | ------------ | ------------------------------------ | -------------------------------------------- |
| Python     | linux, macOS | [payjoin-ffi/python](python)         | [payjoin](https://pypi.org/project/payjoin/) |
| Dart       | linux, macOS | [payjoin-ffi/dart](dart)             | N/A                                          |
| JavaScript | linux, macOS | [payjoin-ffi/javascript](javascript) | N/A                                          |

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features with Rust 1.85.0.

## References

[Payjoin Dev Kit](https://payjoindevkit.org/)

[mozilla/uniffi-rs](https://github.com/mozilla/uniffi-rs)

## Release Status and Disclaimer

This project is in active development and currently in its Alpha stage. **Please proceed with caution**, particularly when using real funds.
We encourage thorough review, testing, and contributions to help improve its stability and security before considering production use.

# Payjoin Language Bindings

Welcome! This repository creates libraries for various programming languages, all using the Rust-based [Payjoin](https://github.com/payjoin/rust-payjoin) as the core implementation of BIP178, sourced from the [Payjoin Dev Kit](https://payjoindevkit.org/).

Our mission is to provide developers with cross-language libraries that seamlessly integrate with different platform languages. By offering support for multiple languages, we aim to enhance the accessibility and usability of Payjoin, empowering developers to incorporate this privacy-enhancing feature into their applications, no matter their preferred programming language.

With a commitment to collaboration and interoperability, this repository strives to foster a more inclusive and diverse ecosystem around Payjoin and BIP178, contributing to the wider adoption of privacy-focused practices within the Bitcoin community. Join us in our mission to build a more private and secure future for Bitcoin transactions through Payjoin and BIP178!

**Current Status:**
This project is in the pre-alpha stage and currently in the design phase. The first language bindings available will be for Python, followed by Swift and Kotlin. Our ultimate goal is to provide Payjoin implementations for Android, iOS, Java, React, Python Native, Flutter, C#, and Golang.

## Supported Target Languages and Platforms

Each supported language and the platform(s) it's packaged for has its own directory. The Rust code in this project is in the `src` directory and is a wrapper around the [Payjoin Dev Kit] to expose its APIs uniformly using the [mozilla/uniffi-rs] bindings generator for each supported target language.

The directories below include instructions for using, building, and publishing the native language bindings for [Payjoin Dev Kit] supported by this project.

| Language | Platform              | Published Package | Building Documentation             | API Docs |
|----------|-----------------------|-------------------|------------------------------------|----------|
| Python   | linux, macOS, Windows | payjoin           | [Readme payjoin](python/README.md) |          |

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features with Rust 1.78.0.

## Using the Libraries

### Python

```shell
pip install payjoin

```
## Running the Integration Test


The integration tests illustrates and verify integration using bitcoin core and bdk.

```shell

# Run the integration test
cargo test  --package payjoin_ffi --test bdk_integration_test v2_to_v2_full_cycle --features _danger-local-https


```
## References

[Payjoin Dev Kit](https://payjoindevkit.org/)

[mozilla/uniffi-rs](https://github.com/mozilla/uniffi-rs)

## Release Status and Disclaimer

This project is in active development and currently in its Alpha stage. **Please proceed with caution**, particularly when using real funds.
We encourage thorough review, testing, and contributions to help improve its stability and security before considering production use.

# Payjoin Language Bindings

This repository creates Payjoin libraries for various programming languages, all using the Rust-based [Payjoin Dev Kit](https://github.com/payjoin/rust-payjoin) as the core implementation of BIP-77.

Our mission is to provide developers with cross-language libraries that seamlessly integrate with different platform languages. By offering support for multiple languages, we aim to enhance the accessibility and usability of Payjoin, empowering developers to incorporate it into their applications, no matter their preferred programming language.

## Supported Target Languages and Platforms

Each supported language is in its own directory. The Rust code in this project is in the `src` directory and is a wrapper around the Payjoin Dev Kit to expose its APIs uniformly using [UniFFI](https://github.com/mozilla/uniffi-rs) for each supported target language.

The directories below include instructions for using, building, and publishing the native language bindings supported by this project.

| Language   | Platform              | Repository                           | Published Package                               |
| ---------- | --------------------- | ------------------------------------ | ----------------------------------------------- |
| Python     | linux, macOS          | [payjoin-ffi/python](python)         | [pypi](https://pypi.org/project/payjoin)        |
| Dart       | linux, macOS          | [payjoin-ffi/dart](dart)             | [pub.dev](https://pub.dev/packages/payjoin)     |
| JavaScript | linux, macOS          | [payjoin-ffi/javascript](javascript) | [npm](https://www.npmjs.com/package/payjoin)    |
| C#         | linux, macOS, windows | [payjoin-ffi/csharp](csharp)         | [nuget](https://www.nuget.org/packages/Payjoin) |

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features with Rust 1.85.0.

## Release Status and Disclaimer

This project is in active development and currently in its Alpha stage. **Please proceed with caution**, particularly when using real funds.
We encourage thorough review, testing, and contributions to help improve its stability and security before considering production use.

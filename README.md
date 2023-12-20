# Payjoin language bindings

This repository creates libraries for various programming languages, all using the
Rust-based [Payjoin](https://github.com/payjoin/rust-payjoin) as the core implementation of [BIP-78](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki), sourced from
the [Payjoin Dev Kit].

The primary focus of this project is to provide developers with cross-language libraries that seamlessly integrate with
different platform languages. By offering support for multiple languages, we aim to enhance the accessibility and
usability of Payjoin, empowering developers to incorporate this privacy-enhancing feature into their applications
regardless of their preferred programming language.

With a commitment to collaboration and interoperability, this repository strives to foster a more inclusive and diverse
ecosystem around Payjoin and BIP-78, contributing to the wider adoption of privacy-focused practices within the Bitcoin
community. Join us in our mission to build a more private and secure future for Bitcoin transactions through Payjoin and
BIP-78!

**Current Status:**
This is a pre-alpha stage and is currently in the design phase. The first language bindings available will be for Python
followed by Swift and Kotlin. The ultimate goal is to have Payjoin implementations for Android, iOS, Java, React, Python
Native, Flutter, C# and Golang.

## Supported target languages and platforms

Each supported language and the platform(s) it's packaged for has its own directory. The Rust code in this project is in
the src directory and is a wrapper around the [Payjoin Dev Kit] to expose its APIs in a uniform way using
the [mozilla/uniffi-rs] bindings generator for each supported target language.

The below directories include instructions for using, building, and
publishing the native language binding for [Payjoin Dev Kit] supported by this project.

| Language | Platform              | Published Package | Building Documentation             | API Docs |
| -------- | --------------------- | ----------------- | ---------------------------------- | -------- |
| Python   | linux, macOS, Windows | payjoin           | [Readme payjoin](python/README.md) |          |

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features with Rust 1.73.0.

## Using the libraries

### python

```shell
pip install payjoin
```

## 🚨 Warning 🚨

The `main` branch of this repository is still under development and is incomplete.

[Payjoin Dev Kit]: https://payjoindevkit.org/

[mozilla/uniffi-rs]: https://github.com/mozilla/uniffi-rs

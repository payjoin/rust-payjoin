# payjoin-test-utils

A collection of testing utilities for Payjoin protocol implementations.

## Overview

The `payjoin-test-utils` crate provides commonly used testing fixtures for
Payjoin development and testing, including:

- Local OHTTP relay and Payjoin directory services
- Bitcoin Core node and wallet management
- Official test vectors
- HTTP client configuration for testing
- Tracing setup for debugging

## Features

- **Test Services**: Easily spin up and manage OHTTP relay and Payjoin Directory
  test services required for Payjoin testing
- **Bitcoin Core Integration**: Initialize and configure Bitcoin nodes for
  testing
- **Wallet Management**: Create and fund wallets for sender and receiver testing
- **OHTTP Relay**: Set up local OHTTP relay services
- **Directory Service**: Configure Payjoin directory services
- **Test Vectors**: Get access to official Payjoin test vectors

## Usage

For examples of using the TestServices, switch to the appropriate
`payjoin-test-utils` tag in
[rust-payjoin](https://github.com/payjoin/rust-payjoin) and view the e2e or
integration tests there.

## Minimum Supported Rust Version (MSRV)

This crate supports Rust 1.63.0 and above.

## License

MIT

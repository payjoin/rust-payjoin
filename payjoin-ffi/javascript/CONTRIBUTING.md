# Contributing

Instructions for building and testing the JavaScript bindings locally.

## Build Bindings

Follow these steps to clone the repository and run the tests.
This assumes you already have Rust and Node.js installed.

```shell
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin/payjoin-ffi/javascript

# Clean out stale dependencies
npm run clean
npm run clean:test-utils
rm -rf node_modules

# Install system dependencies
cargo install wasm-bindgen-cli
# (macOS only - secp256k1-sys requires a WASM-capable C compiler)
brew install llvm

# Install package dependencies
npm install

# Generate the bindings
bash ./scripts/generate_bindings.sh

```

## Running Tests

```shell
# Run all tests
npm test

```

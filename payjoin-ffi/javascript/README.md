# Payjoin JavaScript Bindings

Welcome to the JavaScript language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/)!

## Running Tests

Follow these steps to clone the repository and run the tests.
This assumes you already have Rust and Node.js installed.

```shell
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin/payjoin-ffi/javascript

# Install dependencies
cargo install wasm-bindgen-cli
npm install
# (macOS only - secp256k1-sys requires a WASM-capable C compiler)
brew install llvm

# Generate the bindings
bash ./scripts/generate_bindings.sh

# Run all tests
npm test
```

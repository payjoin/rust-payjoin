# Payjoin Dart Bindings

Welcome to the Dart language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/)!

## Running Tests

Follow these steps to clone the repository and run the tests.


```shell
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin/payjoin-ffi/dart

# Generate the bindings (use the script appropriate for your platform)
bash ./scripts/generate_<platform>.sh

# Run all tests
dart test
```

Note that you'll need Docker to run the integration tests. If you get a "Failed to start container" error, ensure the Docker engine is running on your machine.

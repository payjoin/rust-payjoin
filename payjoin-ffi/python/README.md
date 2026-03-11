# Payjoin Python Bindings

Welcome to the Python language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/)!

## Install from PyPI

Grab the latest release with a simple:

```shell
pip install payjoin

# Or, for uv:
uv add payjoin
```

## Development

### Using Nix (recommended)

If you have [nix](https://nixos.org/download/) installed, enter the Python dev
environment and run the test script:

```sh
nix develop .#python
cd payjoin-ffi/python
./contrib/test.sh
```

This provides `uv`, Python, Rust, and all other dependencies needed to generate
bindings, build the wheel, and run the tests.

### Without Nix

Ensure you have [uv](https://docs.astral.sh/uv/getting-started/installation/)
and Rust 1.85+ installed, then from `payjoin-ffi/python`:

```sh
./contrib/test.sh
```

## Building the Package

```shell
# Setup virtual environment/install packages for release
uv sync --all-extras

bash ./scripts/generate_bindings.sh

# Build the wheel
uv build --wheel

# Force reinstall payjoin with <version>
uv pip install ./dist/payjoin-*.whl --force-reinstall

# Example:
# uv pip install ./dist/payjoin-0.24.0-cp313-cp313-linux_x86_64.whl

# Run all tests
uv run python -m unittest --verbose
```

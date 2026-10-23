# Payjoin Python Bindings

Welcome to the Python language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/)!

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

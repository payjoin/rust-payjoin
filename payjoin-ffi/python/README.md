# Payjoin Python Bindings

Welcome to the Python language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/)!

## Install from PyPI

Grab the latest release with a simple:

```shell
uv add payjoin
```

## Running Tests

Follow these steps to clone the repository and run the tests.

```shell
# FIXME: ensure user has build-essential and python3-dev installed
# TODO: nix will take care of installing uv and running these commands, uv will do the rest

# Setup virtual environment/install all packages
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

Note that you'll need Docker to run the integration tests. If you get a "Failed to start container" error, ensure the Docker engine is running on your machine.
You can [filter which tests](https://docs.python.org/3/library/unittest.html#command-line-interface) to run by passing a file or test name as argument.

## Building the Package

```shell
# Setup virtual environment/install packages for release
uv sync

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

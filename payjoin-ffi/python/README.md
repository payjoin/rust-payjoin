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
# If on Linux, ensure the following are installed:
# build-essential python3-dev

# Setup virtual environment/install all packages (including developer packages)
uv sync --all-extras

bash ./scripts/generate_bindings.sh

# Build the wheel
uv build --wheel

# Force reinstall payjoin with <version>
uv pip install ./dist/payjoin-*.whl --force-reinstall

# Run all tests
uv run python -m unittest --verbose
```

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

# Payjoin Python Bindings

Welcome to the Python language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/)!

## Install from PyPI

Grab the latest release with a simple:

```shell
pip install payjoin
```

## Running Tests

Follow these steps to clone the repository and run the tests.


```shell
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin/payjoin-ffi/python

# Setup a python virtual environment
python -m venv venv
source venv/bin/activate

# Generate the bindings (use the script appropriate for your platform)
PYBIN="./venv/bin/" bash ./scripts/bindgen_generate.sh

# Build the wheel
python setup.py --verbose bdist_wheel

# Force reinstall payjoin
pip install ./dist/payjoin-<version>.whl --force-reinstall

# Run all tests
python -m unittest --verbose
```

Note that you'll need Docker to run the integration tests. If you get a "Failed to start container" error, ensure the Docker engine is running on your machine.
You can [filter which tests](https://docs.python.org/3/library/unittest.html#command-line-interface) to run by passing a file or test name as argument.

## Building the Package

```shell
# Setup a python virtual environment
python -m venv venv
source venv/bin/activate

# Generate the bindings (use the script appropriate for your platform)
PYBIN="./venv/bin/" bash ./scripts/bindgen_generate.sh

# Build the wheel
python setup.py --verbose bdist_wheel

```

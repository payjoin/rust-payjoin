# Payjoin Python Bindings

Welcome to the Python language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/)!

## Install from PyPI

To grab the latest release:

```sh
pip install payjoin
```

## Building the Package

If you have [nix](https://nixos.org/download/) installed, you can simply run:

```sh
nix develop .#python
```

This will get you up and running with a shell containing the dependencies you need.

Otherwise, follow these steps to clone the repository and build the package:

```sh
git clone https://github.com/payjoin/rust-payjoin.git
cd rust-payjoin/payjoin-ffi/python

# Setup a python virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
# NOTE: requirements-dev.txt only needed when running tests
pip install --requirement requirements.txt --requirement requirements-dev.txt

# Generate the bindings (use the script appropriate for your platform (linux or macos))
PYBIN="./venv/bin/" bash ./scripts/generate_<platform>.sh

# Build the wheel
python setup.py bdist_wheel --verbose

# Force reinstall payjoin
pip install ./dist/payjoin-<version>.whl --force-reinstall
```

If all goes well, you should be able to run the Python interpreter and import `payjoin`:

```sh
python
import payjoin
```

## Running Tests

```sh
# Run all tests
python -m unittest --verbose
```

Note that you'll need Docker to run the integration tests. If you get a "Failed to start container" error, ensure the Docker engine is running on your machine.
You can [filter which tests](https://docs.python.org/3/library/unittest.html#command-line-interface) to run by passing a file or test name as argument.

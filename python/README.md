# Payjoin

Welcome to the Python language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/)! Let's get you up and running with some smooth transactions and a sprinkle of fun.

## Install from PyPI

Grab the latest release with a simple:

```shell
pip install payjoin
```

## Running Unit Tests
Follow these steps to clone the repository and run the unit tests:

```shell

git clone https://github.com/LtbLightning/payjoin-ffi.git
cd python

# Setup a python virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install --requirement requirements.txt --requirement requirements-dev.txt

# Generate the bindings (use the script appropriate for your platform)
PYBIN="./venv/bin/" bash ./scripts/generate_<platform>.sh

# Build the wheel
python setup.py bdist_wheel --verbose

# Force reinstall payjoin
pip install ./dist/payjoin-<version>.whl --force-reinstall

# Run unit tests
python -m unittest --verbose test/payjoin_unit_test.py

```

## Running the Integration Test

Before diving into the integration test, you'll need to set up Bitcoin Core on the regtest network. If you don't have Bitcoin Core installed locally, check out [this installation guide](https://learn.saylor.org/mod/page/view.php?id=36347). Alternatively, you can use `Nigiri Bitcoin`, a tool designed to streamline the process of running local instances of Bitcoin and Liquid networks for development and testing. Follow the instructions [here](https://github.com/vulpemventures/nigiri) to install it on your machine.

Now, proceed with the integration test:

```shell

git clone https://github.com/LtbLightning/payjoin-ffi.git
cd python

# Setup a python virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install --requirement requirements.txt --requirement requirements-dev.txt

# Generate the bindings (use the script appropriate for your platform)
PYBIN="./venv/bin/" bash ./scripts/generate_<platform>.sh

# Build the wheel
python setup.py bdist_wheel --verbose

# Force reinstall payjoin
pip install ./dist/payjoin-<version>.whl --force-reinstall

# Run the integration test
python -m unittest --verbose test/payjoin_integration_test.py

```

## Building the Package

```shell
# Setup a python virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install --requirement requirements.txt

# Generate the bindings (use the script appropriate for your platform)
PYBIN="./venv/bin/" bash ./scripts/generate_<platform>.sh

# Build the wheel
python setup.py --verbose bdist_wheel

```
We hope everything worked smoothly! Now go forth test, and may your test results be as reliable as the Bitcoin blockchain itself!
₿🔒🤝

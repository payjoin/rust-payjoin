# Payjoin

The Python language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/).

## Install from PyPI

Install the latest release using

```shell
pip install payjoin
```

## Run the tests

```shell
# Install dependencies
pip install --requirement requirements.txt
pip install payjoin
pip install python-bitcoinlib

# Generate the bindings (use the script appropriate for your platform)
bash ./scripts/generate_macos.sh

# Build the wheel
python setup.py bdist_wheel --verbose

# Force reinstall payjoin
pip install ./dist/payjoin-<version>.whl --force-reinstall

#Run unit tests
python -m unittest --verbose test/payjoin_unit_test.py
```

## Build the package

```shell
# Install dependencies
pip install --requirement requirements.txt

# Generate the bindings (use the script appropriate for your platform)
bash ./scripts/generate_macos.sh

# Build the wheel
python setup.py --verbose bdist_wheel
```

## Install locally

```shell
pip install ./dist/payjoin-<version>.whl
```

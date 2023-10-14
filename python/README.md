# Payjoin

The Python language bindings for the  [Payjoin Dev Kit](https://payjoindevkit.org/).

## Install from PyPI

Install the latest release using

```shell
pip install payjoin
```

## Run the tests

```shell
pip install --requirement requirements.txt
pip install payjoin
bash scripts/generate-macos-arm64.sh # here you should run the script appropriate for your platform
python3 setup.py bdist_wheel --verbose
pip install ./dist/payjoin-<version>.whl --force-reinstall
python -m unittest --verbose tests/payjoin_test.py
```

## Build the package

```shell
# Install dependencies
pip install --requirement requirements.txt

# Generate the bindings (use the script appropriate for your platform)
bash ./scripts/generate-macos-arm64.sh

# Build the wheel
python setup.py --verbose bdist_wheel
```

## Install locally

```shell
pip install ./dist/payjoin-<version>.whl
```
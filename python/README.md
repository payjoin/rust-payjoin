# Payjoin

The Python language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/).

## Install from PyPI

Install the latest release using

```shell
pip install payjoin
```

## Run the unit tests

```shell

git clone https://github.com/XLTBLX-Tech/payjoin-ffi.git
cd python

# Install dependencies
pip install --requirement requirements.txt
pip install python-bitcoinlib

# Build the wheel
python setup.py bdist_wheel --verbose

# Force reinstall payjoin
pip install ./dist/payjoin-<version>.whl --force-reinstall

#Run unit tests
python -m unittest --verbose test/payjoin_unit_test.py
```

## Run the integration test

Before running the integration test, we need to set up the Bitcoin core properly in the regtest network. If you don't
have Bitcoin Core locally, please refer to this [page](https://learn.saylor.org/mod/page/view.php?id=36347). Or you can
install `Nigiri Bitcoin`, which is a tool designed to simplify the process of running local instances of Bitcoin and
Liquid networks for development and testing purposes. You can refer to
this [link](https://github.com/vulpemventures/nigiri), to install it on your local machine.

Once the nigiri bitcoin starts running, please replace following snippet in `payjoin_integration_test.py`, with you
nigiri bitcoin core credentials.

```
rpc_user = "bitcoin"
rpc_password = "bitcoin"
```

NB: The default credentials would be the following

```
rpc_user = "admin1"
rpc_password = "123"
rpc_host = "localhost"
rpc_port = "18443"
```

```shell

git clone https://github.com/XLTBLX-Tech/payjoin-ffi.git
cd python

# Install dependencies
pip install --requirement requirements.txt
pip install python-bitcoinlib

# Build the wheel
python setup.py bdist_wheel --verbose

# Force reinstall payjoin
pip install ./dist/payjoin-<version>.whl --force-reinstall

#Run the integration test
python -m unittest --verbose test/payjoin_integration_test.py
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
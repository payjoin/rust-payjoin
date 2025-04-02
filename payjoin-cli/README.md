# `payjoin-cli`

## A command-line payjoin client for [Bitcoin Core](https://github.com/bitcoin/bitcoin?tab=readme-ov-file) in Rust.

`payjoin-cli` is the reference implementation for the payjoin protocol, written using the [Payjoin Dev Kit](https://payjoindevkit.org).

It enables sending and receiving [BIP 78 Payjoin V1](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) and [Draft BIP Payjoin V2](https://github.com/bitcoin/bips/pull/1483) (also known as Async Payjoin) transactions via `bitcoind`. By default it supports Payjoin V1, and the `v2` feature sends and receives both since the protocol is backwards compatible.

While this code and design have had significant testing, it is still alpha-quality experimental software. Use at your own risk.

Independent audit is welcome.

## Quick Start

Here's a minimal payjoin example using `payjoin-cli` with the `v2` feature connected to `bitcoind` on [regtest](https://developer.bitcoin.org/examples/testing.html#regtest-mode). This example uses [`nigiri`](https://github.com/vulpemventures/nigiri) to setup a regtest environment. 

Payjoin `v2` allows for transactions to be completed asynchronously. Thus the sender and receiver do not need to be online at the same time to payjoin. To make this work, we need a payjoin directory server and OHTTP relay. Learn more about how `v2` works [here](https://payjoin.org/docs/how-it-works/payjoin-v2-bip-77).

To get started, install `nigiri`. Payjoin requires the sender and receiver each to have spendable [UTXOs](https://www.unchained.com/blog/what-is-a-utxo-bitcoin), so we'll create two wallets and fund each with spendable UTXOs.

```sh
cargo install nigiri

nigiri rpc createwallet "sender"
nigiri rpc createwallet "receiver"

# We need 101 blocks for the UTXOs to be spendable due to the coinbase maturity requirement.
nigiri rpc generatetoaddress $(nigiri rpc getnewaddress "sender") 101
nigiri rpc generatetoaddress $(nigiri rpc getnewaddress "receiver") 101
```

Great! Our wallets are setup, now let's do an async payjoin.

### Install `payjoin-cli`

```sh
cargo install payjoin-cli --version $VERSION --features v2
```

where `$VERSION` is the [latest version](https://crates.io/crates/payjoin-cli).

Next, create a directory for the sender & receiver and create a `config.toml` file for each:

```sh
mkdir sender receiver
touch sender/config.toml receiver/config.toml
```

Edit the `config.toml` files. Note that the `v2` feature requires a payjoin directory server and OHTTP relay. Learn more about them [here](https://payjoin.org/docs/how-it-works/payjoin-v2-bip-77).

```toml
# sender/config.toml

# Nigiri uses the following RPC credentials
bitcoind_rpcuser = "admin1"
bitcoind_rpcpassword = "123"
bitcoind_rpchost = "http://localhost:18443/wallet/sender"

# For v2, our config also requires a payjoin directory server and OHTTP relay
pj_directory = "https://payjo.in"
ohttp_relay = "https://pj.bobspacebkk.com"
```

```toml
# receiver/config.toml

# Nigiri uses the following RPC credentials
bitcoind_rpcuser = "admin1"
bitcoind_rpcpassword = "123"
bitcoind_rpchost = "http://localhost:18443/wallet/receiver"

# For v2, our config also requires a payjoin directory server and OHTTP relay
pj_directory = "https://payjo.in"
ohttp_relay = "https://pj.bobspacebkk.com"
```

Now, the receiver must generate an address to receive the payment:

```sh
receiver/payjoin-cli receive 10000
```

This will output a [BIP21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki) URL containing the receiver's address, amount, payjoin directory, and OHTTP relay. For example:

```sh
bitcoin:bcrt1qmdfqplpqy9jatyul6vtcvl26sp3u3vs89986w0?amount=0.0001&pj_directory=https://payjo.in&ohttp_relay=https://pj.bobspacebkk.com
```

Note that the session can be paused by pressing `Ctrl+C`. The receiver can come back online and resume the session by running `payjoin-cli resume` again, and the sender may do a `send` against it while the receiver is offline.

### Send a Payjoin

Now, let's send the payjoin:

```sh
sender/payjoin-cli send bitcoin:bcrt1qmdfqplpqy9jatyul6vtcvl26sp3u3vs89986w0?amount=0.0001&pj_directory=https://payjo.in&ohttp_relay=https://pj.bobspacebkk.com --fee-rate 10
```

Congratulations! You've completed a payjoin, and are on your way toward cheaper, more efficient, and more private payments. Additionally, because we're using `v2`, the sender and receiver don't need to be online at the same time to do the payjoin!

## Configuration

Config options can be passed from the command line, or manually edited in a `config.toml` file within the directory you run `payjoin-cli` from.

Configure it like so (example for regtest):

```toml
# config.toml

# Bitcoin Core RPC configuration
bitcoind_rpchost = "http://localhost:18443/wallet/sender"  # RPC endpoint with wallet name
bitcoind_rpcuser = "admin1"      # RPC username (if not using cookie auth)
bitcoind_rpcpassword = "123"     # RPC password (if not using cookie auth)

# Cookie authentication (alternative to username/password)
# Default locations (mainnet):
# Linux: ~/.bitcoin/.cookie
# MacOS: ~/Library/Application Support/Bitcoin/.cookie
# Windows: %APPDATA%\Bitcoin\.cookie
bitcoind_cookie = "~/.bitcoin/regtest/.cookie"  # Path to Bitcoin Core cookie file

# Default ports for bitcoind:
# Mainnet: 8332
# Testnet: 18332
# Signet: 38332
# Regtest: 18443

# Database configuration
db_path = "~/.local/share/payjoin/wallet.db"  # Custom path for the database

# Payjoin v2 configuration
pj_directory = "https://payjo.in"              # Payjoin directory server
ohttp_relay = "https://pj.bobspacebkk.com"     # OHTTP relay service
```

## Usage

Get a list of commands and options:

```sh
payjoin-cli --help
```

### CLI Reference

#### Commands

| Command  | Description |
|----------|-------------|
| `send`   | Send a payjoin transaction |
| `receive`| Receive a payjoin transaction |
| `help`   | Print this message or the help of the given subcommand(s) |

#### Options

| Option | Flag | Description |
|--------|------|-------------|
| `--rpchost` | `-r` | The port of the bitcoin node |
| `--cookie-file` | `-c` | Path to the cookie file of the bitcoin node |
| `--rpcuser` | | The username for the bitcoin node |
| `--rpcpassword` | | The password for the bitcoin node |
| `--db-path` | `-d` | Sets a custom database path |
| `--help` | `-h` | Print help information |
| `--version` | `-V` | Print version information |

Your configuration details will vary, but you may use this as a template.

#### Send Options

| Argument/Option | Description |
|----------------|-------------|
| `<BIP21>` | The `bitcoin:...` payjoin uri to send to |
| `--fee-rate <FEE_SAT_PER_VB>` | Fee rate in sat/vB |
| `-h, --help` | Print help information |

#### Receive Options

| Argument/Option | Description |
|----------------|-------------|
| `<AMOUNT>` | The amount to receive in satoshis |
| `-p, --port <port>` | The local port to listen on |
| `-e, --pj-endpoint <pj_endpoint>` | The `pj=` endpoint to receive the payjoin request |
| `-h, --help` | Print help information |

## Test Payjoin 2

### Install `payjoin-cli` with the V2 feature


### Asynchronous Operation

Send and receiver state is saved to a database in the directory from which `payjoin-cli` is run. Once a send or receive session is started, it may resume using the `resume` argument if prior payjoin sessions have not yet complete.



### Test Send

Create a "sender" directory within `payjoin-cli`. Open a new terminal window and navigate to this directory.

Note: A wallet cannot payjoin with itself, one needs separate wallets.

Create another `config.toml` file in the directory the sender will run from  and configure it as you did previously, except replace the receiver wallet name with the sender

Using the previously generated bip21 URI, run the following command
from the sender directory:

```sh
 RUST_LOG=debug cargo run --features=_danger-local-https -- send <BIP21> --fee-rate <FEE_SAT_PER_VB>
```

You should see the payjoin transaction occur and be able to verify the Partially Signed Bitcoin Transaction (PSBT), inputs, and Unspent Transaction Outputs (UTXOs).

Congrats, you've payjoined!

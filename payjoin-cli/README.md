# `payjoin-cli`

## A command-line payjoin client for [Bitcoin Core](https://github.com/bitcoin/bitcoin?tab=readme-ov-file) in Rust

`payjoin-cli` is the reference implementation for the payjoin protocol, written using the [Payjoin Dev Kit](https://payjoindevkit.org).

It enables sending and receiving [BIP 78 Payjoin
(v1)](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) and [Draft
BIP 77 Async Payjoin (v2)](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
transactions via `bitcoind`. By default it supports Payjoin v2, which is
backwards compatible with v1. Enable the `v1` feature to disable Payjoin v2 to
send and receive using only v1.

While this code and design have had significant testing, it is still alpha-quality experimental software. Use at your own risk.

Independent audit is welcome.

## Quick Start

Here's a minimal payjoin example using `payjoin-cli` with the `v2` feature connected to `bitcoind` on [regtest](https://developer.bitcoin.org/examples/testing.html#regtest-mode). This example uses [`nigiri`](https://github.com/vulpemventures/nigiri) to setup a regtest environment.

Payjoin `v2` allows for transactions to be completed asynchronously. Thus the sender and receiver do not need to be online at the same time to payjoin. Learn more about how `v2` works [here](https://payjoin.org/docs/how-it-works/payjoin-v2-bip-77).

To get started, install `nigiri` and [`docker`](https://www.docker.com/get-started). Payjoin requires the sender and receiver each to have spendable [UTXOs](https://www.unchained.com/blog/what-is-a-utxo-bitcoin), so we'll create two wallets and fund each.

```sh
# Download nigiri and check that installation has succeeded.
curl https://getnigiri.vulpem.com | bash
nigiri --version

# Create two regtest wallets.
nigiri rpc createwallet sender
nigiri rpc createwallet receiver

# We need 101 blocks for the UTXOs to be spendable due to the coinbase maturity requirement.
nigiri rpc generatetoaddress 101 $(nigiri rpc -rpcwallet=sender getnewaddress)
nigiri rpc generatetoaddress 101 $(nigiri rpc -rpcwallet=receiver getnewaddress)

# Check the balances before doing a Payjoin transaction.
nigiri rpc -rpcwallet=sender getbalance
nigiri rpc -rpcwallet=receiver getbalance
```

Great! Our wallets are setup. Now let's do an async payjoin.

### Install `payjoin-cli`

The following command will install the most recent version of payjoin-cli. See the crates.io page [here](https://crates.io/crates/payjoin-cli).

```sh
cargo install payjoin-cli
```

Optionally, you can install a specific version by setting the `--version` flag in the command.

Next, create a directory for the sender & receiver and create a file called `config.toml` for each. This file provides the information required for `payjoin-cli` to connect to your node and, for `v2`, to know which Payjoin Directory and OHTTP Relay to use.

When running commands, `payjoin-cli` will read the `config.toml` file which is in the current working directory.

```sh
mkdir sender receiver
touch sender/config.toml receiver/config.toml
```

Edit the `config.toml` files.

#### `sender/config.toml`
```toml
# Nigiri uses the following RPC credentials
[bitcoind]
rpcuser = "admin1"
rpcpassword = "123"
rpchost = "http://localhost:18443/wallet/sender"

# For v2, our config also requires a payjoin directory server and OHTTP relay
[v2]
pj_directory = "https://payjo.in"
ohttp_relays = ["https://pj.benalleng.com", "https://pj.bobspacebkk.com", "https://ohttp.achow101.com"]
```

#### `receiver/config.toml`
```toml
# Nigiri uses the following RPC credentials
[bitcoind]
rpcuser = "admin1"
rpcpassword = "123"
rpchost = "http://localhost:18443/wallet/receiver"

# For v2, our config also requires a payjoin directory server and OHTTP relay
[v2]
pj_directory = "https://payjo.in"
ohttp_relays = ["https://pj.benalleng.com", "https://pj.bobspacebkk.com", "https://ohttp.achow101.com"]
```

Now, the receiver must generate an address to receive the payment. The format is:

```sh
payjoin-cli receive <AMOUNT_SATS>
```

For example, to receive 10000 sats from our top-level directory:

```sh
receiver/payjoin-cli receive 10000
```

This will output a [bitcoin URI](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki) containing the receiver's address, amount, payjoin directory, and other session information the client needs. For example:

```sh
bitcoin:tb1qfttmt4z68cfyn2z25t3dusp03rq6gxrucfxs5a?amount=0.0001&pj=HTTPS://PAYJO.IN/EUQKYLU92GC6U%23RK1QFWVXS2LQ2VD4T6DUMQ0F4RZQ5NL9GM0EFWVHJZ9L796L20Z7SL3J+OH1QYP87E2AVMDKXDTU6R25WCPQ5ZUF02XHNPA65JMD8ZA2W4YRQN6UUWG+EX10T57UE
```

Note that the session can be paused by pressing `Ctrl+C`. The receiver can come back online and resume the session by running `payjoin-cli resume` again, and the sender may do a `send` against it while the receiver is offline.

### Send a Payjoin

Now, let's send the payjoin. Here is an example format:

```sh
payjoin-cli send <BIP21> --fee-rate <FEE_SAT_PER_VB>
```

Where `<BIP21>` is the BIP21 URL containing the receiver's address, amount, payjoin directory, and OHTTP relay. Using the example from above:

```sh
sender/payjoin-cli send "bitcoin:tb1qfttmt4z68cfyn2z25t3dusp03rq6gxrucfxs5a?amount=0.0001&pj=HTTPS://PAYJO.IN/EUQKYLU92GC6U%23RK1QFWVXS2LQ2VD4T6DUMQ0F4RZQ5NL9GM0EFWVHJZ9L796L20Z7SL3J+OH1QYP87E2AVMDKXDTU6R25WCPQ5ZUF02XHNPA65JMD8ZA2W4YRQN6UUWG+EX10T57UE" --fee-rate 1
```

Congratulations! You've completed a version 2 payjoin, which can be used for cheaper, more efficient, and more private on-chain payments. Additionally, because we're using `v2`, the sender and receiver don't need to be online at the same time to do the payjoin.

## Configuration

Config options can be passed from the command line, or manually edited in a `config.toml` file within the directory you run `payjoin-cli` from.

You can persist command-line flags into a configuration file. If a config file exists in the current working directory it will be used; otherwise, one in the default directory is used. This behavior is enabled via the `--set-config` flag.

See the
[example.config.toml](https://github.com/payjoin/rust-payjoin/blob/fde867b93ede767c9a50913432a73782a94ef40b/payjoin-cli/example.config.toml)
for inspiration.

### Asynchronous Operation

Sender and receiver state is saved to a database in the directory from which `payjoin-cli` is run, called `payjoin.sqlite`. Once a send or receive session is started, it may resume using the `resume` argument if prior payjoin sessions have not yet complete.

## Usage

Get a list of commands and options:

```sh
payjoin-cli --help
```

or with a subcommand e.g.

```sh
payjoin-cli send --help
```

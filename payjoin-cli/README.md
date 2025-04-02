# `payjoin-cli`

## A command-line payjoin client for [Bitcoin Core](https://github.com/bitcoin/bitcoin?tab=readme-ov-file) in Rust.

`payjoin-cli` is the reference implementation for the payjoin protocol, written using the [Payjoin Dev Kit](https://payjoindevkit.org).

It enables sending and receiving [BIP 78 Payjoin
(v1)](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) and [Draft
BIP 77 Async Payjoin (v2)](https://github.com/bitcoin/bips/pull/1483)
transactions via `bitcoind`. By default it supports Payjoin v2, which is
backwards compatible with v1. Enable the `v1` feature to disable Payjoin v2 to
send and receive using only v1.

While this code and design have had significant testing, it is still alpha-quality experimental software. Use at your own risk.

Independent audit is welcome.

## Quick Start

Here's a minimal payjoin example using `payjoin-cli` with the `v2` feature connected to `bitcoind` on [regtest](https://developer.bitcoin.org/examples/testing.html#regtest-mode). This example uses [`nigiri`](https://github.com/vulpemventures/nigiri) to setup a regtest environment. 

Payjoin `v2` allows for transactions to be completed asynchronously. Thus the sender and receiver do not need to be online at the same time to payjoin. To make this work, we need a payjoin directory server and OHTTP relay. Learn more about how `v2` works [here](https://payjoin.org/docs/how-it-works/payjoin-v2-bip-77).

To get started, install `nigiri`. Payjoin requires the sender and receiver each to have spendable [UTXOs](https://www.unchained.com/blog/what-is-a-utxo-bitcoin), so we'll create two wallets and fund each.

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
cargo install payjoin-cli --version $VERSION
```

where `$VERSION` is the [latest version](https://crates.io/crates/payjoin-cli).

Next, create a directory for the sender & receiver and create a `config.toml` file for each:

```sh
mkdir sender receiver
touch sender/config.toml receiver/config.toml
```

Edit the `config.toml` files. Note that the `v2` feature requires a payjoin directory server and OHTTP relay.

```toml
# sender/config.toml

# Nigiri uses the following RPC credentials
[bitcoind]
rpcuser = "admin1"
rpcpassword = "123"
rpchost = "http://localhost:18443/wallet/sender"

# For v2, our config also requires a payjoin directory server and OHTTP relay
[v2]
pj_directory = "https://payjo.in"
ohttp_relay = "https://pj.bobspacebkk.com"
```

```toml
# receiver/config.toml

# Nigiri uses the following RPC credentials
[bitcoind]
rpcuser = "admin1"
rpcpassword = "123"
rpchost = "http://localhost:18443/wallet/receiver"

# For v2, our config also requires a payjoin directory server and OHTTP relay
[v2]
pj_directory = "https://payjo.in"
ohttp_relay = "https://pj.bobspacebkk.com"
```

Now, the receiver must generate an address to receive the payment. The format is:

```sh
payjoin-cli receive <AMOUNT_SATS>
```

For example, to receive 10000 sats from our top-level directory:

```sh
receiver/payjoin-cli receive 10000
```

This will output a [BIP21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki) URL containing the receiver's address, amount, payjoin directory, and OHTTP relay. For example:

```sh
bitcoin:tb1qfttmt4z68cfyn2z25t3dusp03rq6gxrucfxs5a?amount=0.0001&pj=HTTPS://PAYJO.IN/EUQKYLU92GC6U%23RK1QFWVXS2LQ2VD4T6DUMQ0F4RZQ5NL9GM0EFWVHJZ9L796L20Z7SL3J+OH1QYP87E2AVMDKXDTU6R25WCPQ5ZUF02XHNPA65JMD8ZA2W4YRQN6UUWG+EX10T57UE```

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

see the
[example.config.toml](https://github.com/payjoin/rust-payjoin/blob/fde867b93ede767c9a50913432a73782a94ef40b/payjoin-cli/example.config.toml)
for inspiration.


### Asynchronous Operation

Sender and receiver state is saved to a database in the directory from which `payjoin-cli` is run, called `payjoin.sled`. Once a send or receive session is started, it may resume using the `resume` argument if prior payjoin sessions have not yet complete.

## Usage

Get a list of commands and options:

```sh
payjoin-cli --help
```

or with a subcommand e.g.

```sh
payjoin-cli send --help
```

# `payjoin-cli`

## A command-line payjoin client for [Bitcoin Core](https://github.com/bitcoin/bitcoin?tab=readme-ov-file) in Rust.

`payjoin-cli` is the reference implementation for the payjoin protocol, written using the [Payjoin Dev Kit](https://payjoindevkit.org).

It enables sending and receiving [BIP 78 Payjoin V1](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) and [Draft BIP Payjoin V2](https://github.com/bitcoin/bips/pull/1483) transactions via `bitcoind`. By default it supports Payjoin V1, and the `v2` feature sends and receives both since the protocol is backwards compatible.

While this code and design have had significant testing, it is still alpha-quality experimental software. Use at your own risk.

Independent audit is welcome.

## Quick Start

Here's a minimal example using `payjoin-cli` with the `v2` feature connected to `bitcoind` on [regtest](https://developer.bitcoin.org/examples/testing.html#regtest-mode). This example uses [`nigiri`](https://github.com/vulpemventures/nigiri) to setup a regtest environment.

First, install `nigiri`. Payjoin requires the sender and receiver each to have spendable [UTXOs](https://www.unchained.com/blog/what-is-a-utxo-bitcoin), so we'll create two wallets and fund them each.

```sh
cargo install nigiri

nigiri rpc createwallet "sender"
nigiri rpc createwallet "receiver"

# We need 101 blocks for the UTXOs to be spendable due to the coinbase maturity requirement.
nigiri rpc generatetoaddress $(nigiri rpc getnewaddress "sender") 101
nigiri rpc generatetoaddress $(nigiri rpc getnewaddress "receiver") 101
```

Great! Our wallets are setup, now let's do a payjoin.

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

```sh
sender/payjoin-cli send bitcoin:bcrt1qmdfqplpqy9jatyul6vtcvl26sp3u3vs89986w0?amount=0.0001&pj_directory=https://payjo.in&ohttp_relay=https://pj.bobspacebkk.com --fee-rate 10
```

Congratulations! You've completed a payjoin, and are on your way toward more efficient, private payments.

Get a list of commands and options:

```console
payjoin-cli --help
```

Either pass config options from cli, or manually edit a `config.toml` file within directory you run `payjoin-cli` from.
Configure it like so:

```toml
# config.toml
bitcoind_cookie = "/tmp/regtest1/bitcoind/regtest/.cookie"
# specify your wallet via rpchost connection string
bitcoind_rpchost = "http://localhost:18443/wallet/boom"
 ```

Your configuration details will vary, but you may use this as a template.

## Test Payjoin 2

### Install `payjoin-cli` with the V2 feature

```console
cargo install payjoin-cli --version $VERSION --features v2
```

### V2 Configuration

In addition to the rpc configuration above, specify relevant ohttp and payjoin directory configuration as follows:

```toml
# config.toml
...
# a production payjoin directory server
pj_directory="https://payjo.in"
# payjo.in's ohttp_keys can now be fetched rather than configured ahead of time
 # an ohttp relay with ingress to payjo.in
ohttp_relay="https://pj.bobspacebkk.com"
```

### Asynchronous Operation

Send and receiver state is saved to a database in the directory from which `payjoin-cli` is run. Once a send or receive session is started, it may resume using the `resume` argument if prior payjoin sessions have not yet complete.

```console
payjoin-cli resume
```

## Manual End to End Regtest Testing

### Test Receive

Set up 2 local regtest wallets and fund them. This example uses "boom" and "ocean"

Determine the RPC port specified in your bitcoind's `bitcoin.conf`
file. 18443 is the default. This can be set like so:

```conf
rpcport = 18443
```

From the directory you'll run `payjoin-cli`, assuming "boom" is the name of the receiving wallet, 18443 is the rpc port, and you wish to request 10,000 sats run:

```console
RUST_LOG=debug cargo run --features=_danger-local-https -- -r "http://localhost:18443/wallet/boom" receive 10000
```

The default configuration listens for payjoin requests at `http://localhost:3000` and expects you to relay https requests there.
Payjoin requires a secure endpoint, either https and .onion are valid. In order to receive payjoin in a local testing environment one may enable the  `_danger-local-https` feature which will provision a self-signed certificate and host the `https://localhost:3000` endpoint. Emphasis on HTTP**S**.

This will generate a payjoin capable bip21 URI with which to accept payjoin:

```console
BITCOIN:BCRT1QCJ4X75DUNY4X5NAWLM3CR8MALM9YAUYWWEWKWL?amount=0.00010&pj=https://localhost:3000
```

### Test Send

Create a "sender" directory within `payjoin-cli`. Open a new terminal window and navigate to this directory.

Note: A wallet cannot payjoin with itself, one needs separate wallets.

Create another `config.toml` file in the directory the sender will run from  and configure it as you did previously, except replace the receiver wallet name with the sender

Using the previously generated bip21 URI, run the following command
from the sender directory:

```console
 RUST_LOG=debug cargo run --features=_danger-local-https -- send <BIP21> --fee-rate <FEE_SAT_PER_VB>
```

You should see the payjoin transaction occur and be able to verify the Partially Signed Bitcoin Transaction (PSBT), inputs, and Unspent Transaction Outputs (UTXOs).

Congrats, you've payjoined!

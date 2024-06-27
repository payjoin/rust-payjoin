# payjoin-cli

## A command-line payjoin client for bitcoind in rust

The `payjoin-cli` client enables sending and receiving of [BIP 78 Payjoin V1](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) and [Draft BIP Payjoin V2](https://github.com/bitcoin/bips/pull/1483) transactions. By default it supports Payjoin V1, and the `v2` feature sends and receives both since the protocol is backwards compatible. The implementation is built on [Payjoin Dev Kit](https://payjoindevkit.org).

While this code and design has had significant testing, it is still alpha-quality experimental software. Use at your own risk.
Independent audit is welcome.

## Install payjoin-cli

```console
cargo install payjoin-cli --version $VERSION
```

where `$VERSION` is the latest version of the payjoin-cli you wish to install.

Get a list of commands and options:

```console
payjoin-cli --help
```

Either pass config options from cli, or manually edit a `config.toml` file within directory you run payjoin-cli from.
Configure it like so:

```toml
# config.toml
bitcoind_cookie = "/tmp/regtest1/bitcoind/regtest/.cookie"
# specify your wallet via rpchost connection string
bitcoind_rpchost = "http://localhost:18443/wallet/boom"
 ```

Your configuration details will vary, but you may use this as a template.

## Test Payjoin 2

### Install payjoin-cli with the V2 feature

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

Send and receiver state is saved to a database in the directory from which payjoin-cli is run. Once a send or receive session is started, it may resume using the `resume` argument if prior payjoin sessions have not yet complete.

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

From the directory you'll run payjoin-cli, assuming "boom" is the name of the receiving wallet, 18443 is the rpc port, and you wish to request 10,000 sats run:

```console
RUST_LOG=debug cargo run --features=danger-local-https -- -r "http://localhost:18443/wallet/boom" receive 10000
```

The default configuration listens for payjoin requests at `http://localhost:3000` and expects you to relay https requests there.
Payjoin requires a secure endpoint, either https and .onion are valid. In order to receive payjoin in a local testing environment one may enable the  `danger-local-https` feature which will provision a self-signed certificate and host the `https://localhost:3000` endpoint. Emphasis on HTTP**S**.

This will generate a payjoin capable bip21 URI with which to accept payjoin:

```console
BITCOIN:BCRT1QCJ4X75DUNY4X5NAWLM3CR8MALM9YAUYWWEWKWL?amount=0.00010&pj=https://localhost:3000
```

### Test Send

Create a "sender" directory within payjoin-cli. Open a new terminal window and navigate to this directory.

Note: A wallet cannot payjoin with itself, one needs separate wallets.

Create another `config.toml` file in the directory the sender will run from  and configure it as you did previously, except replace the receiver wallet name with the sender

Using the previously generated bip21 URI, run the following command
from the sender directory:

```console
 RUST_LOG=debug cargo run --features=danger-local-https -- send <BIP21> --fee-rate <FEE_SAT_PER_VB>
```

You should see the payjoin transaction occur and be able to verify the Partially Signed Bitcoin Transaction (PSBT), inputs, and Unspent Transaction Outputs (UTXOs).

Congrats, you've payjoined!

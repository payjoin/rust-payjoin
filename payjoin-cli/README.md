# payjoin-cli

## A command-line payjoin client for bitcoind in rust

### Install payjoin-cli

Get a list of commands and options:

```console
RUST_LOG=debug cargo run -- --help
```

 Manually create a `config.toml` file within the payjoin-cli directory
 and configure it like so:

```toml
 # config.toml
 bitcoind_cookie = "/tmp/regtest1/bitcoind/regtest/.cookie" 
 bitcoind_rpchost = "http://localhost:18443/wallet/boom"
 ```

Your configuration details will vary, but you may use this as a template.

### Receive Payjoin

 Set up 2 local regtest wallets and fund them. This example uses "boom" and "ocean"

Determine the RPC port specified in your bitcoind's `bitcoin.conf`
file. 18443 is the default. This can be set like so:

```conf
rpcport = 18443
```

From the `payjoin-cli directory, where "boom" is the receiving wallet, 18443 is the rpc port, and you wish to request 10,000 sats run:

```console
RUST_LOG=debug cargo run --features=danger-local-https -- -r "http://localhost:18443/wallet/boom" receive 10000
```

The default configuration listens for payjoin requests at `http://localhost:3000` and expects you to proxy https requests there.
Payjoin requires a secure endpoint, either https and .onion are valid. In order to receive payjoin in a local testing environment one may enable the  `danger-local-https` feature which will provision a self-signed certificate and host the `https://localhost:3000` endpoint. Emphasis on HTTP**S**.

This will generate a payjoin capable bip21 URI with which to accept payjoin:

```console
BITCOIN:BCRT1QCJ4X75DUNY4X5NAWLM3CR8MALM9YAUYWWEWKWL?amount=0.00010&pj=https://localhost:3000
```

### Send Payjoin

Create a "sender" directory within payjoin-cli. Open a new terminal window and navigate to this directory.
Note: A wallet cannot payjoin with itself, need separate wallets.
Create another config.toml file in this directory and configure it as you did
previously, except replace the receiver wallet name with the sender
wallet name ("ocean" for me).

Using the previously generated bip21 URI, run the following command
from the sender directory:

```console
 RUST_LOG=debug cargo run -- send <BIP21> --fee-rate <FEE_SAT_PER_VB>
```

You should see the payjoin transaction occur and be able to verify the
Partially Signed Bitcoin Transaction (PSBT), inputs, and Unspent
Transaction Outputs (UTXOs).

Congrats, you've payjoined!

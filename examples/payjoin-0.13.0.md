# Introduction

This tutorial goal is to get you started with payjoin and demonstrate
payjoin capabilities. We will demonstrate how to setup the sender side
in a payjoin transaction and transact with a payjoin receiver
utilising `payjoin-cli`.

While `rust-payjoin` supports both BiP0078 and BiP0077, this tutorial
is specificly to demonstrate BiP0078(payjoin version 1).

For a quick wallet setup, we utilise `docker` and `bitcoincore_rpc`
crate to run a regtest node and fund two wallets, one for the sender
and one for the receiver.

For any feedback, please free to reach out through the payjoin
official discord or github.

# 1. Bitcoin Node
 The following command will start a bitcoin core node in regtest mode,
 with auth setup already in place just for testing purposes.

 *You would need to have docker installed in order to run the
 following command*


 ```
 docker run --name bitcoin-server -d --rm -it \
 -p 18443:18443 \
 -p 18444:18444 \
 ruimarinho/bitcoin-core \
 -printtoconsole \
 -regtest=1 \
 -rpcallowip=0.0.0.0/0 \
 -rpcbind=0.0.0.0 \
 -rpcauth='foo:7d9ba5ae63c3d4dc30583ff4fe65a67e$9e3634e81c11659e3de036d0bf88f89cd169c1039e6e09607562d54765c649cc'
 ```


# 2. Project Setup

  Lets setup a new rust project and name it `payjoin-tutorial`
  ```shell
	cargo new payjoin-tutorial
  ```
  
  Add required dependecies to `cargo.toml` so it looks like the
  following:

  ```toml
  [dependencies]
  bitcoincore-rpc = "0.17.0" 
  ureq = { version = ">=2.8.0, <2.9" }
  rustls = { version = "0.21.9" }
  payjoin = { version = "0.13.0", features = ["send", "base64"]  }
  ```

# 3. Wallets

  We will setup basic bitcoin wallet utilising the bitcoin node we
  just started and the `bitcoincore_rpc` crate.

  Lets add the `setup_wallets` function to top of `main.rs`. Here, we
  create two funded wallets, one for the `sender` and the second for
  the `receiver` so we can test with `payjoin-cli`.

  ```rust
use bitcoincore_rpc::{Auth, RpcApi};

fn setup_wallets() {
    let client = bitcoincore_rpc::Client::new(
        "http://localhost:18443",
        Auth::UserPass(
            "foo".to_string(),
            "qDDZdeQ5vw9XXFeVnXT4PZ--tGN2xNjjR4nrtyszZx0=".to_string(),
        ),
    )
    .unwrap();
    let wallets = client.list_wallets().unwrap();
    dbg!(&wallets);
    if !wallets.contains(&"sender".to_string()) {
        dbg!(
            "creating sender
    wallet"
        );
        assert!(client
            .create_wallet("sender", None, None, None, None)
            .is_ok());
    }
    if !wallets.contains(&"receiver".to_string()) {
        dbg!("creating receiver wallet");
        assert!(client
            .create_wallet("receiver", None, None, None, None)
            .is_ok());
    }

    let sender_client = bitcoincore_rpc::Client::new(
        "http://localhost:18443/wallet/sender",
        Auth::UserPass(
            "foo".to_string(),
            "qDDZdeQ5vw9XXFeVnXT4PZ--tGN2xNjjR4nrtyszZx0=".to_string(),
        ),
    )
    .unwrap();
    let receiver_client = bitcoincore_rpc::Client::new(
        "http://localhost:18443/wallet/receiver",
        Auth::UserPass(
            "foo".to_string(),
            "qDDZdeQ5vw9XXFeVnXT4PZ--tGN2xNjjR4nrtyszZx0=".to_string(),
        ),
    )
    .unwrap();
    if sender_client.get_balances().unwrap().mine.trusted.to_btc() == 0 as f64 {
        assert!(sender_client
            .generate_to_address(
                101,
                &sender_client
                    .get_new_address(None, None)
                    .unwrap()
                    .assume_checked(),
            )
            .is_ok());
    }
    if receiver_client
        .get_balances()
        .unwrap()
        .mine
        .trusted
        .to_btc()
        == 0 as f64
    {
        assert!(receiver_client
            .generate_to_address(
                101,
                &receiver_client
                    .get_new_address(None, None)
                    .unwrap()
                    .assume_checked(),
            )
            .is_ok());
    }
    dbg!(
        "sender balance: {}",
        sender_client.get_balances().unwrap().mine.trusted.to_btc()
    );
    dbg!(
        "receiver balance: {}",
        receiver_client
            .get_balances()
            .unwrap()
            .mine
            .trusted
            .to_btc()
    );
}

fn main() {
    setup_wallets();
}
  ```

   And then:

   ```
   cargo run
   ```

   And you should see messages for creating the
   wallets and their balances.

   ```shell
   [src/main.rs:13] &wallets = [
       "sender",
       "receiver",
   ]
   [src/main.rs:75] "sender balance: {}" = "sender balance: {}"
   [src/main.rs:75]
   sender_client.get_balances().unwrap().mine.trusted.to_btc() =
   5050.0
   [src/main.rs:79] "receiver balance: {}" = "receiver
   balance: {}"
   [src/main.rs:79]
   receiver_client.get_balances().unwrap().mine.trusted.to_btc()
   = 50.0
   ```

# 4. Sender

  Payjoin sender have two responsibilties:

  1. Get receiver URI, construct an http request with PSBT in the
     body based on the URI, and send the request to the payjoin receiver.
  2. Wait for a response from the receiver to confirm the PSBT,
     finalize and broadcast it.

  The first point is where we for example scan a QR code, with BiP21
  URI encoded. If the BiP21 has `pj` param then its a valid URI for
  payjoin and we construct a PSBT based on the bitcoin address and
  amount(if set) from the URI. After building the request, we send it
  to the `pj` param value from the URI, which will be an https end
  point the receiver listening on for incoming requests.


  In the following code we add a `sender` struct and also an
  `https_agent` function. As you would guess, the `https_agent`
  function is used in order to send the https requests and get the
  response back whil the `sender` struct and implementation holds the
  functionality for a payjoin sender.

  In the code below, in the `main` function we also read `args` from
  the command line to consume the URI and utilise `payjoin::Uri::try_from`
  to convert the string to a valid URI.


  lets add the code to `main.rs` as well, just after the
  `setup_wallet` function:

  ```rust
// payjoin-tutorial/src/main.rs

use payjoin::bitcoin::address::NetworkChecked;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use bitcoincore_rpc::bitcoin::psbt::Psbt;
use bitcoincore_rpc::bitcoin::Txid;
use payjoin::base64;
use payjoin::send::RequestBuilder;
use rustls::client::ClientConfig;
use rustls::{Certificate, RootCertStore};
  
const LOCAL_CERT_FILE: &str = "localhost.der";

fn https_agent() -> ureq::Agent {
    use ureq::AgentBuilder;

    let mut local_cert_path = PathBuf::from("/tmp");
    local_cert_path.push(LOCAL_CERT_FILE);
    let cert_der = std::fs::read(local_cert_path).unwrap();
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add(&Certificate(cert_der)).unwrap();
    let client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    AgentBuilder::new()
        .tls_config(Arc::new(client_config))
        .build()
}

struct Sender;

impl Sender {
    pub fn try_payjoin(pj_uri: payjoin::Uri<'static, NetworkChecked>) -> Txid {
        let sender_wallet = bitcoincore_rpc::Client::new(
            "http://localhost:18443/wallet/sender",
            Auth::UserPass(
                "foo".to_string(),
                "qDDZdeQ5vw9XXFeVnXT4PZ--tGN2xNjjR4nrtyszZx0=".to_string(),
            ),
        )
        .unwrap();
        // Step 1. Extract the parameters from the payjoin URI
        let amount_to_send = pj_uri.amount.unwrap();
        let receiver_address = pj_uri.address.clone();

        // Step 2. Construct URI request parameters, a finalized "Original PSBT" paying `.amount` to `.address`
        let mut outputs = HashMap::with_capacity(1);
        outputs.insert(receiver_address.to_string(), amount_to_send);
        let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
            lock_unspent: Some(false),
            fee_rate: Some(bitcoincore_rpc::bitcoin::Amount::from_sat(10000)),
            ..Default::default()
        };
        let sender_psbt = sender_wallet
            .wallet_create_funded_psbt(
                &[], // inputs
                &outputs,
                None, // locktime
                Some(options),
                None,
            )
            .unwrap();
        let psbt = sender_wallet
            .wallet_process_psbt(&sender_psbt.psbt, None, None, None)
            .unwrap()
            .psbt;
        let psbt = Psbt::from_str(&psbt).unwrap();

        // Step 4. Construct the request with the PSBT and parameters
        let (req, ctx) = RequestBuilder::from_psbt_and_uri(psbt, pj_uri)
            .unwrap()
            .build_with_additional_fee(
                bitcoincore_rpc::bitcoin::Amount::from_sat(1),
                None,
                bitcoincore_rpc::bitcoin::FeeRate::MIN,
                true,
            )
            .unwrap()
            .extract_v1()
            .unwrap();
        // Step 5. Send the request and receive response
        // let payjoin_url = pj_uri.extras.e
        // BITCOIN:BCRT1Q0S724W239Z2XQGSZV6TE96HMYLEDCTX3GDFZEP?amount=0.01&pj=https://localhost:3000
        //
        let agent = https_agent();
        let res = agent
            .post(req.url.as_str()) // pj_uri.endpoint
            .set("Content-Type", "text/plain")
            .send_string(&String::from_utf8(req.body).unwrap())
            .unwrap();
        // Step 6. Process the response
        //
        // An `Ok` response should include a Payjoin Proposal PSBT.
        // Check that it's signed, following protocol, not trying to steal or otherwise error.
        let psbt = ctx
            .process_response(&mut res.into_string().unwrap().as_bytes())
            .unwrap();
        // Step 7. Sign and finalize the Payjoin Proposal PSBT
        //
        // Most software can handle adding the last signatures to a PSBT without issue.
        let psbt = sender_wallet
            .wallet_process_psbt(&base64::encode(psbt.serialize()), None, None, None)
            .unwrap()
            .psbt;
        let tx = sender_wallet
            .finalize_psbt(&psbt, Some(true))
            .unwrap()
            .hex
            .unwrap();
        // Step 8. Broadcast the Payjoin Transaction
        let txid = sender_wallet.send_raw_transaction(&tx).unwrap();
        txid
    }
}

fn main() {
    setup_wallets();
    let args: Vec<String> = std::env::args().collect();
    let payjoin_uri: String = args[1].parse().unwrap();
    let payjoin_uri = payjoin::Uri::try_from(payjoin_uri)
        .unwrap()
        .assume_checked();
    let txid = Sender::try_payjoin(payjoin_uri);
    dbg!(&txid);
}

  ```

# 5. Receiver
 To setup the receiver, we will use `payjoin-cli` a cli payjoin
 implementation developed by the `rust-payjoin` team. We will setup
 this receiver, generate BiP21 URI and go back to the `sender` we
 implemented and give it the URI.

 Open your terminal, and:

 1. Install `payjoin-cli`

 ```shell
 cargo install payjoin-cli --version 0.0.2-alpha --features local-danger-https
 ```

 2. Run `payjoin-cli` as the receiver

 *Here we assume that you completed all of the previous steps
 successfully and generated the `receiver` wallet*.

 ```rust
  payjoin-cli -r http://localhost:18443/wallet/reciever --rpcuser foo --rpcpass qDDZdeQ5vw9XXFeVnXT4PZ--tGN2xNjjR4nrtyszZx0= receive --endpoint https://localhost:3000 1230000000
 ```

 Once you run the the above command, an https server will start and a
 payjoin URI will be printed, and will look like this:

 ```shell
 bitcoin:bcrt1qstujjzput7eznwv27e7qh7lpkgz33fh39g2gpt?amount=12.3&pj=https://localhost:3000/&pjos=0
 ```

 Copy the payjoin uri as we will need it in the next(final) step.

# 6. Run

  Lets navigate back to the `payjoin-tutorial` folder and let the
  sender make a request to the payjoin uri generated by the receiver
  in the previous step.

  ```shell
  cargo run -- "bitcoin:bcrt1qstujjzput7eznwv27e7qh7lpkgz33fh39g2gpt?amount=12.3&pj=https://localhost:3000/&pjos=0"
  ```

# Conclusion

  We just demonstrated how to integrate `rust-payjoin` with a bitcoin
  wallet, using only the `sender` functionality. You could enable
  other features like `receiver` and `v2` to build more functionality.
  We also used the `payjoin-cli` to perform as a receiver, while we
  could also utilise it to be a sender.

  Thanks for following along.

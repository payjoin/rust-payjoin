# Introduction

This is a tutorial to get you started with payjoin. We will
demonstrate how you can setup both sender and receiver sides
in a payjoin transaction.

We do a simple bitcoin wallet setup with `bitcoincore_rpc`,
for that part, in production, you are expected to use
your own wallet implementation.

The tutorial demosntrates version 1 of payjoin as described
in BiP0078.

For any feedback, please free to reach out through the payjoin
official discord or github.
	
# 1. Project Setup

  First lets setup a new rust project and call it `payjoin-tutorial`
  ```shell
	cargo new payjoin-tutorial
  ```

  Now we should have a rust project with a src folder a `cargo.toml`
  file.
  
  
  Add required dependecies to `cargo.toml` so it looks like the
  following:

  ```toml
  [package]
  name = "tutorial"
  version = "0.1.0"
  edition = "2021"

  [workspace]

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

  [dependencies]
  axum = "0.7.2" # used by the receiver to create HTTP client server
  bitcoincore-rpc = "0.17.0" # used to communicate with bitcoin-core and create wallets
  http-body-util = "0.1.0"
  payjoin = { version = "0.13.0", features = ["send", "receive", "base64"] }
  tokio = {version = "1.35.1", features = ["rt", "macros", "rt-multi-thread"] }
  ureq = "2.9.1" # used by sender to make http requests
  ```

	
# 2. Wallets

  We will setup basic bitcoin wallet utilising bitcoin
  core.

  ```shell
  touch payjoin-tutorial/src/blockchain.rs
  ```

  Inside the file, we utilize `bitcoincore-rpc`
  in order to load `sender` and `receiver` bitcoin 
  wallets.

  ```rust
  // payjoin-tutorial/src/wallet.rs
pub struct Wallet;

impl Wallet {
    pub fn receiver() -> bitcoincore_rpc::Client {
        let path_buf = std::path::PathBuf::from("/home/ecode/.bitcoin/testnet3/.cookie");
        let receiver_wallet = bitcoincore_rpc::Client::new(
            "http://127.0.0.1:18332/wallet/receiver",
            bitcoincore_rpc::Auth::CookieFile(path_buf),
        )
        .unwrap();
        receiver_wallet
    }
    pub fn sender() -> bitcoincore_rpc::Client {
        let path_buf = std::path::PathBuf::from("/home/ecode/.bitcoin/testnet3/.cookie");
        let sender_wallet = bitcoincore_rpc::Client::new(
            "http://127.0.0.1:18332/wallet/sender",
            bitcoincore_rpc::Auth::CookieFile(path_buf.clone()),
        )
        .unwrap();
        sender_wallet
    }
}
  ```
# 3. HTTPS Server

  Payjoin receiver needs to setup an https server, listening for incoming payjoin requests.
  Here We utilise `axum` crate in order to setup a basic http server.

  ```shell
  touch payjoin-tutorial/src/http_server.rs
  ```

  ```rust
  // payjoin-tutorial/src/http_server.rs
  use axum::Router;

  pub struct HttpServer;

  impl HttpServer {
	  pub async fn new(port: u16, router: Router) {
		  let url = format!("0.0.0.0:{}", port);
		  let listener = tokio::net::TcpListener::bind(url).await.unwrap();
		  axum::serve(listener, router).await.unwrap();
	  }
  }
  ```

# Setup Receiver

  Payjoin receiver have two responsibilties:

  1. Start an http server and listen on a payjoin endpoint, as well
  as providing a `BiP(0021)` URI with payjoin paramters.

  2. Process incoming payjoin requests and return a response
     accordingly. When Processing an incoming payjoin request, we
     need to run some checks and validations that we will see comments
     about in the code

  Lets first create a new file for the `receiver` part.

  ```shell
  touch payjoin-tutorial/src/receiver.rs
  ```

  Let add the following imports to the top of the file:

  ```rust
	use axum::http::HeaderMap;
	use axum::response::IntoResponse;
	use axum::routing::post;
	use axum::{extract::Request, Router};
	use bitcoincore_rpc::{
	    bitcoin::{address::NetworkChecked, psbt::Psbt},
	    RpcApi,
	};
	use http_body_util::BodyExt;
	use std::{collections::HashMap, str::FromStr};

	use payjoin::bitcoin::{self, Amount};
	use payjoin::Uri;
	use payjoin::{
	    base64,
	    receive::{PayjoinProposal, ProvisionalProposal},
	};
  ```

  Next we will implement the `Payjoin::receive::Header` trait so we
  can consume the request headers

  ```rust
	struct Headers(HeaderMap);

	impl payjoin::receive::Headers for Headers {
	    fn get_header(&self, key: &str) -> Option<&str> {
		self.0.get(key).and_then(|v| v.to_str().ok())
	    }
	}

  ```

  Utilising `Payjoin::Uri` we can write a function to build BiP(0021)
  URI with payjoin paramters

  ```rust
	fn build_pj_uri(
	    address: bitcoin::Address,
	    amount: Amount,
	    pj: &'static str,
	) -> Uri<'static, NetworkChecked> {
	    let pj_uri_string = format!("{}?amount={}&pj={}", address.to_qr_uri(), amount.to_btc(), pj);
	    let pj_uri = Uri::from_str(&pj_uri_string).unwrap();
	    pj_uri.assume_checked()
	}

  ```

  And now lets write the main the code for the receiver part, you find
  comments in the code to help indetifying what each step is doing.
  ```rust
	// Payjoin receiver
	//
	// This is the code that receives a Payjoin request from a sender.
	//
	// The receiver flow is:
	// 1. Extracting request data
	// 2  Check if the Original PSBT can be broadcast
	// 3. Check if the sender is trying to make us sign our own inputs
	// 4. Check if there are mixed input scripts, breaking stenographic privacy
	// 5. Check if we have seen this input before
	// 6. Augment a valid proposal to preserve privacy
	// 7. Extract the payjoin PSBT and sign it
	// 8. Respond to the sender's http request with the signed PSBT as payload
	pub struct Receiver;

	impl Receiver {
	    pub async fn handle_pj_request(request: Request) -> impl IntoResponse {
		let receiver_wallet = Wallet::receiver();
		// Step 0: extract request data
		let (parts, body) = request.into_parts();
		let bytes = body.collect().await.unwrap().to_bytes();
		let headers = Headers(parts.headers.clone());
		let proposal =
		    payjoin::receive::UncheckedProposal::from_request(&bytes[..], "", headers).unwrap();
		let network = bitcoincore_rpc::bitcoin::Network::Testnet;

		let min_fee_rate = None;
		// Step 1: Can the Original PSBT be Broadcast?
		// We need to know this transaction is consensus-valid.
		let checked_1 = proposal
		    .check_broadcast_suitability(min_fee_rate, |tx| {
			let raw_tx = bitcoincore_rpc::bitcoin::consensus::encode::serialize_hex(&tx);
			let mempool_results = receiver_wallet.test_mempool_accept(&[raw_tx]).unwrap();
			match mempool_results.first() {
			    Some(result) => Ok(result.allowed),
			    None => panic!(""),
			}
		    })
		    .unwrap();
		// Step 2: Is the sender trying to make us sign our own inputs?
		let checked_2 = checked_1
		    .check_inputs_not_owned(|input| {
			if let Ok(address) = payjoin::bitcoin::Address::from_script(input, network) {
			    Ok(receiver_wallet
				.get_address_info(&address)
				.map(|info| info.is_mine.unwrap_or(false))
				.unwrap())
			} else {
			    Ok(false)
			}
		    })
		    .unwrap();
		// Step 3: Are there mixed input scripts, breaking stenographic privacy?
		let checked_3 = checked_2.check_no_mixed_input_scripts().unwrap();
		// Step 4: Have we seen this input before?
		//
		// Non-interactive i.e. payment processors should be careful to keep track
		// of request inputs or else a malicious sender may try and probe
		// multiple responses containing the receiver utxos, clustering their wallet.
		let checked_4 = checked_3.check_no_inputs_seen_before(|_outpoint| Ok(false)).unwrap();
		// Step 5. Augment a valid proposal to preserve privacy
		//
		// Here's where the PSBT is modified.
		// Inputs may be added to break common input ownership heurstic.
		// There are a number of ways to select coins and break common input heuristic but
		// fail to preserve privacy because of  Unnecessary Input Heuristic (UIH).
		// Until February 2023, even BTCPay occasionally made these errors.
		// Privacy preserving coin selection as implemented in `try_preserving_privacy`
		// is precarious to implement yourself may be the most sensitive and valuable part of this kit.
		//
		// Output substitution is another way to improve privacy and increase functionality.
		// For example, if the Original PSBT output address paying the receiver is coming from a static URI,
		// a new address may be generated on the fly to avoid address reuse.
		// This can even be done from a watch-only wallet.
		// Output substitution may also be used to consolidate incoming funds to a remote cold wallet,
		// break an output into smaller UTXOs to fulfill exchange orders, open lightning channels, and more.
		//
		//
		// Using methods for coin selection not provided by this library may have dire implications for privacy.
		// Significant in-depth research and careful implementation iteration has
		// gone into privacy preserving transaction construction.
		let mut prov_proposal = checked_4
		    .identify_receiver_outputs(|output_script| {
			if let Ok(address) = payjoin::bitcoin::Address::from_script(output_script, network)
			{
			    Ok(receiver_wallet
				.get_address_info(&address)
				.map(|info| info.is_mine.unwrap_or(false))
				.unwrap())
			} else {
			    Ok(false)
			}
		    })
		    .unwrap();
		let _ = Self::try_contributing_inputs(&mut prov_proposal);
		// Select receiver payjoin inputs.
		let receiver_substitute_address = receiver_wallet.get_new_address(None, None).unwrap();
		prov_proposal.substitute_output_address(receiver_substitute_address.assume_checked());
		// Step 6. Extract the payjoin PSBT and sign it
		//
		// Fees are applied to the augmented Payjoin Proposal PSBT using calculation factoring both receiver's
		// preferred feerate and the sender's fee-related [optional parameters]
		// (https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#optional-parameters).
		let payjoin_proposal: PayjoinProposal = prov_proposal
		    .finalize_proposal(
			|psbt: &Psbt| {
			    Ok(receiver_wallet
				.wallet_process_psbt(
				    &base64::encode(psbt.serialize()),
				    None,
				    None,
				    Some(false),
				)
				.map(|res| Psbt::from_str(&res.psbt).unwrap())
				.unwrap())
			},
			Some(payjoin::bitcoin::FeeRate::MIN),
		    )
		    .unwrap();
		// Step 7. Respond to the sender's http request with the signed PSBT as payload
		//
		// BIP 78 senders require specific PSBT validation constraints regulated by prepare_psbt.
		// PSBTv0 was not designed to support input/output modification,
		// so the protocol requires this precise preparation step. A future PSBTv2 payjoin protocol may not.
		//
		// It is critical to pay special care when returning error response messages.
		// Responding with internal errors can make a receiver vulnerable to sender probing attacks which cluster UTXOs.
		let payjoin_proposal_psbt = payjoin_proposal.psbt();
		payjoin_proposal_psbt.to_string()
	    }

	    pub fn accept_payjoin(
		port: u16,
		amount: bitcoincore_rpc::bitcoin::Amount,
	    ) -> Uri<'static, NetworkChecked> {
		let receiver_wallet = Wallet::receiver();
		tokio::task::spawn(async move {
		    let receive_router = Router::new().route("/payjoin", post(Receiver::handle_pj_request));
		    HttpServer::new(port, receive_router).await;
		});
		let payjoin_endpoint = "https://localhost:3227/payjoin";
		let pj_uri = build_pj_uri(
		    receiver_wallet.get_new_address(None, None).unwrap().assume_checked(),
		    amount,
		    payjoin_endpoint,
		);
		pj_uri
	    }

	    fn try_contributing_inputs(provisional_proposal: &mut ProvisionalProposal) -> Result<(), ()> {
		use payjoin::bitcoin::OutPoint;
		let receiver_wallet = Wallet::receiver();

		let available_inputs = receiver_wallet.list_unspent(None, None, None, None, None).unwrap();
		let candidate_inputs: HashMap<payjoin::bitcoin::Amount, OutPoint> = available_inputs
		    .iter()
		    .map(|i| (i.amount, OutPoint { txid: i.txid, vout: i.vout }))
		    .collect();

		let selected_outpoint =
		    provisional_proposal.try_preserving_privacy(candidate_inputs).unwrap();
		let selected_utxo = available_inputs
		    .iter()
		    .find(|i| i.txid == selected_outpoint.txid && i.vout == selected_outpoint.vout)
		    .unwrap();

		// calculate receiver payjoin outputs given receiver payjoin inputs and original_psbt
		let txo_to_contribute = payjoin::bitcoin::TxOut {
		    value: selected_utxo.amount.to_sat(),
		    script_pubkey: selected_utxo.script_pub_key.clone(),
		};
		let outpoint_to_contribute =
		    payjoin::bitcoin::OutPoint { txid: selected_utxo.txid, vout: selected_utxo.vout };
		provisional_proposal.contribute_witness_input(txo_to_contribute, outpoint_to_contribute);
		Ok(())
	    }
	}

  ```
# Setup Sender

  Payjoin sender have two responsibilties as well:
  1. Scan receivers URI, construct an http response with PSBT 
  in the body response, and send the response back to the receiver.
  2. Wait for a response from the receiver to confirm the PSBT and
  finalize and broadcast it.

  ```shell
  touch payjoin-tutorial/src/sender.rs
  ```

  ```rust
// payjoin-tutorial/src/sender.rs
use std::collections::HashMap;
use std::str::FromStr;

use bitcoincore_rpc::bitcoin::address::NetworkChecked;
use bitcoincore_rpc::bitcoin::psbt::Psbt;
use bitcoincore_rpc::bitcoin::Txid;
use bitcoincore_rpc::RpcApi;
use payjoin::base64;
use payjoin::send::RequestBuilder;

use crate::wallet::Wallet;

// Payjoin sender
//
// This is the code that sends a Payjoin request to a receiver.
//
// The sender flow is:
// 1. Extracting the parameters from the payjoin URI provided by the receiver
// 2. Constructing URI request parameters, a finalized "Original PSBT" paying `.amount` to `.address`
// 3. Constructing the request with the PSBT and parameters
// 4. Sending the request and receiving response
// 5. Processing the response
// 6. Signing and finalizing the Payjoin Proposal PSBT
// 7. Broadcasting the Payjoin Transaction
pub struct Sender;

impl Sender {
    pub fn send_request(pj_uri: payjoin::Uri<'static, NetworkChecked>) -> Psbt {
        let sender_wallet = Wallet::sender();
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
        let psbt =
            sender_wallet.wallet_process_psbt(&sender_psbt.psbt, None, None, None).unwrap().psbt;
        let psbt = Psbt::from_str(&psbt).unwrap();

        // Step 4. Construct the request with the PSBT and parameters
        let (req, ctx) = RequestBuilder::from_psbt_and_uri(psbt, pj_uri)
            .unwrap()
            .build_with_additional_fee(
                bitcoincore_rpc::bitcoin::Amount::from_sat(100),
                None,
                bitcoincore_rpc::bitcoin::FeeRate::ZERO,
                false,
            )
            .unwrap()
            .extract_v1()
            .unwrap();
        // Step 5. Send the request and receive response
        let res = ureq::post("http://localhost:3227/payjoin") // pj_uri.endpoint
            .set("content-type", "text/plain")
            .send_string(&String::from_utf8(req.body).unwrap())
            .unwrap();
        // Step 6. Process the response
        //
        // An `Ok` response should include a Payjoin Proposal PSBT.
        // Check that it's signed, following protocol, not trying to steal or otherwise error.
        let psbt = ctx.process_response(&mut res.into_string().unwrap().as_bytes()).unwrap();
        psbt
    }

    pub fn sign_and_broadcast(psbt: &Psbt) -> Txid {
        let sender_wallet = Wallet::sender();
        // Step 7. Sign and finalize the Payjoin Proposal PSBT
        //
        // Most software can handle adding the last signatures to a PSBT without issue.
        let psbt = sender_wallet
            .wallet_process_psbt(&base64::encode(psbt.serialize()), None, None, None)
            .unwrap()
            .psbt;
        let tx = sender_wallet.finalize_psbt(&psbt, Some(true)).unwrap().hex.unwrap();
        // Step 8. Broadcast the Payjoin Transaction
        let txid = sender_wallet.send_raw_transaction(&tx).unwrap();
        txid
    }
}
  ```
# Run Payjoin

  Lets call the functions we implemented from our `main.rs` file:

  ```rust
  // payjoin-tutorial/src/main.rs
use bitcoincore_rpc::bitcoin::psbt::Psbt;
use bitcoincore_rpc::bitcoin::Txid;
use receive::Receiver;
use send::Sender;

mod http_server;
mod receive;
mod send;
mod wallet;

#[tokio::main]
async fn main() {
    let receiver_listening_port = 3227;
    let receiver_amount = bitcoincore_rpc::bitcoin::Amount::from_sat(10000);
    let pj_uri = Receiver::accept_payjoin(receiver_listening_port, receiver_amount);
    let response: Psbt = Sender::send_request(pj_uri);
    let response: Txid = Sender::sign_and_broadcast(&response);
    dbg!(&response);
}
  ```

  ```shell
  cargo run
  ```

# Conclusion


  Lorem Ipsum Lorem Ipsum Lorem Ipsum
  Lorem Ipsum Lorem Ipsum Lorem Ipsum
  Lorem Ipsum Lorem Ipsum Lorem Ipsum
  Lorem Ipsum Lorem Ipsum Lorem Ipsum

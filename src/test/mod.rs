use bitcoin::psbt::Psbt;
use bitcoind::bitcoincore_rpc;
use bitcoind::bitcoincore_rpc::core_rpc_json::AddressType;
use bitcoind::bitcoincore_rpc::RpcApi;
use log::{debug, log_enabled, Level};
use payjoin::bitcoin;
use payjoin::bitcoin::base64;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use crate::receive::{Headers, IsOutoutKnown, IsScriptOwned, UncheckedProposal};
use crate::send::{Configuration, Request};
use crate::transaction::PartiallySignedTransaction;
use crate::uri::Uri;
use crate::{Network, ScriptBuf};

#[test]
fn integration_test() {
	let _ = env_logger::try_init();
	let bitcoind_exe = std::env::var("BITCOIND_EXE")
		.ok()
		.or_else(|| bitcoind::downloaded_exe_path().ok())
		.expect("version feature or env BITCOIND_EXE is required for tests");
	let mut conf = bitcoind::Conf::default();
	conf.view_stdout = log_enabled!(Level::Debug);
	let bitcoind = bitcoind::BitcoinD::with_conf(bitcoind_exe, &conf).unwrap();
	let receiver = bitcoind.create_wallet("receiver").unwrap();
	let receiver_address =
		receiver.get_new_address(None, Some(AddressType::Bech32)).unwrap().assume_checked();
	let sender = bitcoind.create_wallet("sender").unwrap();
	let sender_address =
		sender.get_new_address(None, Some(AddressType::Bech32)).unwrap().assume_checked();
	bitcoind.client.generate_to_address(1, &receiver_address).unwrap();
	bitcoind.client.generate_to_address(101, &sender_address).unwrap();

	assert_eq!(
		payjoin::bitcoin::Amount::from_btc(50.0).unwrap(),
		receiver.get_balances().unwrap().mine.trusted,
		"receiver doesn't own bitcoin"
	);

	assert_eq!(
		payjoin::bitcoin::Amount::from_btc(50.0).unwrap(),
		sender.get_balances().unwrap().mine.trusted,
		"sender doesn't own bitcoin"
	);

	// Receiver creates the payjoin URI
	let pj_receiver_address = receiver.get_new_address(None, None).unwrap().assume_checked();
	let amount = payjoin::bitcoin::Amount::from_btc(1.0).unwrap();
	let pj_uri_string = format!(
		"{}?amount={}&pj=https://example.com",
		pj_receiver_address.to_qr_uri(),
		amount.to_btc()
	);
	let _uri = Uri::new(pj_uri_string).unwrap();
	let pj_uri = _uri.check_pj_supported().expect("Bad Uri");
	// Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
	let mut outputs = HashMap::with_capacity(1);
	outputs.insert(pj_uri.address().clone().to_string(), pj_uri.amount().clone().unwrap());
	debug!("outputs: {:?}", outputs);
	let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
		lock_unspent: Some(true),
		fee_rate: Some(payjoin::bitcoin::Amount::from_sat(2000)),
		..Default::default()
	};
	let psbt = sender
		.wallet_create_funded_psbt(
			&[], // inputs
			&outputs,
			None, // locktime
			Some(options),
			None,
		)
		.expect("failed to create PSBT")
		.psbt;
	let psbt = sender.wallet_process_psbt(&psbt, None, None, None).unwrap().psbt;
	let psbt = PartiallySignedTransaction::new(psbt).expect("Psbt new");
	debug!("Original psbt: {:#?}", psbt);
	let pj_params = Configuration::with_fee_contribution(10000, None);
	let (req, ctx) = pj_uri.create_pj_request(psbt, pj_params).unwrap();
	let headers = Headers::from_vec(req.body.clone());

	// **********************
	// Inside the Receiver:
	// this data would transit from one party to another over the network in production
	let rec_clone = Arc::new(receiver);
	let response = handle_pj_request(req, headers, rec_clone.clone());
	// this response would be returned as http response to the sender

	// **********************
	// Inside the Sender:
	// Sender checks, signs, finalizes, extracts, and broadcasts
	let checked_payjoin_proposal_psbt = ctx.process_response(&mut response.as_bytes()).unwrap();
	let payjoin_base64_string = base64::encode(&checked_payjoin_proposal_psbt.serialize());
	let payjoin_psbt =
		sender.wallet_process_psbt(&payjoin_base64_string, None, None, None).unwrap().psbt;
	let payjoin_psbt = sender.finalize_psbt(&payjoin_psbt, Some(false)).unwrap().psbt.unwrap();
	let payjoin_psbt = Psbt::from_str(&payjoin_psbt).unwrap();
	debug!("Sender's Payjoin PSBT: {:#?}", payjoin_psbt);

	let payjoin_tx = payjoin_psbt.extract_tx();
	bitcoind.client.send_raw_transaction(&payjoin_tx).unwrap();
}

// Receiver receive and process original_psbt from a sender
// In production it it will come in as an HTTP request (over ssl or onion)
fn handle_pj_request(
	req: Request, headers: Headers, receiver: Arc<bitcoincore_rpc::Client>,
) -> String {
	// Receiver receive payjoin proposal, IRL it will be an HTTP request (over ssl or onion)
	let proposal = UncheckedProposal::from_request(
		req.body.as_slice(),
		req.url.internal.query().unwrap_or("").to_string(),
		headers,
	)
	.unwrap();

	// in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
	let _to_broadcast_in_failure_case = proposal.get_transaction_to_schedule_broadcast();

	let proposal = proposal
		.check_can_broadcast(Box::new(TestBroadcast(receiver.clone())))
		.expect("Payjoin proposal should be broadcastable");

	// Receive Check 2: receiver can't sign for proposal inputs
	let proposal = proposal
		.check_inputs_not_owned(MockScriptOwned(receiver.clone()))
		.expect("Receiver should not own any of the inputs");

	// Receive Check 3: receiver can't sign for proposal inputs
	let proposal = proposal.check_no_mixed_input_scripts().unwrap();

	// Receive Check 4: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
	let payjoin = Arc::new(
		proposal
			.check_no_inputs_seen_before(MockOutputOwned {})
			.unwrap()
			.identify_receiver_outputs(MockScriptOwned(receiver.clone()))
			.expect("Receiver should have at least one output"),
	);
	print!("payjoin:  {}", payjoin.is_output_substitution_disabled());
	// Select receiver payjoin inputs. TODO Lock them.
	let available_inputs = receiver.list_unspent(None, None, None, None, None).unwrap();
	let candidate_inputs: HashMap<u64, crate::OutPoint> = available_inputs
		.iter()
		.map(|i| (i.amount.to_sat(), crate::OutPoint { txid: i.txid.to_string(), vout: i.vout }))
		.collect();

	let selected_outpoint = payjoin.try_preserving_privacy(candidate_inputs).expect("gg");
	let selected_utxo = available_inputs
		.iter()
		.find(|i| {
			i.txid.to_string() == selected_outpoint.txid.to_string()
				&& i.vout == selected_outpoint.vout
		})
		.unwrap();

	//  calculate receiver payjoin outputs given receiver payjoin inputs and original_psbt,
	let txo_to_contribute = crate::TxOut {
		value: selected_utxo.amount.to_sat(),
		script_pubkey: ScriptBuf { internal: selected_utxo.script_pub_key.clone() },
	};
	let outpoint_to_contribute =
		crate::OutPoint { txid: selected_utxo.txid.to_string(), vout: selected_utxo.vout };
	payjoin.contribute_witness_input(txo_to_contribute, outpoint_to_contribute);

	let receiver_substitute_address =
		receiver.get_new_address(None, None).unwrap().assume_checked();
	payjoin.substitute_output_address(
		crate::Address::new(receiver_substitute_address.to_string().as_str().to_owned())
			.expect("Invalid address"),
	);

	let payjoin_proposal_psbt = payjoin.apply_fee(None).expect("Aplly fee");

	// Sign payjoin psbt
	let payjoin_base64_string = base64::encode(&payjoin_proposal_psbt.serialize());
	let payjoin_proposal_psbt =
		receiver.wallet_process_psbt(&payjoin_base64_string, None, None, Some(false)).unwrap().psbt;
	let payjoin_proposal_psbt =
		PartiallySignedTransaction::new(payjoin_proposal_psbt).expect("Invalid psbt");

	let payjoin_proposal_psbt = payjoin.prepare_psbt(payjoin_proposal_psbt).expect("Prepare psbt");
	debug!("Receiver's Payjoin proposal PSBT: {:#?}", payjoin_proposal_psbt);

	base64::encode(&payjoin_proposal_psbt.serialize())
}

struct TestBroadcast(Arc<bitcoincore_rpc::Client>);
impl crate::receive::CanBroadcast for TestBroadcast {
	fn test_mempool_accept(&self, tx_hex: Vec<String>) -> Result<bool, ::anyhow::Error> {
		match self.0.test_mempool_accept(&tx_hex) {
			Ok(e) => Ok(match e.first() {
				Some(e) => e.allowed,
				None => anyhow::bail!("No Mempool Result"),
			}),
			Err(e) => anyhow::bail!(e),
		}
	}
}
struct MockScriptOwned(Arc<bitcoincore_rpc::Client>);
struct MockOutputOwned {}
impl IsOutoutKnown for MockOutputOwned {
	fn is_known(&self, _: crate::OutPoint) -> Result<bool, anyhow::Error> {
		Ok(false)
	}
}
impl IsScriptOwned for MockScriptOwned {
	fn is_owned(&self, script: ScriptBuf) -> Result<bool, anyhow::Error> {
		{
			let network = Network::Regtest;

			let address = crate::Address::from_script(script, network.clone()).unwrap();
			let addr: bitcoin::Address = address.into();
			Ok(self.0.get_address_info(&addr).unwrap().is_mine.unwrap())
		}
	}
}

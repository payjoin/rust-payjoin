use std::collections::HashMap;

use std::sync::Arc;

use crate::error::PayjoinError;
use crate::receive::{
	Headers, IsOutputKnown, IsScriptOwned, ProcessPartiallySignedTransaction, UncheckedProposal,
};
use crate::send::{Configuration, Request};
use crate::transaction::PartiallySignedTransaction;
use crate::uri::{Amount, Uri};
use crate::{FeeRate, Network, ScriptBuf};
use bitcoincore_rpc::bitcoincore_rpc_json::{AddressType, WalletProcessPsbtResult};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use log::debug;

fn get_client(wallet_name: &str) -> Client {
	let url = format!("{}{}{}", "http://localhost:18443", "/wallet/", wallet_name);
	Client::new(&*url, Auth::UserPass("bitcoin".to_string(), "bitcoin".to_string())).unwrap()
}

#[test]
fn integration_test() {
	let receiver = get_client("receiver");
	let receiver_address = receiver.get_new_address(None, None).unwrap().assume_checked();

	let sender = get_client("sender");
	let sender_address = receiver.get_new_address(None, None).unwrap().assume_checked();

	receiver.generate_to_address(1, &receiver_address).unwrap();
	sender.generate_to_address(101, &sender_address).unwrap();

	// Receiver creates the payjoin URI
	let pj_receiver_address =
		receiver.get_raw_change_address(Some(AddressType::Bech32)).unwrap().assume_checked();
	let amount = Amount::from_btc(1.0);
	let pj_uri_string = format!(
		"{}?amount={}&pj=https://example.com",
		pj_receiver_address.to_qr_uri(),
		amount.to_btc()
	);
	let pj_uri = Uri::new(pj_uri_string).unwrap();
	let pj_uri = pj_uri.check_pj_supported().expect("Bad Uri");

	// Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
	let mut outputs = HashMap::with_capacity(1);
	outputs.insert(pj_uri.address().as_string(), (*pj_uri.amount().unwrap()).clone().into());
	eprintln!("outputs: {:?}", outputs);
	let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
		lock_unspent: Some(true),
		fee_rate: Some(Amount::from_sat(2000).into()),
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
	let psbt_base64 = sender.wallet_process_psbt(&psbt, None, None, None).unwrap().psbt;
	let psbt = PartiallySignedTransaction::from_string(psbt_base64).expect("Invalid psbt_base64");
	eprintln!("Original psbt: {:#?}", psbt.as_string());
	let pj_params = Configuration::with_fee_contribution(10000, None);
	let prj_uri_req = pj_uri.create_pj_request(Arc::new(psbt), pj_params.into()).unwrap();
	let req = prj_uri_req.request;
	let ctx = prj_uri_req.context;
	let headers = Headers::from_vec(req.body.clone());

	// **********************
	// Inside the Receiver:
	// this data would transit from one party to another over the network in production
	let response = handle_pj_request(req, headers, Arc::new(receiver));
	// this response would be returned as http response to the sender

	// **********************
	// Inside the Sender:
	// Sender checks, signs, finalizes, extracts, and broadcasts
	let checked_payjoin_proposal_psbt = (*ctx).process_response(response).unwrap();
	let payjoin_psbt = sender
		.wallet_process_psbt(&checked_payjoin_proposal_psbt.as_string(), None, None, None)
		.unwrap()
		.psbt;
	let payjoin_psbt = sender.finalize_psbt(&payjoin_psbt, Some(false)).unwrap().psbt.unwrap();

	let payjoin_psbt = PartiallySignedTransaction::from_string(payjoin_psbt).unwrap();
	eprintln!("Sender's Payjoin PSBT: {:#?}\n", payjoin_psbt.as_string());
	let tx = payjoin_psbt.extract_tx();
	let payjoin_tx: payjoin::bitcoin::Transaction =
		(crate::Transaction::new(tx.serialize()).expect("Invalid payjoin_psbt tx")).clone().into();
	let txid = sender.send_raw_transaction(&payjoin_tx).unwrap();
	eprintln!("Broadcast txid: {:?}", txid)
}

// Receiver receive and process original_psbt from a sender
// In production it will come in as an HTTP request (over ssl or onion)
fn handle_pj_request(
	req: Request, headers: Headers, receiver: Arc<bitcoincore_rpc::Client>,
) -> String {
	// Receiver receive payjoin proposal, IRL it will be an HTTP request (over ssl or onion)
	let proposal = UncheckedProposal::from_request(
		req.body.clone(),
		req.url.query().unwrap_or("".to_string()),
		Arc::new(headers),
	)
	.unwrap();

	// in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
	let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();
	let inputs_owned = proposal
		.check_can_broadcast(Box::new(TestBroadcast(receiver.clone())))
		.expect("Payjoin proposal should be broadcast");

	// Receive Check 2: receiver can't sign for proposal inputs
	let proposal = inputs_owned
		.check_inputs_not_owned(Box::new(MockScriptOwned(receiver.clone())))
		.expect("Receiver should not own any of the inputs");

	// Receive Check 3: receiver can't sign for proposal inputs
	let proposal = proposal.check_no_mixed_input_scripts().unwrap();

	// Receive Check 4: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
	let payjoin = Arc::new(
		proposal
			.check_no_inputs_seen_before(Box::new(MockOutputOwned {}))
			.unwrap()
			.identify_receiver_outputs(Box::new(MockScriptOwned(receiver.clone())))
			.expect("Receiver should have at least one output"),
	);

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
		script_pubkey: Arc::new(ScriptBuf { internal: selected_utxo.script_pub_key.clone() }),
	};
	let outpoint_to_contribute =
		crate::OutPoint { txid: selected_utxo.txid.to_string(), vout: selected_utxo.vout };
	payjoin.contribute_witness_input(txo_to_contribute, outpoint_to_contribute);

	let receiver_substitute_address =
		receiver.get_new_address(None, None).unwrap().assume_checked();
	payjoin.substitute_output_address(Arc::new(receiver_substitute_address.into()));
	let payjoin_proposal = payjoin
		.finalize_proposal(
			Box::new(MockProcessPartiallySignedTransaction { 0: receiver }),
			Some(Arc::new(FeeRate::min())),
		)
		.unwrap();
	let psbt = payjoin_proposal.psbt();
	println!("\n Receiver psbt: {}", psbt.as_string());
	psbt.as_string()
}

struct TestBroadcast(Arc<bitcoincore_rpc::Client>);

impl crate::receive::CanBroadcast for TestBroadcast {
	fn test_mempool_accept(&self, tx: Vec<u8>) -> Result<bool, PayjoinError> {
		debug!("{:?}", tx);
		Ok(true)
	}
}

struct MockScriptOwned(Arc<bitcoincore_rpc::Client>);

struct MockOutputOwned {}

struct MockProcessPartiallySignedTransaction(Arc<bitcoincore_rpc::Client>);

impl ProcessPartiallySignedTransaction for MockProcessPartiallySignedTransaction {
	fn process_psbt(&self, psbt: Arc<PartiallySignedTransaction>) -> Result<String, PayjoinError> {
		Ok(self
			.0
			.wallet_process_psbt(&psbt.as_string(), None, None, Some(false))
			.map(|res: WalletProcessPsbtResult| res.psbt)
			.unwrap())
	}
}

impl IsOutputKnown for MockOutputOwned {
	fn is_known(&self, _: crate::OutPoint) -> Result<bool, PayjoinError> {
		Ok(false)
	}
}

impl IsScriptOwned for MockScriptOwned {
	fn is_owned(&self, script: Arc<ScriptBuf>) -> Result<bool, PayjoinError> {
		{
			let network = Network::Regtest;
			let address = crate::Address::from_script(script, network).unwrap();
			let addr: payjoin::bitcoin::Address = address.into();
			Ok(self.0.get_address_info(&addr).unwrap().is_mine.unwrap())
		}
	}
}

#![cfg(all(feature = "enable-danger-local-https", not(feature = "uniffi")))]

extern crate core;

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use bitcoincore_rpc::bitcoincore_rpc_json::WalletProcessPsbtResult;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use payjoin_ffi::receive::v1::{Headers, PayjoinProposal, UncheckedProposal};
use payjoin_ffi::send::v1::RequestBuilder;
use payjoin_ffi::types::{OutPoint, Request, TxOut};
use payjoin_ffi::uri::{PjUriBuilder, Uri, Url};

type BoxError = Box<dyn std::error::Error>;

// Set up RPC connections
static RPC_USER: &str = "admin1";
static RPC_PASSWORD: &str = "123";
static RPC_HOST: &str = "localhost";
static RPC_PORT: &str = "18443";
#[test]
fn v1_to_v1_full_cycle() -> Result<(), BoxError> {
    let (sender, receiver) = init_rpc_sender_receiver();

    // Receiver creates the payjoin URI
    let pj_receiver_address = receiver.get_new_address(None, None).unwrap().assume_checked();
    let pj_uri_string = PjUriBuilder::new(
        pj_receiver_address.to_string(),
        Url::from_str("https://example.com".to_string())?,
        None,
        None,
    )?
    .amount(832_850)
    .build()
    .as_string();
    print!("pj_uri {}", pj_uri_string);

    let pj_uri = Uri::from_str(pj_uri_string).unwrap();

    // Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
    let mut outputs = HashMap::with_capacity(1);
    outputs.insert(
        pj_uri.address(),
        bitcoincore_rpc::bitcoin::Amount::from_btc(pj_uri.amount().unwrap().clone()).unwrap(),
    );

    let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
        lock_unspent: Some(true),
        fee_rate: Some(bitcoincore_rpc::bitcoin::Amount::from_sat(2000)),
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
    let psbt_base64 = sender.wallet_process_psbt(&psbt, None, None, None)?.psbt;
    eprintln!("Original psbt: {:#?}", psbt_base64);
    let req_ctx =
        RequestBuilder::from_psbt_and_uri(psbt_base64, pj_uri.check_pj_supported().unwrap())?
            .build_with_additional_fee(10000, None, 0, false)?
            .extract_v1()?;
    let req = req_ctx.request;
    let ctx = req_ctx.context_v1;
    let headers = Headers::from_vec(req.body.clone());

    // **********************
    // Inside the Receiver:
    // this data would transit from one party to another over the network in production
    let response = handle_pj_request(req, headers, receiver);
    // this response would be returned as http response to the sender

    // **********************
    // Inside the Sender:
    // Sender checks, signs, finalizes, extracts, and broadcasts
    let checked_payjoin_proposal_psbt =
        (*ctx).process_response(response?.as_bytes().to_vec()).expect("process error");
    let tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt);
    let txid = broadcast_tx(&sender, tx);
    println!("Broadcast txid: {:?}", txid);
    Ok(())
}

fn handle_pj_request(req: Request, headers: Headers, receiver: Client) -> Result<String, BoxError> {
    let receiver = Arc::new(receiver);
    let proposal = UncheckedProposal::from_request(
        req.body.clone(),
        req.url.query().unwrap_or("".to_string()),
        Arc::new(headers),
    )?;

    let payjoin_proposal = handle_pj_proposal(proposal, receiver);
    let psbt = payjoin_proposal.psbt();
    println!("\n Receiver psbt: {}", psbt);
    Ok(psbt)
}
fn handle_pj_proposal(proposal: UncheckedProposal, receiver: Arc<Client>) -> Arc<PayjoinProposal> {
    // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
    let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();
    let inputs_owned = proposal
        .check_broadcast_suitability(None, |tx| {
            Ok(receiver
                .test_mempool_accept(&[payjoin::bitcoin::consensus::encode::serialize_hex(
                    &payjoin::bitcoin::consensus::encode::deserialize::<
                        payjoin::bitcoin::Transaction,
                    >(tx)
                    .unwrap(),
                )])
                .unwrap()
                .first()
                .unwrap()
                .allowed)
        })
        .expect("Payjoin proposal should be broadcast");

    // Receive Check 2: receiver can't sign for proposal inputs
    let proposal = inputs_owned
        .check_inputs_not_owned(|e| {
            let addr = bitcoincore_rpc::bitcoin::Address::from_script(
                bitcoincore_rpc::bitcoin::Script::from_bytes(e.as_slice()),
                bitcoincore_rpc::bitcoin::Network::Regtest,
            )
            .unwrap();
            Ok(receiver.get_address_info(&addr).unwrap().is_mine.unwrap())
        })
        .expect("Receiver should not own any of the inputs");

    // Receive Check 3: receiver can't sign for proposal inputs
    let proposal = proposal.check_no_mixed_input_scripts().unwrap();

    // Receive Check 4: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
    let payjoin = Arc::new(
        proposal
            .check_no_inputs_seen_before(|_| Ok(false))
            .unwrap()
            .identify_receiver_outputs(|e| {
                let network = bitcoincore_rpc::bitcoin::Network::Regtest;
                let addr = bitcoincore_rpc::bitcoin::Address::from_script(
                    bitcoincore_rpc::bitcoin::Script::from_bytes(e.as_slice()),
                    network,
                )
                .unwrap();
                Ok(receiver.get_address_info(&addr).unwrap().is_mine.unwrap())
            })
            .expect("Receiver should have at least one output"),
    );

    // Select receiver payjoin inputs. TODO Lock them.
    let available_inputs = receiver.list_unspent(None, None, None, None, None).unwrap();
    let candidate_inputs: HashMap<u64, OutPoint> = available_inputs
        .iter()
        .map(|i| (i.amount.to_sat(), OutPoint { txid: i.txid.to_string(), vout: i.vout }))
        .collect();
    let selected_outpoint =
        payjoin.try_preserving_privacy(candidate_inputs).expect("try_preserving_privacy error");
    let selected_utxo = available_inputs
        .iter()
        .find(|i| {
            i.txid.to_string() == selected_outpoint.txid.to_string()
                && i.vout == selected_outpoint.vout
        })
        .unwrap();

    //  calculate receiver payjoin outputs given receiver payjoin inputs and original_psbt,
    let txo_to_contribute = TxOut {
        value: selected_utxo.amount.to_sat(),
        script_pubkey: selected_utxo.script_pub_key.clone().into_bytes(),
    };
    let outpoint_to_contribute =
        OutPoint { txid: selected_utxo.txid.to_string(), vout: selected_utxo.vout };
    payjoin
        .contribute_witness_input(txo_to_contribute, outpoint_to_contribute)
        .expect("contribute_witness_input error");

    let payjoin_proposal = payjoin
        .finalize_proposal(
            |e| {
                Ok(receiver
                    .wallet_process_psbt(e.as_str(), Some(true), None, Some(false))
                    .map(|res: WalletProcessPsbtResult| res.psbt)
                    .unwrap())
            },
            Some(1),
        )
        .expect("Failed to finalize proposal");
    payjoin_proposal
}

fn init_rpc_sender_receiver() -> (Client, Client) {
    let receiver = get_client("receiver");
    let sender = get_client("sender");
    let sender_address = sender.get_new_address(None, None).unwrap().assume_checked();
    let receiver_address = receiver.get_new_address(None, None).unwrap().assume_checked();
    receiver.generate_to_address(11, &receiver_address).unwrap();
    sender.generate_to_address(101, &sender_address).unwrap();
    println!("\n sender balance: {:?}", sender.get_balance(None, None));
    println!("\n receiver balance: {:?}", receiver.get_balance(None, None));
    (sender, receiver)
}
fn broadcast_tx(client: &Client, tx: payjoin::bitcoin::Transaction) -> Result<String, BoxError> {
    let raw_tx_hex = payjoin::bitcoin::consensus::encode::serialize_hex(&tx);
    Ok(client.send_raw_transaction(raw_tx_hex.as_str())?.to_string())
}

fn extract_pj_tx(sender: &Client, psbt: String) -> payjoin::bitcoin::Transaction {
    let payjoin_base64_string = psbt;
    let payjoin_psbt = sender
        .wallet_process_psbt(&payjoin_base64_string, None, None, None)
        .expect("process error")
        .psbt;
    let payjoin_psbt =
        sender.finalize_psbt(&payjoin_psbt, Some(false)).expect("finalize error").psbt.unwrap();

    let payjoin_psbt = payjoin::bitcoin::psbt::Psbt::from_str(payjoin_psbt.as_str()).unwrap();
    eprintln!("Sender's Payjoin PSBT: {:#?}", payjoin_psbt);
    payjoin_psbt.extract_tx().unwrap()
}
fn get_client(wallet_name: &str) -> Client {
    let url = format!("http://{}:{}/wallet/{}", RPC_HOST, RPC_PORT, wallet_name);
    Client::new(&*url, Auth::UserPass(RPC_USER.to_string(), RPC_PASSWORD.to_string())).unwrap()
}

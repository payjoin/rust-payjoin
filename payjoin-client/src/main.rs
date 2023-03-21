use std::collections::HashMap;
use std::convert::TryFrom;
use std::str::FromStr;

use bitcoincore_rpc::bitcoin::Amount;
use bitcoincore_rpc::RpcApi;
use clap::{arg, Arg, Command};
use payjoin::bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use payjoin::{PjUriExt, UriExt};

fn main() {
    env_logger::init();

    let matches = cli().get_matches();
    let port = matches.get_one::<String>("PORT").unwrap();
    let cookie_file = matches.get_one::<String>("COOKIE_FILE").unwrap();
    let bitcoind = bitcoincore_rpc::Client::new(
        &format!("http://127.0.0.1:{}", port.parse::<u16>().unwrap()),
        bitcoincore_rpc::Auth::CookieFile(cookie_file.into()),
    )
    .unwrap();
    match matches.subcommand() {
        Some(("send", sub_matches)) => {
            let bip21 = sub_matches.get_one::<String>("BIP21").unwrap();
            let danger_accept_invalid_certs =
                match { sub_matches.get_one::<String>("DANGER_ACCEPT_INVALID_CERTS") } {
                    Some(danger_accept_invalid_certs) =>
                        bool::from_str(danger_accept_invalid_certs).unwrap_or(false),
                    None => false,
                };
            send_payjoin(bitcoind, bip21, danger_accept_invalid_certs);
        }
        Some(("receive", sub_matches)) => {
            let amount = sub_matches.get_one::<String>("AMOUNT").unwrap();
            let endpoint = sub_matches.get_one::<String>("ENDPOINT").unwrap();
            receive_payjoin(bitcoind, amount, endpoint);
        }
        _ => unreachable!(), // If all subcommands are defined above, anything else is unreachabe!()
    }
}

fn send_payjoin(bitcoind: bitcoincore_rpc::Client, bip21: &str, danger_accept_invalid_certs: bool) {
    let link = payjoin::Uri::try_from(bip21).unwrap();

    let link = link
        .check_pj_supported()
        .unwrap_or_else(|_| panic!("The provided URI doesn't support payjoin (BIP78)"));

    if link.amount.is_none() {
        panic!("please specify the amount in the Uri");
    }

    let amount = Amount::from_sat(link.amount.unwrap().to_sat());
    let mut outputs = HashMap::with_capacity(1);
    outputs.insert(link.address.to_string(), amount);

    let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
        lock_unspent: Some(true),
        fee_rate: Some(Amount::from_sat(2000)),
        ..Default::default()
    };
    let psbt = bitcoind
        .wallet_create_funded_psbt(
            &[], // inputs
            &outputs,
            None, // locktime
            Some(options),
            None,
        )
        .expect("failed to create PSBT")
        .psbt;
    let psbt = bitcoind.wallet_process_psbt(&psbt, None, None, None).unwrap().psbt;
    let psbt = load_psbt_from_base64(psbt.as_bytes()).unwrap();
    log::debug!("Original psbt: {:#?}", psbt);
    let pj_params = payjoin::sender::Configuration::with_fee_contribution(
        payjoin::bitcoin::Amount::from_sat(10000),
        None,
    );
    let (req, ctx) = link.create_pj_request(psbt, pj_params).unwrap();
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(danger_accept_invalid_certs)
        .build()
        .unwrap();
    let response = client
        .post(req.url)
        .body(req.body)
        .header("Content-Type", "text/plain")
        .send()
        .expect("failed to communicate");
    //.error_for_status()
    //.unwrap();
    let psbt = ctx.process_response(response).unwrap();
    log::debug!("Proposed psbt: {:#?}", psbt);
    let psbt = bitcoind.wallet_process_psbt(&serialize_psbt(&psbt), None, None, None).unwrap().psbt;
    let tx = bitcoind.finalize_psbt(&psbt, Some(true)).unwrap().hex.expect("incomplete psbt");
    bitcoind.send_raw_transaction(&tx).unwrap();
}

fn receive_payjoin(bitcoind: bitcoincore_rpc::Client, amount_arg: &str, endpoint_arg: &str) {
    use bitcoin::hashes::hex::ToHex;
    use bitcoin::OutPoint;
    use payjoin::Uri;
    use rouille::Response;

    let pj_receiver_address = bitcoind.get_new_address(None, None).unwrap();
    let amount = Amount::from_sat(amount_arg.parse().unwrap());
    let pj_uri_string = format!(
        "{}?amount={}&pj={}",
        pj_receiver_address.to_qr_uri(),
        amount.to_btc(),
        endpoint_arg
    );
    let pj_uri = Uri::from_str(&pj_uri_string).unwrap();
    let _pj_uri = pj_uri.check_pj_supported().expect("Bad Uri");

    println!("Awaiting payjoin at BIP 21 Payjoin Uri:");
    println!("{}", pj_uri_string);

    rouille::start_server("0.0.0.0:3000", move |req| {
        let headers = Headers(req.headers());
        let proposal = payjoin::receiver::UncheckedProposal::from_request(
            req.data().unwrap(),
            req.raw_query_string(),
            headers,
        )
        .unwrap();

        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.get_transaction_to_schedule_broadcast();

        // The network is used for checks later
        let network = match bitcoind.get_blockchain_info().unwrap().chain.as_str() {
            "main" => bitcoin::Network::Bitcoin,
            "test" => bitcoin::Network::Testnet,
            "regtest" => bitcoin::Network::Regtest,
            _ => panic!("Unknown network"),
        };

        // Receive Check 1: Can Broadcast
        let proposal = proposal
            .check_can_broadcast(|tx| {
                bitcoind
                    .test_mempool_accept(&[bitcoin::consensus::encode::serialize(&tx).to_hex()])
                    .unwrap()
                    .first()
                    .unwrap()
                    .allowed
            })
            .expect("Payjoin proposal should be broadcastable");
        log::trace!("check1");

        // Receive Check 2: receiver can't sign for proposal inputs
        let proposal = proposal
            .check_inputs_not_owned(|input| {
                let address = bitcoin::Address::from_script(&input, network).unwrap();
                bitcoind.get_address_info(&address).unwrap().is_mine.unwrap()
            })
            .expect("Receiver should not own any of the inputs");
        log::trace!("check2");
        // Receive Check 3: receiver can't sign for proposal inputs
        let proposal = proposal.check_no_mixed_input_scripts().unwrap();
        log::trace!("check3");

        // Receive Check 4: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
        let mut payjoin = proposal
            .check_no_inputs_seen_before(|_| false)
            .unwrap()
            .identify_receiver_outputs(|output_script| {
                let address = bitcoin::Address::from_script(&output_script, network).unwrap();
                bitcoind.get_address_info(&address).unwrap().is_mine.unwrap()
            })
            .expect("Receiver should have at least one output");
        log::trace!("check4");

        // Select receiver payjoin inputs.
        let available_inputs = bitcoind.list_unspent(None, None, None, None, None).unwrap();
        let candidate_inputs: HashMap<Amount, OutPoint> = available_inputs
            .iter()
            .map(|i| (i.amount, OutPoint { txid: i.txid, vout: i.vout }))
            .collect();

        let selected_outpoint = payjoin.try_preserving_privacy(candidate_inputs).expect("gg");
        let selected_utxo = available_inputs
            .iter()
            .find(|i| i.txid == selected_outpoint.txid && i.vout == selected_outpoint.vout)
            .unwrap();
        log::debug!("selected utxo: {:#?}", selected_utxo);

        //  calculate receiver payjoin outputs given receiver payjoin inputs and original_psbt,
        let txo_to_contribute = bitcoin::TxOut {
            value: selected_utxo.amount.to_sat(),
            script_pubkey: selected_utxo.script_pub_key.clone(),
        };
        let outpoint_to_contribute =
            bitcoin::OutPoint { txid: selected_utxo.txid, vout: selected_utxo.vout };
        payjoin.contribute_witness_input(txo_to_contribute, outpoint_to_contribute);

        let receiver_substitute_address = bitcoind.get_new_address(None, None).unwrap();
        payjoin.substitute_output_address(receiver_substitute_address);

        let payjoin_proposal_psbt = payjoin.extract_psbt(Some(1)).expect("failed to apply fees");
        log::debug!("Extracted PSBT: {:#?}", payjoin_proposal_psbt);
        // Sign payjoin psbt
        let payjoin_base64_string =
            base64::encode(bitcoin::consensus::serialize(&payjoin_proposal_psbt));
        // `wallet_process_psbt` adds available utxo data and finalizes
        let payjoin_proposal_psbt = bitcoind
            .wallet_process_psbt(&payjoin_base64_string, None, None, Some(false))
            .unwrap()
            .psbt;
        let payjoin_proposal_psbt =
            load_psbt_from_base64(payjoin_proposal_psbt.as_bytes()).unwrap();
        let payjoin_proposal_psbt =
            payjoin::receiver::clear_utxo_from_non_final_inputs(payjoin_proposal_psbt);
        log::debug!("Receiver's PayJoin proposal PSBT Rsponse: {:#?}", payjoin_proposal_psbt);

        let payload = base64::encode(bitcoin::consensus::serialize(&payjoin_proposal_psbt));
        log::info!("successful response");
        Response::text(payload)
    });
}

struct Headers<'a>(rouille::HeadersIter<'a>);
impl payjoin::receiver::Headers for Headers<'_> {
    fn get_header(&self, key: &str) -> Option<&str> {
        let mut copy = self.0.clone(); // lol
        copy.find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v)
    }
}

fn load_psbt_from_base64(
    mut input: impl std::io::Read,
) -> Result<Psbt, payjoin::bitcoin::consensus::encode::Error> {
    use payjoin::bitcoin::consensus::Decodable;

    let mut reader = base64::read::DecoderReader::new(
        &mut input,
        base64::Config::new(base64::CharacterSet::Standard, true),
    );
    Psbt::consensus_decode(&mut reader)
}

fn serialize_psbt(psbt: &Psbt) -> String {
    use payjoin::bitcoin::consensus::Encodable;

    let mut encoder = base64::write::EncoderWriter::new(Vec::new(), base64::STANDARD);
    psbt.consensus_encode(&mut encoder)
        .expect("Vec doesn't return errors in its write implementation");
    String::from_utf8(
        encoder.finish().expect("Vec doesn't return errors in its write implementation"),
    )
    .unwrap()
}

fn cli() -> Command {
    Command::new("payjoin")
        .about("Transfer bitcoin and preserve your privacy")
        .arg(arg!(<PORT> "The port of the bitcoin node"))
        .arg_required_else_help(true)
        .arg(arg!(<COOKIE_FILE> "Path to the cookie file of the bitcoin node"))
        .subcommand_required(true)
        .subcommand(
            Command::new("send")
                .arg_required_else_help(true)
                .arg(arg!(<BIP21> "The `bitcoin:...` payjoin uri to send to"))
                .arg(Arg::new("DANGER_ACCEPT_INVALID_CERTS").hide(true).help("Wicked dangerous! Vulnerable to MITM attacks! Accept invalid certs for the payjoin endpoint")),
        )
        .subcommand(
            Command::new("receive")
                .arg_required_else_help(true)
                .arg(arg!(<AMOUNT> "The amount to receive in satoshis"))
                .arg_required_else_help(true)
                .arg(arg!(<ENDPOINT> "The `pj=` endpoint to receive the payjoin request")),
        )
}

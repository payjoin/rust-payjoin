use std::collections::HashMap;
use std::convert::TryFrom;

use bitcoincore_rpc::bitcoin::Amount;
use bitcoincore_rpc::RpcApi;
use clap::{arg, Command};
use payjoin::bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use payjoin::{PjUriExt, UriExt};

fn main() {
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
            send_payjoin(bitcoind, bip21);
        }
        Some(("receive", sub_matches)) => {
            let amount = sub_matches.get_one::<String>("AMOUNT").unwrap();
            let endpoint = sub_matches.get_one::<String>("ENDPOINT").unwrap();
            receive_payjoin(bitcoind, amount, endpoint);
        }
        _ => unreachable!(), // If all subcommands are defined above, anything else is unreachabe!()
    }
}

fn send_payjoin(bitcoind: bitcoincore_rpc::Client, bip21: &str) {
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
    println!("Original psbt: {:#?}", psbt);
    let pj_params = payjoin::sender::Configuration::with_fee_contribution(
        payjoin::bitcoin::Amount::from_sat(10000),
        None,
    );
    let (req, ctx) = link.create_pj_request(psbt, pj_params).unwrap();
    let response = reqwest::blocking::Client::new()
        .post(req.url)
        .body(req.body)
        .header("Content-Type", "text/plain")
        .send()
        .expect("failed to communicate");
    //.error_for_status()
    //.unwrap();
    let psbt = ctx.process_response(response).unwrap();
    println!("Proposed psbt: {:#?}", psbt);
    let psbt = bitcoind.wallet_process_psbt(&serialize_psbt(&psbt), None, None, None).unwrap().psbt;
    let tx = bitcoind.finalize_psbt(&psbt, Some(true)).unwrap().hex.expect("incomplete psbt");
    bitcoind.send_raw_transaction(&tx).unwrap();
}

fn receive_payjoin(_bitcoind: bitcoincore_rpc::Client, _amount_arg: &str, _endpoint_arg: &str) {
    todo!();
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
                .arg(arg!(<BIP21> "The `bitcoin:...` payjoin uri to send to")),
        )
        .subcommand(
            Command::new("receive")
                .arg_required_else_help(true)
                .arg(arg!(<AMOUNT> "The amount to receive in satoshis"))
                .arg_required_else_help(true)
                .arg(arg!(<ENDPOINT> "The `pj=` endpoint to receive the payjoin request")),
        )
}

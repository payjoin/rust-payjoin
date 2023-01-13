use std::collections::HashMap;
use std::convert::TryFrom;


use bitcoincore_rpc::bitcoin::Amount;
use bitcoincore_rpc::RpcApi;
use clap::{App, AppSettings, Arg};
use payjoin::bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use payjoin::{PjUriExt, UriExt};

fn main() {
    let mut app = App::new("payjoin-client")
        .version("0.1.0")
        .author("Dan Gould <d@ngould.dev>")
        .about("A simple payjoin client that can receive without hosting a secure endpoint using TURN")
        .setting(AppSettings::DeriveDisplayOrder)
        .setting(AppSettings::SubcommandsNegateReqs)
        .arg(Arg::with_name("port")
            .short("p")
            .long("port")
            .help("The bitcoind rpc port to connect to")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("cookie_file")
            .short("c")
            .long("cookie_file")
            .help("The bitcoind rpc cookie file to use for authentication")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("bip21")
            .short("b")
            .long("bip21")
            .help("The BIP21 URI to send to")
            .takes_value(true)
            .required(true));

    let matches = app.clone().get_matches();

    if matches.is_present("FULLHELP") {
        app.print_long_help().unwrap();
        return;
    }

    let port = matches.value_of("port").unwrap();
    let cookie_file = matches.value_of("cookie_file").unwrap();
    let bip21 = matches.value_of("bip21").unwrap().as_ref();

    let client = bitcoincore_rpc::Client::new(
        &format!("http://127.0.0.1:{}", port),
        bitcoincore_rpc::Auth::CookieFile(cookie_file.into()),
    )
    .unwrap();

    send_payjoin(bip21, client);

}

fn send_payjoin<'a>(bip21: &str, client: bitcoincore_rpc::Client) -> bitcoincore_rpc::bitcoin::Txid { 
    let link = payjoin::Uri::try_from(&*bip21).unwrap();

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
    let psbt = client
        .wallet_create_funded_psbt(
            &[], // inputs
            &outputs,
            None, // locktime
            Some(options),
            None,
        )
        .expect("failed to create PSBT")
        .psbt;
    let psbt = client.wallet_process_psbt(&psbt, None, None, None).unwrap().psbt;
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
    let psbt = client.wallet_process_psbt(&serialize_psbt(&psbt), None, None, None).unwrap().psbt;
    let tx = client.finalize_psbt(&psbt, Some(true)).unwrap().hex.expect("incomplete psbt");
    client.send_raw_transaction(&tx).unwrap()
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

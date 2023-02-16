use std::collections::HashMap;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::str::FromStr;
use std::sync::Arc;

use payjoin::bitcoin::hashes::hex::ToHex;
use turn::client::*;
use turn::Error;
use bitcoincore_rpc::bitcoin::Address;
use bitcoincore_rpc::bitcoin::Amount;
use bitcoincore_rpc::RpcApi;
use clap::{App, AppSettings, Arg};
use payjoin::bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use payjoin::{PjUriExt, UriExt};
use tokio::net::UdpSocket;
use webrtc_util::Conn;
use noiseexplorer_nnpsk0::noisesession::NoiseSession;
use noiseexplorer_nnpsk0::consts::{MAC_LENGTH, DHLEN};
use noiseexplorer_nnpsk0::types::Keypair;
use magic_wormhole::Wormhole;


#[tokio::main]
async fn main() -> Result<(), Error> {
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
        .arg(Arg::with_name("cookie-file")
            .short("c")
            .long("cookie-file")
            .help("The bitcoind rpc cookie file to use for authentication")
            .takes_value(true)
            .required(true))
            
        .arg(Arg::with_name("bip21")
            .short("b")
            .long("bip21")
            .help("The BIP21 URI to send to")
            .takes_value(true))
        .arg(Arg::with_name("code")
            .short("o")
            .long("code")
            .help("The magic wormhole code to send the payjoin to")
            .takes_value(true))
        .arg(Arg::with_name("psk")
            .short("s")
            .long("psk")
            .help("The pre-shared symmetric key")
            .takes_value(true))
        .arg(Arg::with_name("amount")
            .short("a")
            .long("amount")
            .help("The amount to request in satoshis")
            .takes_value(true));

    let matches = app.clone().get_matches();

    if matches.is_present("FULLHELP") {
        app.print_long_help().unwrap();
        return Ok(());
    }

    let port = matches.value_of("port").unwrap();
    let cookie_file = matches.value_of("cookie-file").unwrap();

    let bitcoind = bitcoincore_rpc::Client::new(
        &format!("http://127.0.0.1:{}", port),
        bitcoincore_rpc::Auth::CookieFile(cookie_file.into()),
    )
    .unwrap();

    if matches.is_present("amount") {
        let amount = matches.value_of("amount").unwrap();
        let amount = Amount::from_sat(amount.parse::<u64>().unwrap());
        listen_receiver(amount, bitcoind).await?;
    } else {
        let bip21 = matches.value_of("bip21").unwrap().as_ref();
        let code = matches.value_of("code").unwrap();
        let psk = matches.value_of("psk").unwrap();
        let (req, ctx) = create_pj_request(bip21, &bitcoind); //base64 request
        let payjoin_psbt = do_send(req, ctx, code, psk).await?;
        let psbt = bitcoind.wallet_process_psbt(&serialize_psbt(&payjoin_psbt), None, None, None).unwrap().psbt;
        let tx = bitcoind.finalize_psbt(&psbt, Some(true)).unwrap().hex.expect("incomplete psbt");
        let txid = bitcoind.send_raw_transaction(&tx).unwrap();
        println!("Sent tx: {}", txid);
    }

    Ok(())
}

async fn listen_receiver(amount: Amount, bitcoind: bitcoincore_rpc::Client) -> Result<(), Error> {
    let psk = gen_psk();
    let (welcome, res) = Wormhole::connect_without_code(magic_wormhole::transfer::APP_CONFIG, 2).await.unwrap();
    print!("--code={:?} --psk=\"{}\" ", welcome.code.0, psk);
    let pj_receiver_address = bitcoind.get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32)).unwrap();
    print_payjoin_uri(pj_receiver_address, amount);

    // 2. Recv
    let mut wormhole = res.await.unwrap();
    process_original_psbt(&mut wormhole,  bitcoind, psk).await?;

    wormhole.close().await.unwrap();
    Ok(())
}

async fn process_original_psbt(
    wormhole: &mut Wormhole,
    receiver: bitcoincore_rpc::Client,
    psk: String,
) -> Result<(), Error> {
    use payjoin::bitcoin;
    use payjoin::receiver::UncheckedProposal;
    use payjoin::bitcoin::consensus;
    use payjoin::bitcoin::blockdata::script::Script;
    use payjoin::bitcoin::blockdata::transaction::TxOut;

    let psk: [u8; 32] = base64::decode(psk).unwrap().try_into().unwrap();
    let psk = noiseexplorer_nnpsk0::types::Psk::from_bytes(psk);
    
    let mut buf = wormhole.receive().await.unwrap();
    println!("received {} bytes of supposed Original PSBT", buf.len());
    
    // security does not depend on long-term static keys in NNpsk0. The interface still requires a Keypair, but it is not used.
    let mut responder = NoiseSession::init_session(false, b"", Keypair::new_empty(), psk);
    responder.recv_message(&mut buf).unwrap(); // es derived internally
    let (_initiator_e, payload) = buf.split_at_mut(DHLEN);
    let (payload, _mac) = payload.split_at_mut(payload.len() - MAC_LENGTH);
    let n = payload.len(); // hopefully from_request can trim the padding, else we're gonna need to send the length on the wire as headers does
    // query, headers not passed by default udp
    // We'll need to figure out how to pass query info at least.
    let query = "";
    let headers = MockHeaders::new(n);
    let proposal = UncheckedProposal::from_request(&payload[..n], query, headers).unwrap();

    // Receive Check 1: Is Broadcastable
    let original_tx = proposal.get_transaction_to_check_broadcast();
    let tx_is_broadcastable = receiver
    .test_mempool_accept(&[bitcoin::consensus::encode::serialize(&original_tx).to_hex()])
    .unwrap()
    .first()
    .unwrap()
    .allowed;
    assert!(tx_is_broadcastable);

    let checked_proposal = proposal.assume_tested_and_scheduled_broadcast().assume_inputs_not_owned().assume_no_mixed_input_scripts().assume_no_inputs_seen_before();

    let mut original_psbt = checked_proposal.psbt();
    original_psbt.unsigned_tx.input.iter_mut().for_each(|txin| txin.script_sig = Script::default());

    let mut payjoin_proposal_psbt = original_psbt.clone();
    let receiver_vout = 0; // correct???
                            //      TODO add selected receiver input utxo
                            //      substitute receiver output
    let receiver_substitute_address = receiver.get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32)).unwrap();
    let receiver_substitute_address = bitcoin::Address::from_str(&receiver_substitute_address.to_string()).unwrap();
    let substitute_txout = TxOut {
        value: payjoin_proposal_psbt.unsigned_tx.output[receiver_vout].value,
        script_pubkey: receiver_substitute_address.script_pubkey(),
    };
    payjoin_proposal_psbt.unsigned_tx.output[receiver_vout] = substitute_txout;
    payjoin_proposal_psbt
        .outputs
        .resize_with(payjoin_proposal_psbt.unsigned_tx.output.len(), Default::default);

    // Sign payjoin psbt
    let payjoin_base64_string = base64::encode(consensus::serialize(&payjoin_proposal_psbt));
    let payjoin_proposal_psbt =
        receiver.wallet_process_psbt(&payjoin_base64_string, None, None, None).unwrap().psbt;
    let payjoin_proposal_psbt =
        receiver.finalize_psbt(&payjoin_proposal_psbt, Some(false)).unwrap().psbt.unwrap();
    let payjoin_proposal_psbt =
        load_psbt_from_base64(payjoin_proposal_psbt.as_bytes()).unwrap();
    println!("Receiver's PayJoin proposal PSBT: {:#?}", payjoin_proposal_psbt);

    // Remove vestigial invalid signature data from the Original PSBT
    let payjoin_proposal_psbt =
        Psbt::from_unsigned_tx(payjoin_proposal_psbt.unsigned_tx.clone())
            .expect("resetting tx failed");
    let payjoin_proposal_psbt = base64::encode(consensus::serialize(&payjoin_proposal_psbt));
    
    // noise handshake response
    let mut in_out: Vec<u8> = vec![0; DHLEN];
    let message_b_size = DHLEN + payjoin_proposal_psbt.len() + MAC_LENGTH;
    in_out.append(&mut payjoin_proposal_psbt.as_bytes().to_vec());
    in_out.resize(message_b_size, 0);
    responder.send_message(&mut in_out).unwrap(); // e, ee
    
    wormhole.send(in_out).await.unwrap();

    Ok(())
}

async fn do_send(req: payjoin::sender::Request, ctx: payjoin::sender::Context, code: &str, psk: &str) -> Result<Psbt, Error> {
    let mut original_psbt = req.body.clone(); //format!("{:?}", tokio::time::Instant::now());

    // Set up wormhole
    let (_, mut wormhole) = Wormhole::connect_with_code(magic_wormhole::transfer::APP_CONFIG, magic_wormhole::Code(code.to_owned())).await.unwrap();

    // do noise secure handshake
    let psk: [u8; 32] = base64::decode(psk).unwrap().try_into().unwrap();
    println!("psk: {:?}", base64::encode(psk));
    let psk = noiseexplorer_nnpsk0::types::Psk::from_bytes(psk);

    // security does not depend on long-term static keys in NNpsk0. The interface still requires a Keypair, but it is not used.
    let mut initiator = NoiseSession::init_session(true, b"", Keypair::new_empty(), psk.clone());
    let mut in_out: Vec<u8> = vec![0; DHLEN];
    let message_a_size = DHLEN + original_psbt.len() + MAC_LENGTH;
    in_out.append(&mut original_psbt);
    in_out.resize(message_a_size, 0);
    println!("sending in_out: {:?}", in_out);
    initiator.send_message(&mut in_out).unwrap(); // psk, e
    println!("sending message_a: {:?}", in_out);
    wormhole.send(in_out).await.unwrap();


    let mut buf = wormhole.receive().await.unwrap();

    // finish noise handshake
    initiator.recv_message(&mut buf).unwrap();
    let (_responder_e, payload) = buf.split_at_mut(DHLEN);
    let (payload, _mac) = payload.split_at_mut(payload.len() - MAC_LENGTH);
    let n = payload.len();
    let proposal = ctx.process_response(&payload[..n]).unwrap();
    println!("proposal: {:#?}", proposal);
    Ok(proposal)
}

// get a valid BIP 21 URI for payjoin as defined in BIP 78
// we have to use a mock endpoing because we are using udp not https
fn print_payjoin_uri<'a>(address: Address, amount: Amount) {
        // Receiver creates the bip21 payjoin URI
        let mock_endpoint = "https://example.com";
        let pj_uri_string = format!(
            "{}?amount={}&pj={}",
            address.to_qr_uri(),
            amount.as_btc(),
            mock_endpoint,
        );
        println!("--bip21=\"{}\"", pj_uri_string);
        let _pj_uri = payjoin::Uri::from_str(&pj_uri_string).unwrap(); // just validate the Uri
        // pj_uri.check_pj_supported().expect("Bad Uri"); ignore this because we are using udp not https and endpoint will fail
}

fn create_pj_request(bip21: &str, client: &bitcoincore_rpc::Client) -> (payjoin::sender::Request, payjoin::sender::Context) {
    let link = payjoin::Uri::try_from(&*bip21).unwrap();

    if link.amount.is_none() {
        panic!("please specify the amount in the Uri");
    }

    // ⚠️ we're hacking around this check by using a dummy endpoint. This is not a good idea in production
    // We use a udp endpoint that would not support BIP 78 payjoin instead.
    let link = link
        .check_pj_supported()
        .unwrap_or_else(|_| panic!("The provided URI doesn't support payjoin (BIP78)"));

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
    let pj_params = payjoin::sender::Configuration::non_incentivizing();
    link.create_pj_request(psbt, pj_params).unwrap()
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

pub struct MockHeaders {
    length: String,
}

impl MockHeaders {
    fn new(length: usize) -> MockHeaders { MockHeaders { length: length.to_string() } }
}

impl payjoin::receiver::Headers for MockHeaders {
    fn get_header(&self, key: &str) -> Option<&str> {
        match key {
            "content-length" => Some(&self.length),
            "content-type" => Some("text/plain"),
            _ => None,
        }
    }
}

fn gen_psk() -> String {
    use rand::RngCore;
    use rand::thread_rng;

    let mut rng = thread_rng();
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    base64::encode(&key)
}
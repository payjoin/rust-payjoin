use std::collections::HashMap;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use nkpsk0::consts::DHLEN;
use nkpsk0::consts::MAC_LENGTH;
use nkpsk0::types::Keypair;
use nkpsk0::types::Psk;
use nkpsk0::types::PublicKey;
use turn::client::*;
use turn::Error;
use bitcoincore_rpc::bitcoin::Address;
use bitcoincore_rpc::bitcoin::Amount;
use bitcoincore_rpc::RpcApi;
use clap::{App, AppSettings, Arg};
use payjoin::bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use payjoin::{PjUriExt, UriExt};
use tokio::net::UdpSocket;
use tokio::time::Duration;
use webrtc_util::Conn;

use nkpsk0::noisesession::NoiseSession;

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
            .takes_value(true))
        .arg(Arg::with_name("endpoint")
            .short("e")
            .long("endpoint")
            .help("The endpoint to send the payjoin to")
            .takes_value(true))
        .arg(Arg::with_name("rs")
            .short("s")
            .long("rs")
            .help("The receiver's static public key")
            .takes_value(true))

        .arg(Arg::with_name("relay")
            .short("r")
            .long("relay")
            .help("PayJoin TURN server relay address to establish p2p networking")
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
    let cookie_file = matches.value_of("cookie_file").unwrap();

    let bitcoind = bitcoincore_rpc::Client::new(
        &format!("http://127.0.0.1:{}", port),
        bitcoincore_rpc::Auth::CookieFile(cookie_file.into()),
    )
    .unwrap();

    if matches.is_present("relay") {
        let relay = matches.value_of("relay").unwrap();
        let amount = matches.value_of("amount").unwrap();
        let amount = Amount::from_sat(amount.parse::<u64>().unwrap());
        listen_receiver(relay, amount, bitcoind).await?;
    } else {
        //let bip21 = matches.value_of("bip21").unwrap().as_ref();
        let endpoint = matches.value_of("endpoint").unwrap();
        let rs = matches.value_of("rs").unwrap();
        do_send(endpoint, rs).await?;
        //send_payjoin(bip21, bitcoind);
    }

    Ok(())
}

async fn listen_receiver(relay: &str, amount: Amount, bitcoind: bitcoincore_rpc::Client) -> Result<(), Error> {
    // 1. ConnectReceive
    // Ensure relay connection
    // TURN client won't create a local listening socket by itself.
    let conn = UdpSocket::bind("0.0.0.0:0").await?;

    let turn_server_addr = relay.to_string();

    let cfg = ClientConfig {
        stun_serv_addr: turn_server_addr.clone(),
        turn_serv_addr: turn_server_addr,
        username: "receiver".to_string(),
        password: "test".to_string(),
        realm: "test".to_string(),
        software: String::new(),
        rto_in_ms: 0,
        conn: Arc::new(conn),
        vnet: None,
    };

    let client = Client::new(cfg).await?;

    // Start listening on the conn provided.
    client.listen().await?;

    // Allocate a relay socket on the TURN server. On success, it
    // will return a net.PacketConn which represents the remote
    // socket.
    let relay_conn = client.allocate().await?;

    let static_key = Keypair::default();
    let s_base64 = base64::encode(static_key.get_public_key().as_bytes());
    let psk = Psk::default(); // could derive psk from bip21 address
    let mut noise = NoiseSession::init_session(false, &[], static_key, None, psk);

    // The relayConn's local address is actually the transport
    // address assigned on the TURN server.
    let relay_conn_endpoint = relay_conn.local_addr()?;
    println!("--rs={} --endpoint={}", s_base64, relay_conn_endpoint);

    let mapped_addr = client.send_binding_request().await?;
    // punch UDP hole. after this packets from the IP address will be accepted by the turn server
    relay_conn.send_to("Hello".as_bytes(), mapped_addr).await?;

    // 2. Recv
    let pj_receiver_address = bitcoind.get_new_address(None, None).unwrap();
    print_payjoin_uri(pj_receiver_address, amount, relay_conn_endpoint);
    process_original_psbt(relay_conn, &mut noise, bitcoind).await?;

    client.close().await?;
    Ok(())
}

async fn process_original_psbt(
    relay_conn: impl Conn + std::marker::Send + std::marker::Sync + 'static,
    noise: &mut NoiseSession,
    receiver: bitcoincore_rpc::Client,
) -> Result<(), Error> {
    use payjoin::bitcoin;
    use payjoin::receiver::UncheckedProposal;
    use payjoin::bitcoin::consensus;
    use payjoin::bitcoin::blockdata::script::Script;
    use payjoin::bitcoin::blockdata::transaction::TxOut;

    let mut buf = [0u8; 1024];
    let (n, from) = relay_conn.recv_from(&mut buf).await?;
    println!("received {} bytes of supposed Original PSBT from {}", n, from);
    noise.recv_message(&mut buf[..n]).unwrap();

    // query, headers not passed by default udp
    // We'll need to figure out how to pass query info at least.
    let query = "";
    let headers = MockHeaders::new(n);
    let proposal = UncheckedProposal::from_request(&buf[..n], query, headers).unwrap();
    let checked_proposal = proposal.assume_tested_and_scheduled_broadcast().assume_inputs_not_owned().assume_no_mixed_input_scripts().assume_no_inputs_seen_before();

    let mut original_psbt = checked_proposal.psbt();
    original_psbt.unsigned_tx.input.iter_mut().for_each(|txin| txin.script_sig = Script::default());

    let mut payjoin_proposal_psbt = original_psbt.clone();
    let receiver_vout = 0; // correct???
                            //      TODO add selected receiver input utxo
                            //      substitute receiver output
    let receiver_substitute_address = receiver.get_new_address(None, None).unwrap();
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
    let mut payjoin_proposal_psbt = consensus::serialize(&payjoin_proposal_psbt);
    payjoin_proposal_psbt.resize(payjoin_proposal_psbt.len() + DHLEN + MAC_LENGTH, 0u8);
    noise.send_message(&mut payjoin_proposal_psbt).unwrap();
    relay_conn.send_to(payjoin_proposal_psbt.as_slice(), from).await?;
    println!("sent PayJin Proposal");

    Ok(())
}

async fn do_send(relay_addr: &str, rs_base64: &str) -> Result<(), Error> {
    let msg = "Original PSBT".to_owned(); //format!("{:?}", tokio::time::Instant::now());
    println!("sending msg={} with size={}", msg, msg.as_bytes().len());

    let s = Keypair::default();
    let rs_bytes: [u8; DHLEN] = base64::decode(rs_base64).unwrap().try_into().unwrap();
    let rs = PublicKey::from_bytes(rs_bytes).unwrap();
    let psk = Psk::default(); // could use bitcoin address as psk, ⚠️ empty for demo
    let mut noise = NoiseSession::init_session(true, &[], s, Some(rs), psk);
    noise.set_ephemeral_keypair(Keypair::default());
    // Set up pinger socket (pingerConn)
    //println!("bind...");
    let pinger_conn_tx = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let pinger_conn_rx = Arc::clone(&pinger_conn_tx);
    let mut msg = msg.into_bytes();
    msg.resize(msg.len() + DHLEN + MAC_LENGTH, 0); // + buf + MAC_LENGTH + DH_LENGTH
    noise.send_message(&mut msg).unwrap();

    pinger_conn_tx.send_to(msg.as_slice(), relay_addr).await?;

    let mut buf = [0u8; 1024];

    let (n, from) = pinger_conn_rx.recv_from(&mut buf).await?;
    let msg = String::from_utf8(buf[..n].to_vec()).unwrap();
    println!("response: {} from {}", msg, from);
    Ok(())
}

fn print_payjoin_uri<'a>(address: Address, amount: Amount, endpoint: SocketAddr) {
        // Receiver creates the bip21 payjoin URI
        let pj_uri_string = format!(
            "{}?amount={}&pj={}",
            address.to_qr_uri(),
            amount.as_btc(),
            format!("udp://{}", endpoint)
        );
        println!("PayJoin URI: {}", pj_uri_string);
        let _pj_uri = payjoin::Uri::from_str(&pj_uri_string).unwrap(); // just validate the Uri
        // pj_uri.check_pj_supported().expect("Bad Uri"); ignore this because we are using udp not https and endpoint will fail
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
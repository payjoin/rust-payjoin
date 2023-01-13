use std::collections::HashMap;
use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::Arc;

use turn::client::*;
use turn::Error;
use bitcoincore_rpc::bitcoin::Amount;
use bitcoincore_rpc::RpcApi;
use clap::{App, AppSettings, Arg};
use payjoin::bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use payjoin::{PjUriExt, UriExt};
use tokio::net::UdpSocket;
use tokio::time::Duration;
use webrtc_util::Conn;

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
        .arg(Arg::with_name("relay")
            .short("r")
            .long("relay")
            .help("PayJoin relay to establish p2p networking")
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
        // Ensure relay connection
        // TURN client won't create a local listening socket by itself.
        let conn = UdpSocket::bind("0.0.0.0:0").await?;

        let turn_server_addr = relay.to_string();

        let cfg = ClientConfig {
            stun_serv_addr: turn_server_addr.clone(),
            turn_serv_addr: turn_server_addr,
            username: "test".to_string(),
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

        // The relayConn's local address is actually the transport
        // address assigned on the TURN server.
        println!("relayed-address={}", relay_conn.local_addr()?);

        // If you provided `-ping`, perform a ping test agaist the
        let ping = true;
        // relayConn we have just allocated.
        if ping {
            do_ping_test(&client, relay_conn).await?;
        }

        receive_payjoin(relay, amount, bitcoind);

        client.close().await?;
    } else {
        let bip21 = matches.value_of("bip21").unwrap().as_ref();
        send_payjoin(bip21, bitcoind);
    }

    Ok(())
}

async fn do_ping_test(
    client: &Client,
    relay_conn: impl Conn + std::marker::Send + std::marker::Sync + 'static,
) -> Result<(), Error> {
    // Send BindingRequest to learn our external IP
    let mapped_addr = client.send_binding_request().await?;

    // Set up pinger socket (pingerConn)
    //println!("bind...");
    let pinger_conn_tx = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    // Punch a UDP hole for the relay_conn by sending a data to the mapped_addr.
    // This will trigger a TURN client to generate a permission request to the
    // TURN server. After this, packets from the IP address will be accepted by
    // the TURN server.
    //println!("relay_conn send hello to mapped_addr {}", mapped_addr);
    relay_conn.send_to("Hello".as_bytes(), mapped_addr).await?;
    let relay_addr = relay_conn.local_addr()?;

    let pinger_conn_rx = Arc::clone(&pinger_conn_tx);

    // Start read-loop on pingerConn
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let (n, from) = match pinger_conn_rx.recv_from(&mut buf).await {
                Ok((n, from)) => (n, from),
                Err(_) => break,
            };

            let msg = match String::from_utf8(buf[..n].to_vec()) {
                Ok(msg) => msg,
                Err(_) => break,
            };

            println!("pingerConn read-loop: {} from {}", msg, from);
            /*if sentAt, pingerErr := time.Parse(time.RFC3339Nano, msg); pingerErr == nil {
                rtt := time.Since(sentAt)
                log.Printf("%d bytes from from %s time=%d ms\n", n, from.String(), int(rtt.Seconds()*1000))
            }*/
        }
    });

    // Start read-loop on relay_conn
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let (n, from) = match relay_conn.recv_from(&mut buf).await {
                Err(_) => break,
                Ok((n, from)) => (n, from),
            };

            println!("relay_conn read-loop: {:?} from {}", &buf[..n], from);

            // Echo back
            if relay_conn.send_to(&buf[..n], from).await.is_err() {
                break;
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    /*println!(
        "pinger_conn_tx send 10 packets to relay addr {}...",
        relay_addr
    );*/
    // Send 10 packets from relay_conn to the echo server
    for _ in 0..2 {
        let msg = "12345678910".to_owned(); //format!("{:?}", tokio::time::Instant::now());
        println!("sending msg={} with size={}", msg, msg.as_bytes().len());
        pinger_conn_tx.send_to(msg.as_bytes(), relay_addr).await?;

        // For simplicity, this example does not wait for the pong (reply).
        // Instead, sleep 1 second.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Ok(())
}

fn receive_payjoin(relay: &str, amount: &str, client: bitcoincore_rpc::Client) {
        
        // Receiver creates the bip21 payjoin URI
        let pj_receiver_address = client.get_new_address(None, None).unwrap();
        let amount = Amount::from_str(amount).unwrap();
        let pj_uri_string = format!(
            "{}?amount={}&pj={}&s=secret",
            pj_receiver_address.to_qr_uri(),
            amount.as_btc(),
            relay,
        );
        let pj_uri = payjoin::Uri::from_str(&pj_uri_string).unwrap();
        let _pj_uri = pj_uri.check_pj_supported().expect("Bad Uri");
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

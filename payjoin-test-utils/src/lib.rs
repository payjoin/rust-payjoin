use std::time::Duration;

use bitcoincore_rpc::bitcoin::Amount;
use bitcoincore_rpc::json::AddressType;
use bitcoincore_rpc::RpcApi;
use testcontainers::clients::Cli;
use testcontainers_modules::redis::Redis;

type Error = Box<dyn std::error::Error + 'static>;

pub fn init_bitcoind() -> Result<bitcoind::BitcoinD, Error> {
    let bitcoind_exe = std::env::var("BITCOIND_EXE")
        .ok()
        .or_else(|| bitcoind::downloaded_exe_path().ok())
        .unwrap();
    let mut conf = bitcoind::Conf::default();
    conf.view_stdout = log::log_enabled!(log::Level::Debug);
    let bitcoind = bitcoind::BitcoinD::with_conf(bitcoind_exe, &conf)?;
    Ok(bitcoind)
}

pub fn init_bitcoind_sender_receiver(
    sender_address_type: Option<AddressType>,
    receiver_address_type: Option<AddressType>,
) -> Result<(bitcoind::BitcoinD, bitcoincore_rpc::Client, bitcoincore_rpc::Client), Error> {
    let bitcoind = init_bitcoind()?;
    let receiver = bitcoind.create_wallet("receiver")?;
    let receiver_address = receiver.get_new_address(None, receiver_address_type)?.assume_checked();
    let sender = bitcoind.create_wallet("sender")?;
    let sender_address = sender.get_new_address(None, sender_address_type)?.assume_checked();
    bitcoind.client.generate_to_address(1, &receiver_address)?;
    bitcoind.client.generate_to_address(101, &sender_address)?;

    assert_eq!(
        Amount::from_btc(50.0)?,
        receiver.get_balances()?.mine.trusted,
        "receiver doesn't own bitcoin"
    );

    assert_eq!(
        Amount::from_btc(50.0)?,
        sender.get_balances()?.mine.trusted,
        "sender doesn't own bitcoin"
    );
    Ok((bitcoind, sender, receiver))
}

pub async fn init_directory(port: u16, local_cert_key: (Vec<u8>, Vec<u8>)) -> Result<(), Error> {
    let docker: Cli = Cli::default();
    let timeout = Duration::from_secs(2);
    let db = docker.run(Redis);
    let db_host = format!("127.0.0.1:{}", db.get_host_port_ipv4(6379));
    println!("Database running on {}", db.get_host_port_ipv4(6379));
    payjoin_directory::listen_tcp_with_tls(port, db_host, timeout, local_cert_key).await
}

pub async fn init_ohttp_relay(
    port: u16,
    gateway_origin: http::Uri,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    ohttp_relay::listen_tcp(port, gateway_origin).await
}

// generates or gets a DER encoded localhost cert and key.
pub fn local_cert_key() -> (Vec<u8>, Vec<u8>) {
    let cert =
        rcgen::generate_simple_self_signed(vec!["0.0.0.0".to_string(), "localhost".to_string()])
            .expect("Failed to generate cert");
    let cert_der = cert.serialize_der().expect("Failed to serialize cert");
    let key_der = cert.serialize_private_key_der();
    (cert_der, key_der)
}

pub fn find_free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

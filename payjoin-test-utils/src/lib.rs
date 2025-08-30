use std::env;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::result::Result;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::{Amount, Psbt};
use bitcoind::bitcoincore_rpc::json::AddressType;
use bitcoind::bitcoincore_rpc::{self, RpcApi};
use http::StatusCode;
use ohttp::hpke::{Aead, Kdf, Kem};
use ohttp::{KeyId, SymmetricSuite};
use once_cell::sync::{Lazy, OnceCell};
use payjoin::io::{fetch_ohttp_keys_with_cert, Error as IOError};
use payjoin::OhttpKeys;
use rcgen::Certificate;
use reqwest::{Client, ClientBuilder};
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;
use testcontainers_modules::redis::{Redis, REDIS_PORT};
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ContainerAsync;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::Level;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use url::Url;

pub type BoxError = Box<dyn std::error::Error + 'static>;
pub type BoxSendSyncError = Box<dyn std::error::Error + Send + Sync>;

pub use payjoin::persist::test_utils::InMemoryTestPersister;
pub use payjoin::persist::SessionPersister;

static INIT_TRACING: OnceCell<()> = OnceCell::new();

pub fn init_tracing() {
    INIT_TRACING.get_or_init(|| {
        let subscriber = FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env())
            .with_test_writer()
            .finish();

        tracing::subscriber::set_global_default(subscriber)
            .expect("failed to set global default subscriber");
    });
}

pub struct TestServices {
    cert: Certificate,
    /// redis is an implicit dependency of the directory service
    #[allow(dead_code)]
    redis: (u16, ContainerAsync<Redis>),
    directory: (u16, Option<JoinHandle<Result<(), BoxSendSyncError>>>),
    ohttp_relay: (u16, Option<JoinHandle<Result<(), BoxSendSyncError>>>),
    http_agent: Arc<Client>,
}

impl TestServices {
    pub async fn initialize() -> Result<Self, BoxSendSyncError> {
        // TODO add a UUID, and cleanup guard to delete after on successful run
        let cert = local_cert_key();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();
        let cert_key = (cert_der.clone(), key_der);

        let mut root_store = RootCertStore::empty();
        root_store.add(CertificateDer::from(cert.cert.der().to_vec())).unwrap();

        let redis = init_redis().await;
        let db_host = format!("127.0.0.1:{}", redis.0);
        let directory = init_directory(db_host, cert_key).await?;
        let gateway_origin =
            ohttp_relay::GatewayUri::from_str(&format!("https://localhost:{}", directory.0))?;
        let ohttp_relay = ohttp_relay::listen_tcp_on_free_port(gateway_origin, root_store).await?;
        let http_agent: Arc<Client> = Arc::new(http_agent(cert_der)?);

        Ok(Self {
            cert: cert.cert,
            redis,
            directory: (directory.0, Some(directory.1)),
            ohttp_relay: (ohttp_relay.0, Some(ohttp_relay.1)),
            http_agent,
        })
    }

    pub fn cert(&self) -> Vec<u8> { self.cert.der().to_vec() }

    pub fn directory_url(&self) -> Url {
        Url::parse(&format!("https://localhost:{}", self.directory.0)).expect("invalid URL")
    }

    pub fn take_directory_handle(&mut self) -> JoinHandle<Result<(), BoxSendSyncError>> {
        self.directory.1.take().expect("directory handle not found")
    }

    pub fn ohttp_relay_url(&self) -> Url {
        Url::parse(&format!("http://localhost:{}", self.ohttp_relay.0)).expect("invalid URL")
    }

    pub fn ohttp_gateway_url(&self) -> Url {
        let url = self.directory_url();
        url.join("/.well-known/ohttp-gateway").expect("invalid URL")
    }

    pub fn take_ohttp_relay_handle(&mut self) -> JoinHandle<Result<(), BoxSendSyncError>> {
        self.ohttp_relay.1.take().expect("ohttp relay handle not found")
    }

    pub fn http_agent(&self) -> Arc<Client> { self.http_agent.clone() }

    pub async fn wait_for_services_ready(&self) -> Result<(), &'static str> {
        wait_for_service_ready(self.ohttp_relay_url(), self.http_agent()).await?;
        wait_for_service_ready(self.directory_url(), self.http_agent()).await?;
        Ok(())
    }

    pub async fn fetch_ohttp_keys(&self) -> Result<OhttpKeys, IOError> {
        fetch_ohttp_keys_with_cert(self.ohttp_relay_url(), self.directory_url(), self.cert()).await
    }
}

pub async fn init_redis() -> (u16, ContainerAsync<Redis>) {
    let redis_instance = Redis::default().start().await.expect("redis container should start");
    let host_port = redis_instance
        .get_host_port_ipv4(REDIS_PORT)
        .await
        .expect("redis instance should have port");
    (host_port, redis_instance)
}

pub async fn init_directory(
    db_host: String,
    local_cert_key: (Vec<u8>, Vec<u8>),
) -> std::result::Result<
    (u16, tokio::task::JoinHandle<std::result::Result<(), BoxSendSyncError>>),
    BoxSendSyncError,
> {
    let timeout = Duration::from_secs(2);
    let ohttp_server = payjoin_directory::gen_ohttp_server_config()?;

    println!("Database running on {db_host}");
    let db = payjoin_directory::DbPool::new(timeout, db_host).await?;
    let metrics = payjoin_directory::metrics::Metrics::new();
    let service = payjoin_directory::Service::new(db, ohttp_server.into(), metrics);

    let listener = bind_free_port().await?;
    let port = listener.local_addr()?.port();

    let handle = tokio::spawn(service.serve_tls(listener, local_cert_key));

    Ok((port, handle))
}

async fn bind_free_port() -> Result<tokio::net::TcpListener, std::io::Error> {
    let bind_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    TcpListener::bind(bind_addr).await
}

/// generate or get a DER encoded localhost cert and key.
pub fn local_cert_key() -> rcgen::CertifiedKey<rcgen::KeyPair> {
    rcgen::generate_simple_self_signed(vec!["0.0.0.0".to_string(), "localhost".to_string()])
        .expect("Failed to generate cert")
}

pub fn init_bitcoind() -> Result<bitcoind::BitcoinD, BoxError> {
    let bitcoind_exe = env::var("BITCOIND_EXE")
        .ok()
        .or_else(|| bitcoind::downloaded_exe_path().ok())
        .expect("bitcoind not found");
    let mut conf = bitcoind::Conf::default();
    conf.view_stdout = tracing::enabled!(target: "bitcoind", Level::TRACE);
    let bitcoind = bitcoind::BitcoinD::with_conf(bitcoind_exe, &conf)?;
    Ok(bitcoind)
}

pub fn init_bitcoind_sender_receiver(
    sender_address_type: Option<AddressType>,
    receiver_address_type: Option<AddressType>,
) -> Result<(bitcoind::BitcoinD, bitcoincore_rpc::Client, bitcoincore_rpc::Client), BoxError> {
    let bitcoind = init_bitcoind()?;
    let mut wallets = create_and_fund_wallets(
        &bitcoind,
        vec![("receiver", receiver_address_type), ("sender", sender_address_type)],
    )?;
    let receiver = wallets.pop().expect("receiver to exist");
    let sender = wallets.pop().expect("sender to exist");

    Ok((bitcoind, receiver, sender))
}

fn create_and_fund_wallets<W: AsRef<str>>(
    bitcoind: &bitcoind::BitcoinD,
    wallets: Vec<(W, Option<AddressType>)>,
) -> Result<Vec<bitcoincore_rpc::Client>, BoxError> {
    let mut funded_wallets = vec![];
    let funding_wallet = bitcoind.create_wallet("funding_wallet")?;
    let funding_address = funding_wallet.get_new_address(None, None)?.assume_checked();
    // 100 blocks would work here, we add a extra block to cover fees between transfers
    bitcoind.client.generate_to_address(101 + wallets.len() as u64, &funding_address)?;
    for (wallet_name, address_type) in wallets {
        let wallet = bitcoind.create_wallet(wallet_name)?;
        let address = wallet.get_new_address(None, address_type)?.assume_checked();
        funding_wallet.send_to_address(
            &address,
            Amount::from_btc(50.0)?,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;
        funded_wallets.push(wallet);
    }
    // Mine the block which funds the different wallets
    bitcoind.client.generate_to_address(1, &funding_address)?;

    for wallet in funded_wallets.iter() {
        let balances = wallet.get_balances()?;
        assert_eq!(
            balances.mine.trusted,
            Amount::from_btc(50.0)?,
            "wallet doesn't have expected amount of bitcoin"
        );
    }

    Ok(funded_wallets)
}

pub fn http_agent(cert_der: Vec<u8>) -> Result<Client, BoxSendSyncError> {
    Ok(http_agent_builder(cert_der).build()?)
}

pub fn init_bitcoind_multi_sender_single_reciever(
    number_of_senders: usize,
) -> Result<(bitcoind::BitcoinD, Vec<bitcoincore_rpc::Client>, bitcoincore_rpc::Client), BoxError> {
    let bitcoind = init_bitcoind()?;
    let wallets_to_create =
        (0..number_of_senders + 1).map(|i| (format!("sender_{i}"), None)).collect::<Vec<_>>();
    let mut wallets = create_and_fund_wallets(&bitcoind, wallets_to_create)?;
    let receiver = wallets.pop().expect("receiver to exist");
    let senders = wallets;

    Ok((bitcoind, senders, receiver))
}

fn http_agent_builder(cert_der: Vec<u8>) -> ClientBuilder {
    ClientBuilder::new().use_rustls_tls().add_root_certificate(
        reqwest::tls::Certificate::from_der(cert_der.as_slice())
            .expect("cert_der should be a valid DER-encoded certificate"),
    )
}

const TESTS_TIMEOUT: Duration = Duration::from_secs(20);
const WAIT_SERVICE_INTERVAL: Duration = Duration::from_secs(3);

pub async fn wait_for_service_ready(
    service_url: Url,
    agent: Arc<Client>,
) -> Result<(), &'static str> {
    let health_url = service_url.join("/health").map_err(|_| "Invalid URL")?;
    let start = std::time::Instant::now();

    while start.elapsed() < TESTS_TIMEOUT {
        let request_result =
            agent.get(health_url.as_str()).send().await.map_err(|_| "Bad request")?;
        match request_result.status() {
            StatusCode::OK => return Ok(()),
            StatusCode::NOT_FOUND => return Err("Endpoint not found"),
            _ => std::thread::sleep(WAIT_SERVICE_INTERVAL),
        }
    }

    Err("Timeout waiting for service to be ready")
}

pub static EXAMPLE_URL: Lazy<Url> =
    Lazy::new(|| Url::parse("https://example.com").expect("invalid URL"));

pub const KEY_ID: KeyId = 1;
pub const KEM: Kem = Kem::K256Sha256;
pub const SYMMETRIC: &[SymmetricSuite] =
    &[ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];

// https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#user-content-span_idtestvectorsspanTest_vectors
// | InputScriptType | Original PSBT Fee rate | maxadditionalfeecontribution | additionalfeeoutputindex|
// |-----------------|-----------------------|------------------------------|-------------------------|
// | P2SH-P2WPKH     |  2 sat/vbyte          | 0.00000182                   | 0                       |

pub const QUERY_PARAMS: &str = "maxadditionalfeecontribution=182&additionalfeeoutputindex=0";

/// From the BIP-78 test vector
pub const ORIGINAL_PSBT: &str = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";

/// From the BIP-174 test vector
pub const INVALID_PSBT: &str = "AgAAAAEmgXE3Ht/yhek3re6ks3t4AAwFZsuzrWRkFxPKQhcb9gAAAABqRzBEAiBwsiRRI+a/R01gxbUMBD1MaRpdJDXwmjSnZiqdwlF5CgIgATKcqdrPKAvfMHQOwDkEIkIsgctFg5RXrrdvwS7dlbMBIQJlfRGNM1e44PTCzUbbezn22cONmnCry5st5dyNv+TOMf7///8C09/1BQAAAAAZdqkU0MWZA8W6woaHYOkP1SGkZlqnZSCIrADh9QUAAAAAF6kUNUXm4zuDLEcFDyTT7rk8nAOUi8eHsy4TAA&#61;&#61;";

/// From the BIP-78 test vector
pub const PAYJOIN_PROPOSAL: &str = "cHNidP8BAJwCAAAAAo8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////jye60aAl3JgZdaIERvjkeh72VYZuTGH/ps2I4l0IO4MBAAAAAP7///8CJpW4BQAAAAAXqRQd6EnwadJ0FQ46/q6NcutaawlEMIcACT0AAAAAABepFHdAltvPSGdDwi9DR+m0af6+i2d6h9MAAAAAAQEgqBvXBQAAAAAXqRTeTh6QYcpZE1sDWtXm1HmQRUNU0IcAAQEggIQeAAAAAAAXqRTI8sv5ymFHLIjkZNRrNXSEXZHY1YcBBxcWABRfgGZV5ZJMkgTC1RvlOU9L+e2iEAEIawJHMEQCIGe7e0DfJaVPRYEKWxddL2Pr0G37BoKz0lyNa02O2/tWAiB7ZVgBoF4s8MHocYWWmo4Q1cyV2wl7MX0azlqa8NBENAEhAmXWPPW0G3yE3HajBOb7gO7iKzHSmZ0o0w0iONowcV+tAAAA";

/// From the BIP-78 test vector
pub const PAYJOIN_PROPOSAL_WITH_SENDER_INFO: &str = "cHNidP8BAJwCAAAAAo8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////jye60aAl3JgZdaIERvjkeh72VYZuTGH/ps2I4l0IO4MBAAAAAP7///8CJpW4BQAAAAAXqRQd6EnwadJ0FQ46/q6NcutaawlEMIcACT0AAAAAABepFHdAltvPSGdDwi9DR+m0af6+i2d6h9MAAAAAAQEgqBvXBQAAAAAXqRTeTh6QYcpZE1sDWtXm1HmQRUNU0IcBBBYAFMeKRXJTVYKNVlgHTdUmDV/LaYUwIgYDFZrAGqDVh1TEtNi300ntHt/PCzYrT2tVEGcjooWPhRYYSFzWUDEAAIABAACAAAAAgAEAAAAAAAAAAAEBIICEHgAAAAAAF6kUyPLL+cphRyyI5GTUazV0hF2R2NWHAQcXFgAUX4BmVeWSTJIEwtUb5TlPS/ntohABCGsCRzBEAiBnu3tA3yWlT0WBClsXXS9j69Bt+waCs9JcjWtNjtv7VgIge2VYAaBeLPDB6HGFlpqOENXMldsJezF9Gs5amvDQRDQBIQJl1jz1tBt8hNx2owTm+4Du4isx0pmdKNMNIjjaMHFfrQABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUIgICygvBWB5prpfx61y1HDAwo37kYP3YRJBvAjtunBAur3wYSFzWUDEAAIABAACAAAAAgAEAAAABAAAAAAA=";

/// Input contribution for the receiver, from the BIP78 test vector
pub const RECEIVER_INPUT_CONTRIBUTION: &str = "cHNidP8BAJwCAAAAAo8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////jye60aAl3JgZdaIERvjkeh72VYZuTGH/ps2I4l0IO4MBAAAAAP7///8CJpW4BQAAAAAXqRQd6EnwadJ0FQ46/q6NcutaawlEMIcACT0AAAAAABepFHdAltvPSGdDwi9DR+m0af6+i2d6h9MAAAAAAAEBIICEHgAAAAAAF6kUyPLL+cphRyyI5GTUazV0hF2R2NWHAQcXFgAUX4BmVeWSTJIEwtUb5TlPS/ntohABCGsCRzBEAiBnu3tA3yWlT0WBClsXXS9j69Bt+waCs9JcjWtNjtv7VgIge2VYAaBeLPDB6HGFlpqOENXMldsJezF9Gs5amvDQRDQBIQJl1jz1tBt8hNx2owTm+4Du4isx0pmdKNMNIjjaMHFfrQAAAA==";

pub static PARSED_ORIGINAL_PSBT: Lazy<Psbt> =
    Lazy::new(|| Psbt::from_str(ORIGINAL_PSBT).expect("known psbt should parse"));

pub static PARSED_PAYJOIN_PROPOSAL: Lazy<Psbt> =
    Lazy::new(|| Psbt::from_str(PAYJOIN_PROPOSAL).expect("known psbt should parse"));

pub static PARSED_PAYJOIN_PROPOSAL_WITH_SENDER_INFO: Lazy<Psbt> = Lazy::new(|| {
    Psbt::from_str(PAYJOIN_PROPOSAL_WITH_SENDER_INFO).expect("known psbt should parse")
});

pub const MULTIPARTY_ORIGINAL_PSBT_ONE: &str = "cHNidP8BAMMCAAAAA9cTcqYjSnJdteUn3Re12vFuVb5xPypYheHze74WBW8EAAAAAAD+////6JHS6JgYdav7tr+Q5bWk95C2aA4AudqZnjeRF0hx33gBAAAAAP7///+d/1mRjJ6snVe9o0EfMM8bIExdlwfaig1j/JnUupqIWwAAAAAA/v///wJO4wtUAgAAABYAFGAEc6cWf7z5a97Xxulg+S7JZyg/kvEFKgEAAAAWABQexWFsGEdXxYNTJLJ1qBCO0nXELwAAAAAAAQCaAgAAAAKa/zFrWjicRDNVCehGj/2jdXGKuZLMzLNUo+uj7PBW8wAAAAAA/v///4HkRlmU9FA3sHckkCQMjGrabNpgAw37XaqUItNFjR5rAAAAAAD+////AgDyBSoBAAAAFgAUGPI/E9xCHmaL6DIsjkaD8LX2mpLg6QUqAQAAABYAFH6MyygysrAmk/nunEFuGGDLf244aAAAAAEBHwDyBSoBAAAAFgAUGPI/E9xCHmaL6DIsjkaD8LX2mpIBCGsCRzBEAiBLJUhV7tja6FdELXDcB6Q3Gd+BMBpkjdHpj3DLnbL6AAIgJmFl3kpWBzkO8yDDl73BMMalSlAOQvfY+hqFRos5DhQBIQLfeq7CCftNEUHcRLZniJOqcgKZEqPc1A40BnEiZHj3FQABAJoCAAAAAp3/WZGMnqydV72jQR8wzxsgTF2XB9qKDWP8mdS6mohbAQAAAAD+////1xNypiNKcl215SfdF7Xa8W5VvnE/KliF4fN7vhYFbwQBAAAAAP7///8CoNkFKgEAAAAWABQchAe9uxzqT1EjLx4jgx9u1Mn6QADyBSoBAAAAFgAUye8yXWX0MvouXYhAFb06xX5kADpoAAAAAQEfAPIFKgEAAAAWABTJ7zJdZfQy+i5diEAVvTrFfmQAOgEIawJHMEQCIF7ihY/YtUPUTOaEdJbg0/HiwKunK398BI67/LknPGqMAiBHBXmL6gTP8PxEGeWswk6T0tCI2Gvwq1zh+wd7h8QCWAEhApM0w2WFlw0eg64Zp3PeyRmxl/7WGHUED8Ul/aX1FiTBAAAAAA==";

pub const MULTIPARTY_ORIGINAL_PSBT_TWO: &str = "cHNidP8BAMMCAAAAA9cTcqYjSnJdteUn3Re12vFuVb5xPypYheHze74WBW8EAAAAAAD+////6JHS6JgYdav7tr+Q5bWk95C2aA4AudqZnjeRF0hx33gBAAAAAP7///+d/1mRjJ6snVe9o0EfMM8bIExdlwfaig1j/JnUupqIWwAAAAAA/v///wJO4wtUAgAAABYAFGAEc6cWf7z5a97Xxulg+S7JZyg/kvEFKgEAAAAWABQexWFsGEdXxYNTJLJ1qBCO0nXELwAAAAAAAAEAmgIAAAACnf9ZkYyerJ1XvaNBHzDPGyBMXZcH2ooNY/yZ1LqaiFsBAAAAAP7////XE3KmI0pyXbXlJ90XtdrxblW+cT8qWIXh83u+FgVvBAEAAAAA/v///wKg2QUqAQAAABYAFByEB727HOpPUSMvHiODH27UyfpAAPIFKgEAAAAWABTJ7zJdZfQy+i5diEAVvTrFfmQAOmgAAAABAR8A8gUqAQAAABYAFMnvMl1l9DL6Ll2IQBW9OsV+ZAA6AQhrAkcwRAIgXuKFj9i1Q9RM5oR0luDT8eLAq6crf3wEjrv8uSc8aowCIEcFeYvqBM/w/EQZ5azCTpPS0IjYa/CrXOH7B3uHxAJYASECkzTDZYWXDR6Drhmnc97JGbGX/tYYdQQPxSX9pfUWJMEAAQCaAgAAAAIKOB8lY4eoEupDnxviz0/nAuR2biNFKbdkvckiW5ioPAAAAAAA/v///w0g/mj67592vy29xhnZMGeVtEXN1jD4lU/SMZM8oStqAAAAAAD+////AgDyBSoBAAAAFgAUC3r4YzVSpsWp3knMxbgWIx2R36/g6QUqAQAAABYAFMGlw3hwcx1b+KQGWIfOUxzwrwWkaAAAAAEBHwDyBSoBAAAAFgAUC3r4YzVSpsWp3knMxbgWIx2R368BCGsCRzBEAiA//JH+jonzbzqnKI0Uti16iJcdsXI+6Zu0IAZKlOq6AwIgP0XawCCH73uXKilFqSXQQQrBvmi/Sx44D/A+/MQ/mJYBIQIekOyEpJKpFQd7eHuY6Vt4Qlf0+00Wp529I23hl/EpcQAAAA==";

/// sha256d of the empty string
#[rustfmt::skip]
pub const DUMMY32: [u8; 32] = [
    0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3,
    0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29, 0x9f, 0xcc,
    0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4,
    0x3e, 0x41, 0x98, 0x3f, 0x5d, 0x4c, 0x94, 0x56,
];
/// hash160 of the empty string
#[rustfmt::skip]
pub const DUMMY20: [u8; 20] = [
    0xb4, 0x72, 0xa2, 0x66, 0xd0, 0xbd, 0x89, 0xc1, 0x37, 0x06,
    0xa4, 0x13, 0x2c, 0xcf, 0xb1, 0x6f, 0x7c, 0x3b, 0x9f, 0xcb,
];

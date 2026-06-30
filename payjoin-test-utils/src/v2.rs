use std::result::Result;
use std::sync::Arc;
use std::time::Duration;

type RelayEntry = (u16, Option<JoinHandle<Result<(), BoxSendSyncError>>>);

use axum_server::tls_rustls::RustlsConfig;
use http::StatusCode;
use ohttp::hpke::{Aead, Kdf, Kem};
use ohttp::{KeyId, SymmetricSuite};
use payjoin::io::{fetch_ohttp_keys_with_cert, Error as IOError};
pub use payjoin::persist::{InMemoryPersister, SessionPersister};
use payjoin::OhttpKeys;
use rcgen::Certificate;
use reqwest::{Client, ClientBuilder};
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;
use tempfile::tempdir;
use tokio::task::JoinHandle;

use crate::BoxSendSyncError;

pub struct TestServices {
    cert: Certificate,
    directory: (u16, Option<JoinHandle<Result<(), BoxSendSyncError>>>),
    ohttp_relays: Vec<RelayEntry>,
    http_agent: Arc<Client>,
}

impl TestServices {
    pub async fn initialize() -> Result<Self, BoxSendSyncError> {
        Self::initialize_with_relays(2).await
    }

    pub async fn initialize_with_relays(num_relays: u8) -> Result<Self, BoxSendSyncError> {
        // TODO add a UUID, and cleanup guard to delete after on successful run
        let cert = local_cert_key();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();
        let cert_key = (cert_der.clone(), key_der);

        let mut root_store = RootCertStore::empty();
        root_store.add(CertificateDer::from(cert.cert.der().to_vec())).unwrap();

        let directory = init_directory(cert_key, root_store.clone()).await?;

        let mut ohttp_relays = Vec::with_capacity(num_relays as usize);
        for _ in 0..num_relays {
            let relay = init_ohttp_relay(root_store.clone(), None).await?;
            ohttp_relays.push((relay.0, Some(relay.1)));
        }

        let http_agent: Arc<Client> = Arc::new(http_agent(cert_der)?);

        Ok(Self {
            cert: cert.cert,
            directory: (directory.0, Some(directory.1)),
            ohttp_relays,
            http_agent,
        })
    }

    pub fn cert(&self) -> Vec<u8> { self.cert.der().to_vec() }

    pub fn directory_url(&self) -> String { format!("https://localhost:{}", self.directory.0) }

    pub fn take_directory_handle(&mut self) -> JoinHandle<Result<(), BoxSendSyncError>> {
        self.directory.1.take().expect("directory handle not found")
    }

    pub fn ohttp_relay_url(&self) -> String {
        format!("http://localhost:{}", self.ohttp_relays[0].0)
    }

    pub fn ohttp_relay_urls(&self) -> String {
        self.ohttp_relays
            .iter()
            .map(|r| format!("http://localhost:{}", r.0))
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn ohttp_gateway_url(&self) -> String {
        format!("{}/.well-known/ohttp-gateway", self.directory_url())
    }

    pub fn take_ohttp_relay_handle(&mut self) -> JoinHandle<Result<(), BoxSendSyncError>> {
        let handles: Vec<_> = self
            .ohttp_relays
            .iter_mut()
            .map(|r| r.1.take().expect("ohttp relay handle not found"))
            .collect();
        tokio::spawn(async move {
            match futures::future::select_all(handles).await {
                (Ok(inner), _idx, _rest) => inner,
                (Err(e), _idx, _rest) => Err(e.into()),
            }
        })
    }

    pub fn http_agent(&self) -> Arc<Client> { self.http_agent.clone() }

    pub async fn wait_for_services_ready(&self) -> Result<(), &'static str> {
        for relay in &self.ohttp_relays {
            wait_for_service_ready(&format!("http://localhost:{}", relay.0), self.http_agent())
                .await?;
        }
        wait_for_service_ready(&self.directory_url(), self.http_agent()).await?;
        Ok(())
    }

    pub async fn fetch_ohttp_keys(&self) -> Result<OhttpKeys, IOError> {
        fetch_ohttp_keys_with_cert(
            self.ohttp_relay_url().as_str(),
            self.directory_url().as_str(),
            &self.cert(),
        )
        .await
    }
}

pub async fn init_directory(
    local_cert_key: (Vec<u8>, Vec<u8>),
    root_store: RootCertStore,
) -> std::result::Result<
    (u16, tokio::task::JoinHandle<std::result::Result<(), BoxSendSyncError>>),
    BoxSendSyncError,
> {
    let tempdir = tempdir()?;
    let config = payjoin_mailroom::config::Config::new(
        "[::]:0".parse().expect("valid listener address"),
        tempdir.path().to_path_buf(),
        Duration::from_secs(2),
        None,
        Some(payjoin_mailroom::config::V1Config::default()),
    );

    let tls_config = RustlsConfig::from_der(vec![local_cert_key.0], local_cert_key.1).await?;

    let (port, handle) =
        payjoin_mailroom::serve_manual_tls(config, Some(tls_config), root_store, None)
            .await
            .map_err(|e| e.to_string())?;

    let handle = tokio::spawn(async move {
        let _tempdir = tempdir; // keep the tempdir until the directory shuts down
        handle.await.map_err(|e| e.to_string())?.map_err(|e| e.to_string().into())
    });

    Ok((port, handle))
}

pub async fn init_ohttp_relay(
    root_store: RootCertStore,
    default_gateway: Option<payjoin_mailroom::ohttp_relay::GatewayUri>,
) -> std::result::Result<
    (u16, tokio::task::JoinHandle<std::result::Result<(), BoxSendSyncError>>),
    BoxSendSyncError,
> {
    let tempdir = tempdir()?;
    let config = payjoin_mailroom::config::Config::new(
        "[::]:0".parse().expect("valid listener address"),
        tempdir.path().to_path_buf(),
        Duration::from_secs(2),
        None,
        None,
    );

    let (port, handle) =
        payjoin_mailroom::serve_manual_tls(config, None, root_store, default_gateway)
            .await
            .map_err(|e| e.to_string())?;

    let handle = tokio::spawn(async move {
        let _tempdir = tempdir; // keep the tempdir until the relay shuts down
        handle.await.map_err(|e| e.to_string())?.map_err(|e| e.to_string().into())
    });

    Ok((port, handle))
}

/// generate or get a DER encoded localhost cert and key.
pub fn local_cert_key() -> rcgen::CertifiedKey<rcgen::KeyPair> {
    rcgen::generate_simple_self_signed(vec!["0.0.0.0".to_string(), "localhost".to_string()])
        .expect("Failed to generate cert")
}

pub fn http_agent(cert_der: Vec<u8>) -> Result<Client, BoxSendSyncError> {
    Ok(http_agent_builder(cert_der).build()?)
}

fn http_agent_builder(cert_der: Vec<u8>) -> ClientBuilder {
    ClientBuilder::new().http1_only().use_rustls_tls().add_root_certificate(
        reqwest::tls::Certificate::from_der(cert_der.as_slice())
            .expect("cert_der should be a valid DER-encoded certificate"),
    )
}

const TESTS_TIMEOUT: Duration = Duration::from_secs(20);
const WAIT_SERVICE_INTERVAL: Duration = Duration::from_secs(3);

pub async fn wait_for_service_ready(
    service_url: &str,
    agent: Arc<Client>,
) -> Result<(), &'static str> {
    let health_url = format!("{}/health", service_url.trim_end_matches("/"));
    let start = std::time::Instant::now();

    while start.elapsed() < TESTS_TIMEOUT {
        let request_result =
            agent.get(health_url.clone()).send().await.map_err(|_| "Bad request")?;
        match request_result.status() {
            StatusCode::OK => return Ok(()),
            StatusCode::NOT_FOUND => return Err("Endpoint not found"),
            _ => std::thread::sleep(WAIT_SERVICE_INTERVAL),
        }
    }

    Err("Timeout waiting for service to be ready")
}

pub const KEY_ID: KeyId = 1;
pub const KEM: Kem = Kem::K256Sha256;
pub const SYMMETRIC: &[SymmetricSuite] =
    &[ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];

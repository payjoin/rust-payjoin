pub use error::IoError;

use crate::ohttp::OhttpKeys;

pub mod error {
    #[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Object)]
    #[error("IO error: {message}")]
    pub struct IoError {
        message: String,
    }
    impl From<payjoin::io::Error> for IoError {
        fn from(value: payjoin::io::Error) -> Self { IoError { message: format!("{value:?}") } }
    }
}

/// Fetch the ohttp keys from the specified payjoin directory via proxy.
///
/// * `ohttp_relay`: The http CONNECT method proxy to request the ohttp keys from a payjoin
///   directory.  Proxying requests for ohttp keys ensures a client IP address is never revealed to
///   the payjoin directory.
///
/// * `payjoin_directory`: The payjoin directory from which to fetch the ohttp keys.  This
///   directory stores and forwards payjoin client payloads.
pub async fn fetch_ohttp_keys(
    ohttp_relay: &str,
    payjoin_directory: &str,
) -> Result<OhttpKeys, IoError> {
    payjoin::io::fetch_ohttp_keys(ohttp_relay, payjoin_directory)
        .await
        .map(|e| e.into())
        .map_err(|e| e.into())
}

/// Fetch the ohttp keys from the specified payjoin directory via proxy.
///
/// * `ohttp_relay`: The http CONNECT method proxy to request the ohttp keys from a payjoin
///   directory.  Proxying requests for ohttp keys ensures a client IP address is never revealed to
///   the payjoin directory.
///
/// * `payjoin_directory`: The payjoin directory from which to fetch the ohttp keys.  This
///   directory stores and forwards payjoin client payloads.
///
/// * `cert_der`: The DER-encoded certificate to use for local HTTPS connections.
#[cfg(feature = "_manual-tls")]
pub async fn fetch_ohttp_keys_with_cert(
    ohttp_relay: &str,
    payjoin_directory: &str,
    cert_der: Vec<u8>,
) -> Result<OhttpKeys, IoError> {
    payjoin::io::fetch_ohttp_keys_with_cert(ohttp_relay, payjoin_directory, cert_der)
        .await
        .map(|e| e.into())
        .map_err(|e| e.into())
}

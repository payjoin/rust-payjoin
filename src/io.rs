use crate::error::PayjoinError;
use crate::ohttp::OhttpKeys;

/// Fetch the ohttp keys from the specified payjoin directory via proxy.
///
/// * `ohttp_relay`: The http CONNNECT method proxy to request the ohttp keys from a payjoin
///   directory.  Proxying requests for ohttp keys ensures a client IP address is never revealed to
///   the payjoin directory.
///
/// * `payjoin_directory`: The payjoin directory from which to fetch the ohttp keys.  This
///   directory stores and forwards payjoin client payloads.
pub async fn fetch_ohttp_keys(
    ohttp_relay: &str,
    payjoin_directory: &str,
) -> Result<OhttpKeys, PayjoinError> {
    payjoin::io::fetch_ohttp_keys(ohttp_relay, payjoin_directory)
        .await
        .map(|e| e.into())
        .map_err(|e| e.into())
}

/// Fetch the ohttp keys from the specified payjoin directory via proxy.
///
/// * `ohttp_relay`: The http CONNNECT method proxy to request the ohttp keys from a payjoin
///   directory.  Proxying requests for ohttp keys ensures a client IP address is never revealed to
///   the payjoin directory.
///
/// * `payjoin_directory`: The payjoin directory from which to fetch the ohttp keys.  This
///   directory stores and forwards payjoin client payloads.
///
/// * `cert_der`: The DER-encoded certificate to use for local HTTPS connections.
#[cfg(feature = "_danger-local-https")]
pub async fn fetch_ohttp_keys_with_cert(
    ohttp_relay: &str,
    payjoin_directory: &str,
    cert_der: Vec<u8>,
) -> Result<OhttpKeys, PayjoinError> {
    payjoin::io::fetch_ohttp_keys_with_cert(ohttp_relay, payjoin_directory, cert_der)
        .await
        .map(|e| e.into())
        .map_err(|e| e.into())
}

use crate::error::PayjoinError;
use crate::types::OhttpKeys;
use crate::uri::Url;

/// Fetch the ohttp keys from the specified payjoin directory via proxy.
///
/// * `ohttp_relay`: The http CONNNECT method proxy to request the ohttp keys from a payjoin
/// directory.  Proxying requests for ohttp keys ensures a client IP address is never revealed to
/// the payjoin directory.
///
/// * `payjoin_directory`: The payjoin directory from which to fetch the ohttp keys.  This
/// directory stores and forwards payjoin client payloads.
///
/// * `cert_der` (optional): The DER-encoded certificate to use for local HTTPS connections.  This
/// parameter is only available when the "danger-local-https" feature is enabled.
pub async fn fetch_ohttp_keys(
    ohttp_relay: Url,
    payjoin_directory: Url,
     cert_der: Vec<u8>,
) -> Result<OhttpKeys, PayjoinError> {
    payjoin::io::fetch_ohttp_keys(ohttp_relay.into(), payjoin_directory.into(), cert_der).await
        .map(|e| e.into())
        .map_err(|e| e.into())
}
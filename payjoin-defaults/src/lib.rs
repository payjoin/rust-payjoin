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
#[cfg(feature = "v2")]
pub async fn fetch_ohttp_keys(
    ohttp_relay: payjoin::Url,
    payjoin_directory: payjoin::Url,
    #[cfg(feature = "danger-local-https")] cert_der: Vec<u8>,
) -> Result<payjoin::OhttpKeys, Error> {
    let ohttp_keys_url = payjoin_directory.join("/ohttp-keys")?;
    let proxy = reqwest::Proxy::all(ohttp_relay.as_str())?;
    #[cfg(not(feature = "danger-local-https"))]
    let client = reqwest::Client::builder().proxy(proxy).build()?;
    #[cfg(feature = "danger-local-https")]
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .use_rustls_tls()
        .add_root_certificate(reqwest::tls::Certificate::from_der(cert_der.as_slice())?)
        .proxy(proxy)
        .build()?;
    let res = client.get(ohttp_keys_url).send().await?;
    let body = res.bytes().await?.to_vec();
    payjoin::OhttpKeys::decode(body.as_slice())
        .map_err(|e| Error(InternalError::InvalidOhttpKeys(e.to_string())))
}

#[derive(Debug)]
pub struct Error(InternalError);

#[derive(Debug)]
enum InternalError {
    ParseUrl(payjoin::ParseError),
    Reqwest(reqwest::Error),
    Io(std::io::Error),
    #[cfg(feature = "danger-local-https")]
    Rustls(rustls::Error),
    #[cfg(feature = "v2")]
    InvalidOhttpKeys(String),
}

macro_rules! impl_from_error {
    ($from:ty, $to:ident) => {
        impl From<$from> for Error {
            fn from(value: $from) -> Self { Self(InternalError::$to(value)) }
        }
    };
}

impl_from_error!(reqwest::Error, Reqwest);
impl_from_error!(payjoin::ParseError, ParseUrl);
impl_from_error!(std::io::Error, Io);
#[cfg(feature = "danger-local-https")]
impl_from_error!(rustls::Error, Rustls);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use InternalError::*;

        match &self.0 {
            Reqwest(e) => e.fmt(f),
            ParseUrl(e) => e.fmt(f),
            Io(e) => e.fmt(f),
            #[cfg(feature = "v2")]
            InvalidOhttpKeys(e) => {
                write!(f, "Invalid ohttp keys returned from payjoin directory: {}", e)
            }
            #[cfg(feature = "danger-local-https")]
            Rustls(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalError::*;

        match &self.0 {
            Reqwest(e) => Some(e),
            ParseUrl(e) => Some(e),
            Io(e) => Some(e),
            #[cfg(feature = "v2")]
            InvalidOhttpKeys(_) => None,
            #[cfg(feature = "danger-local-https")]
            Rustls(e) => Some(e),
        }
    }
}

impl From<InternalError> for Error {
    fn from(value: InternalError) -> Self { Self(value) }
}

#[cfg(test)]
mod tests {

    #[cfg(feature = "v2")]
    #[tokio::test]
    async fn test_fetch_ohttp_keys() {
        use payjoin;

        use super::fetch_ohttp_keys;
        let payjoin_directory = payjoin::Url::parse("https://payjo.in").unwrap();
        let payjoin_relay = payjoin::Url::parse("https://pj.bobspacebkk.com").unwrap();
        let res = fetch_ohttp_keys(payjoin_relay, payjoin_directory).await;
        assert!(res.is_ok());
    }
}

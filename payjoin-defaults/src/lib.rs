use payjoin::Url;

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
pub fn fetch_ohttp_keys(
    ohttp_relay: Url,
    payjoin_directory: Url,
    #[cfg(feature = "danger-local-https")] cert_der: Vec<u8>,
) -> Result<payjoin::OhttpKeys, Error> {
    let ohttp_keys_url = payjoin_directory.join("/ohttp-keys")?;
    let proxy = PayjoinProxy::new(
        &ohttp_relay,
        #[cfg(feature = "danger-local-https")]
        cert_der,
    )?;
    let res = proxy.get(ohttp_keys_url.as_str()).call()?;
    let mut body = Vec::new();
    let _ = res.into_reader().read_to_end(&mut body)?;
    payjoin::OhttpKeys::decode(&body)
        .map_err(|e| Error(InternalError::InvalidOhttpKeys(e.to_string())))
}

#[derive(Debug)]
pub struct Error(InternalError);

#[derive(Debug)]
enum InternalError {
    ParseUrl(payjoin::ParseError),
    Ureq(ureq::Error),
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

impl_from_error!(payjoin::ParseError, ParseUrl);
impl_from_error!(ureq::Error, Ureq);
impl_from_error!(std::io::Error, Io);
#[cfg(feature = "danger-local-https")]
impl_from_error!(rustls::Error, Rustls);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use InternalError::*;

        match &self.0 {
            ParseUrl(e) => e.fmt(f),
            Ureq(e) => e.fmt(f),
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
            ParseUrl(e) => Some(e),
            Ureq(e) => Some(e),
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

struct PayjoinProxy {
    client: ureq::Agent,
}

impl PayjoinProxy {
    fn new(
        proxy: &Url,
        #[cfg(feature = "danger-local-https")] cert_der: Vec<u8>,
    ) -> Result<Self, Error> {
        let proxy = ureq::Proxy::new(Self::normalize_proxy_url(proxy)?)?;
        #[cfg(feature = "danger-local-https")]
        let client = Self::http_agent_builder(cert_der)?.proxy(proxy).build();
        #[cfg(not(feature = "danger-local-https"))]
        let client = ureq::AgentBuilder::new().proxy(proxy).build();

        Ok(Self { client })
    }

    fn get(&self, url: &str) -> ureq::Request { self.client.get(url) }

    // Normalize the Url to include the port for ureq. ureq has a bug
    // which makes Proxy::new(...) use port 8080 for all input with scheme
    // http regardless of the port included in the Url. This prevents that.
    // https://github.com/algesten/ureq/pull/717
    fn normalize_proxy_url(proxy: &Url) -> Result<String, Error> {
        let host = match proxy.host_str() {
            Some(host) => host,
            None => return Err(Error(InternalError::ParseUrl(payjoin::ParseError::EmptyHost))),
        };
        match proxy.scheme() {
            "http" | "https" => Ok(format!("{}:{}", host, proxy.port().unwrap_or(80))),
            _ => Ok(proxy.as_str().to_string()),
        }
    }

    #[cfg(feature = "danger-local-https")]
    fn http_agent_builder(cert_der: Vec<u8>) -> Result<ureq::AgentBuilder, Error> {
        use std::sync::Arc;

        use rustls::client::ClientConfig;
        use rustls::pki_types::CertificateDer;
        use rustls::RootCertStore;
        use ureq::AgentBuilder;

        let mut root_cert_store = RootCertStore::empty();
        root_cert_store.add(CertificateDer::from(cert_der.as_slice()))?;
        let client_config =
            ClientConfig::builder().with_root_certificates(root_cert_store).with_no_client_auth();
        Ok(AgentBuilder::new().tls_config(Arc::new(client_config)))
    }
}

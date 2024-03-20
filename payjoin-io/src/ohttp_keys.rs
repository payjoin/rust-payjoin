use ohttp::KeyConfig;
use tokio::task::spawn_blocking;
use url::Url;

use crate::error::{Error, InternalError};

/// Returns the ohttp keys from a payjoin server.
///
/// `proxy_endpoint` - The proxy the user want to use when
/// requesting the ohttp keys from a payjoin server.
/// `pj_endpoint` - The payjoin server endpoint to fetch the ohttp
/// keys from.
pub async fn fetch(proxy_endpoint: Url, pj_endpoint: &Url) -> Result<KeyConfig, Error> {
    let ohttp_keys_url = pj_endpoint.join("/ohttp-keys")?;
    let res = spawn_blocking(move || {
        let proxy = match ProxyServer::new(&proxy_endpoint) {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        proxy.get(ohttp_keys_url.as_str()).call().map_err(Error::from)
    })
    .await?
    .map_err(Error::from)?;
    if res.status() != 200 {
        return Err(Error(InternalError::Ureq(ureq::Error::Status(res.status(), res))));
    }
    let mut body = Vec::new();
    let _ = res.into_reader().read_to_end(&mut body)?;
    KeyConfig::decode(&body).map_err(Error::from)
}

// Proxy server struct.
// This is used to make requests to the payjoin server.
struct ProxyServer {
    agent: ureq::Agent,
}

impl ProxyServer {
    fn new(proxy: &Url) -> Result<Self, Error> {
        let proxy = ureq::Proxy::new(Self::normalize_proxy_url(proxy)?)?;
        let agent = ureq::AgentBuilder::new().proxy(proxy).build();
        Ok(Self { agent })
    }

    fn get(&self, url: &str) -> ureq::Request { self.agent.get(url) }

    // Normalize the Url to include the port for ureq. ureq has a bug
    // which makes Proxy::new(...) use port 8080 for all input with scheme
    // http regardless of the port included in the Url. This prevents that.
    // https://github.com/algesten/ureq/pull/717
    fn normalize_proxy_url(proxy: &Url) -> Result<String, Error> {
        let host = match proxy.host_str() {
            Some(host) => host,
            None => return Err(Error(InternalError::ParseUrl(url::ParseError::EmptyHost))),
        };
        match proxy.scheme() {
            "http" | "https" => Ok(format!("{}:{}", host, proxy.port().unwrap_or(80))),
            _ => Ok(proxy.as_str().to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use http::uri::Uri;

    use super::*;

    fn find_free_port() -> u16 {
        let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    // This test depends on the production payjo.in server being live.
    #[tokio::test]
    async fn test_fetch_ohttp_keys() {
        let relay_port = find_free_port();
        let relay_url = Url::parse(&format!("http://0.0.0.0:{}", relay_port)).unwrap();
        let pj_endpoint = Url::parse("https://payjo.in:443").unwrap();
        tokio::select! {
            _ = ohttp_relay::listen_tcp(relay_port, Uri::from_static("payjo.in:443")) => {
                assert!(false, "Relay is long running");
            }
            res = fetch(relay_url, &pj_endpoint) => {
                assert!(res.is_ok());
            }
        }
    }
}

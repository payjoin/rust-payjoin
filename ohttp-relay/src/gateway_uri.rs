use std::str::FromStr;

use http::uri::{Authority, Scheme};
use http::Uri;

use crate::error::BoxError;

pub(crate) const RFC_9540_GATEWAY_PATH: &str = "/.well-known/ohttp-gateway";
const ALLOWED_PURPOSES_PATH_AND_QUERY: &str = "/.well-known/ohttp-gateway?allowed_purposes";

/// A normalized gateway origin URI with a default port if none is specified.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GatewayUri {
    scheme: Scheme,
    authority: Authority,
}

impl GatewayUri {
    pub fn new(scheme: Scheme, authority: Authority) -> Result<Self, BoxError> {
        let default_port = if scheme == Scheme::HTTP {
            80
        } else if scheme == Scheme::HTTPS {
            443
        } else {
            return Err("Unsupported URI scheme".into());
        };

        // If no explicit port is provided, make the default one explicit
        let mut authority = authority;
        if authority.port().is_none() {
            authority = Authority::from_str(&format!("{}:{}", authority.host(), default_port))
                .expect("setting default port must succeed");
        }

        Ok(Self { scheme, authority })
    }

    pub fn from_static(string: &'static str) -> Self {
        Uri::from_static(string)
            .try_into()
            .expect("gateway URI must consist of a scheme and authority only")
    }

    fn to_uri_builder(&self) -> http::uri::Builder {
        Uri::builder().scheme(self.scheme.clone()).authority(self.authority.clone())
    }

    pub fn to_uri(&self) -> Uri {
        self.to_uri_builder()
            .path_and_query("/")
            .build()
            .expect("Building Uri from scheme and authority must succeed")
    }

    pub fn rfc_9540_url(&self) -> Uri {
        self.to_uri_builder()
            .path_and_query(RFC_9540_GATEWAY_PATH)
            .build()
            .expect("building RFC 9540 uri from scheme and authority must succeed")
    }

    pub fn probe_url(&self) -> Uri {
        self.to_uri_builder()
            .path_and_query(ALLOWED_PURPOSES_PATH_AND_QUERY)
            .build()
            .expect("building RFC 9540 uri from scheme and authority must succeed")
    }

    pub async fn to_socket_addr(&self) -> std::io::Result<Option<std::net::SocketAddr>> {
        Ok(self.to_socket_addrs().await?.next())
    }

    pub async fn to_socket_addrs(
        &self,
    ) -> std::io::Result<impl Iterator<Item = std::net::SocketAddr>> {
        tokio::net::lookup_host(self.authority.to_string()).await
    }
}

impl From<GatewayUri> for Uri {
    fn from(val: GatewayUri) -> Uri { val.to_uri() }
}

impl TryFrom<Uri> for GatewayUri {
    type Error = BoxError;

    fn try_from(uri: Uri) -> Result<Self, Self::Error> {
        let parts = uri.into_parts();

        if let Some(pq) = parts.path_and_query {
            if pq.as_str() != "/" {
                return Err("URI must not contain path or query".into());
            }
        }

        let scheme = parts.scheme.ok_or::<BoxError>("URI must have a scheme".into())?;
        let authority = parts.authority.ok_or::<BoxError>("URI must have an authority".into())?;

        Self::new(scheme, authority)
    }
}

impl From<Authority> for GatewayUri {
    fn from(authority: Authority) -> Self {
        Self::new(Scheme::HTTPS, authority)
            .expect("constructing GatewayUri with valid authority must succeed")
    }
}

impl FromStr for GatewayUri {
    type Err = BoxError;
    fn from_str(string: &str) -> Result<Self, Self::Err> { Uri::from_str(string)?.try_into() }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn conversion() {
        let uri_with_port = Uri::from_static("http://payjo.in:80");
        let gateway_uri = GatewayUri::try_from(uri_with_port.clone())
            .expect("should be a valid gateway base URI");
        assert_eq!(gateway_uri.to_uri(), uri_with_port, "uri should be the same as input");

        let uri_without_port = Uri::from_static("http://payjo.in");
        let gateway_uri =
            GatewayUri::try_from(uri_without_port).expect("should be a valid gateway base URI");

        let uri: Uri = gateway_uri.clone().into();
        assert_eq!(uri, uri_with_port, "uri should be canonicalized to contain port");

        assert_eq!(
            gateway_uri.rfc_9540_url(),
            Uri::from_static("http://payjo.in:80/.well-known/ohttp-gateway"),
            "uri should be canonicalized to contain port"
        );
    }

    #[test]
    fn default_port() {
        let uri = GatewayUri::from_static("http://payjo.in");
        assert_eq!(
            uri.authority.port_u16(),
            Some(80),
            "default port should be made explicit for http scheme"
        );

        let uri = GatewayUri::from_static("https://payjo.in");
        assert_eq!(
            uri.authority.port_u16(),
            Some(443),
            "default port should be made explicit for https scheme"
        );

        let uri = GatewayUri::from_static("https://payjo.in:80");
        assert_eq!(uri.authority.port_u16(), Some(80), "explicit port should override default");

        let uri = GatewayUri::from_static("http://payjo.in:1234");
        assert_eq!(uri.authority.port_u16(), Some(1234), "explicit port should override default");
    }

    #[test]
    fn invalid_uris() {
        assert!(GatewayUri::from_str("payjo.in").is_err(), "scheme is mandatory");

        assert!(GatewayUri::from_str("/index.html").is_err(), "url must be absolute");

        assert!(
            GatewayUri::from_str("ftp://payjo.in").is_err(),
            "only http and https scheme should be allowed"
        );

        assert!(GatewayUri::from_str("http://payjo.in/blah").is_err(), "url must not contain path");
    }
}

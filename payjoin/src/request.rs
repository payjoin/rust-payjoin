use url::Url;

pub const V1_REQ_CONTENT_TYPE: &str = "text/plain";

#[cfg(feature = "v2")]
pub const V2_REQ_CONTENT_TYPE: &str = "message/ohttp-req";

/// Represents data that needs to be transmitted to the receiver or payjoin directory.
/// Ensure the `Content-Length` is set to the length of `body`. (most libraries do this automatically)
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Request {
    /// URL to send the request to.
    ///
    /// This is full URL with scheme etc - you can pass it right to `reqwest` or a similar library.
    pub url: Url,

    /// The `Content-Type` header to use for the request.
    ///
    /// `text/plain` for v1 requests and `message/ohttp-req` for v2 requests.
    pub content_type: &'static str,

    /// Bytes to be sent to the receiver.
    ///
    /// This is properly encoded PSBT payload either in base64 in v1 or an OHTTP encapsulated payload in v2.
    pub body: Vec<u8>,
}

impl Request {
    // FIXME: could be &Url and clone inside to help caller
    // FIXME: could be &[u8] and clone inside to help caller
    pub fn new_v1(url: Url, body: Vec<u8>) -> Self {
        Self { url, content_type: V1_REQ_CONTENT_TYPE, body }
    }

    // FIXME: could be &Url and clone inside to help caller
    // FIXME: could be &[u8] and clone inside to help caller
    #[cfg(feature = "v2")]
    pub fn new_v2(url: Url, body: Vec<u8>) -> Self {
        Self { url, content_type: V2_REQ_CONTENT_TYPE, body }
    }
}

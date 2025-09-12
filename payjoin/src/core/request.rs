#[cfg(feature = "v1")]
const V1_REQ_CONTENT_TYPE: &str = "text/plain";

#[cfg(feature = "v2")]
const V2_REQ_CONTENT_TYPE: &str = "message/ohttp-req";

/// Represents data that needs to be transmitted to the receiver or payjoin directory.
/// Ensure the `Content-Length` is set to the length of `body`. (most libraries do this automatically)
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Request {
    /// URL to send the request to.
    ///
    /// This is a URL string - you will need to parse it before you can pass it to `reqwest` or a similar library.
    pub url: String,

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
    /// Construct a new v1 request.
    #[cfg(feature = "v1")]
    pub(crate) fn new_v1(url: &str, body: &[u8]) -> Self {
        Self { url: url.to_string(), content_type: V1_REQ_CONTENT_TYPE, body: body.to_vec() }
    }

    /// Construct a new v2 request.
    #[cfg(feature = "v2")]
    pub(crate) fn new_v2(
        url: &str,
        body: &[u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES],
    ) -> Self {
        Self { url: url.to_string(), content_type: V2_REQ_CONTENT_TYPE, body: body.to_vec() }
    }
}

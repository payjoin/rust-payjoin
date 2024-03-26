use url::Url;

/// Represents data that needs to be transmitted to the receiver or payjoin directory.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Request {
    /// URL to send the request to.
    ///
    /// This is full URL with scheme etc - you can pass it right to `reqwest` or a similar library.
    pub url: Url,

    /// Bytes to be sent to the receiver.
    ///
    /// This is properly encoded PSBT, already in base64. You only need to make sure `Content-Type`
    /// is appropriate (`text/plain` for v1 requests and 'message/ohttp-req' for v2)
    /// and `Content-Length` is `body.len()` (most libraries do the latter automatically).
    pub body: Vec<u8>,
}

///Represents data that needs to be transmitted to the receiver.
///You need to send this request over HTTP(S) to the receiver.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Request {
    /// URL to send the request to.
    ///
    /// This is a URL string - you will need to parse it before you can pass it to `reqwest` or a similar library.
    pub url: String,

    /// The `Content-Type` header to use for the request.
    ///
    /// `text/plain` for v1 requests and `message/ohttp-req` for v2 requests.
    pub content_type: String,

    /// Bytes to be sent to the receiver.
    ///
    /// This is properly encoded PSBT payload either in base64 in v1 or an OHTTP encapsulated payload in v2.
    pub body: Vec<u8>,
}

impl From<payjoin::Request> for Request {
    fn from(value: payjoin::Request) -> Self {
        Self { url: value.url, content_type: value.content_type.to_string(), body: value.body }
    }
}

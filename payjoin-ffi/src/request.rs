///Represents data that needs to be transmitted to the receiver.
///You need to send this request over HTTP(S) to the receiver.
#[derive(Clone, Debug, uniffi::Object)]
pub struct Request {
    /// URL to send the request to.
    ///
    /// This is full URL with scheme etc - you can pass it right to `reqwest` or a similar library.
    url: String,

    /// The `Content-Type` header to use for the request.
    ///
    /// `text/plain` for v1 requests and `message/ohttp-req` for v2 requests.
    content_type: String,

    /// Bytes to be sent to the receiver.
    ///
    /// This is properly encoded PSBT payload either in base64 in v1 or an OHTTP encapsulated payload in v2.
    body: Vec<u8>,
}

impl From<payjoin::Request> for Request {
    fn from(value: payjoin::Request) -> Self {
        Self {
            url: value.url().to_string(),
            content_type: value.content_type().to_string(),
            body: value.body().to_vec(),
        }
    }
}

#[uniffi::export]
impl Request {
    pub fn url(&self) -> String { self.url.clone() }

    pub fn content_type(&self) -> String { self.content_type.clone() }

    pub fn body(&self) -> Vec<u8> { self.body.clone() }
}

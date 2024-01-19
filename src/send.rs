use std::sync::{Arc, Mutex};

pub use payjoin::send::RequestBuilder as PdkRequestBuilder;

use crate::error::PayjoinError;
use crate::transaction::PartiallySignedTransaction;
use crate::uri::{Uri, Url};

///Builder for sender-side payjoin parameters
///
///These parameters define how client wants to handle Payjoin.
pub struct RequestBuilder(PdkRequestBuilder<'static>);

impl From<PdkRequestBuilder<'static>> for RequestBuilder {
    fn from(value: PdkRequestBuilder<'static>) -> Self {
        Self(value)
    }
}

impl RequestBuilder {
    /// Prepare an HTTP request and request context to process the response
    ///
    /// An HTTP client will own the Request data while Context sticks around so
    /// a `(Request, Context)` tuple is returned from `RequestBuilder::build()`
    /// to keep them separated.
    pub fn from_psbt_and_uri(
        psbt: Arc<PartiallySignedTransaction>,
        uri: Arc<Uri>,
    ) -> Result<Self, PayjoinError> {
        match PdkRequestBuilder::from_psbt_and_uri((*psbt).clone().into(), (*uri).clone().into()) {
            Ok(e) => Ok(e.into()),
            Err(e) => Err(e.into()),
        }
    }
}

///Data required for validation of response.

///This type is used to process the response. It is returned from PjUriExt::create_pj_request() method and you only need to call .process_response() on it to continue BIP78 flow.

pub struct Context(Mutex<Option<payjoin::send::ContextV1>>);

impl Context {
    fn get_context(&self) -> Option<payjoin::send::ContextV1> {
        let mut data_guard = self.0.lock().unwrap();
        Option::take(&mut *data_guard)
    }
}

impl From<payjoin::send::ContextV1> for Context {
    fn from(value: payjoin::send::ContextV1) -> Self {
        Self(Mutex::new(Some(value)))
    }
}

///Represents data that needs to be transmitted to the receiver.

///You need to send this request over HTTP(S) to the receiver.
pub struct Request {
    ///URL to send the request to.
    ///
    ///This is full URL with scheme etc - you can pass it right to reqwest or a similar library.
    pub url: Arc<Url>,
    ///Bytes to be sent to the receiver.
    ///
    ///This is properly encoded PSBT, already in base64. You only need to make sure Content-Type is text/plain and Content-Length is body.len() (most libraries do the latter automatically).
    pub body: Vec<u8>,
}

impl From<payjoin::receive::v2::Request> for Request {
    fn from(value: payjoin::receive::v2::Request) -> Self {
        Self { url: Arc::new(value.url.into()), body: value.body }
    }
}
impl From<payjoin::send::Request> for Request {
    fn from(value: payjoin::send::Request) -> Self {
        Self { url: Arc::new(value.url.into()), body: value.body }
    }
}

#[cfg(test)]
mod tests {
    use crate::PartiallySignedTransaction;

    #[test]
    fn official_vectors() {
        let original = "cHNidP8BAHECAAAAAVuDh6O7xLpvJm70AWI6N25VtXzMiknZxAwcPtGoB/VHAAAAAAD+////AuYPECQBAAAAFgAUHAMjFjcTerY7Cmi4se8VqWIW5HgA4fUFAAAAABYAFL6Az084ngrVLQfpl3hccYjeF+EQAAAAAAABAIQCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wNSAQH/////AgDyBSoBAAAAFgAUQ0p5pXSyKswNZuFoJjltIQhFnpkAAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QAAAAABAR8A8gUqAQAAABYAFENKeaV0sirMDWbhaCY5bSEIRZ6ZAQhrAkcwRAIgFe1S3DHoDIPHogsTU/9UD7IqPbNXDYfyU2JZT9HKD7oCIAxU7sZzUcoGsmM3lDetos/3N5fM5oynmzuvsrFiILN5ASECfoMstJPrqnyhems+r158wTniKIBaPkkCinDC4VdvmsYAIgIDXVq5OYL7D4Ur28OTJ77j0lZrSPzO5XGmkL/KIF7wKmgQgTP32gAAAIABAACAAQAAgAAA";

        let original_psbt = PartiallySignedTransaction::from_string(original.to_string()).unwrap();
        eprintln!("original: {:#?}", original_psbt);

        let pj_uri_string = "BITCOIN:BCRT1Q7WXQ0R2JHJKX8HQS3SHLKFAEAEF38C38SYKGZY?amount=1&pj=https://example.comOriginal".to_string();
        let _uri = crate::Uri::new(pj_uri_string).unwrap();
        eprintln!("address: {:#?}", _uri.address().as_string());
    }
}

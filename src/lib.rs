#![crate_name = "payjoin_ffi"]

pub mod bitcoin;
pub mod error;
pub mod io;
pub mod ohttp;
pub mod receive;
pub mod send;
pub mod uri;

pub use crate::bitcoin::*;
use crate::error::PayjoinError;
pub use crate::ohttp::*;
pub use crate::receive::v1::*;
pub use crate::receive::v2::*;
pub use crate::send::v1::*;
pub use crate::send::v2::*;
pub use crate::uri::{PjUri, PjUriBuilder, Uri, Url};

#[cfg(feature = "uniffi")]
uniffi::include_scaffolding!("payjoin_ffi");

use std::sync::Arc;
///Represents data that needs to be transmitted to the receiver.
///You need to send this request over HTTP(S) to the receiver.
#[derive(Clone, Debug)]
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

impl From<payjoin::Request> for Request {
    fn from(value: payjoin::Request) -> Self {
        Self { url: Arc::new(value.url.into()), body: value.body }
    }
}

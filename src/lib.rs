#![crate_name = "payjoin_ffi"]

pub mod bitcoin_ffi;
pub mod error;
pub mod io;
pub mod ohttp;
pub mod receive;
pub mod request;
pub mod send;
pub mod uri;

pub use crate::bitcoin_ffi::*;
pub use crate::error::PayjoinError;
pub use crate::ohttp::*;
#[cfg(feature = "uniffi")]
pub use crate::receive::uni::*;
pub use crate::request::Request;
#[cfg(feature = "uniffi")]
pub use crate::send::uni::*;
pub use crate::uri::{PjUri, Uri, Url};
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

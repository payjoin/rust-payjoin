#![crate_name = "payjoin_ffi"]

pub mod bitcoin_ffi;
pub mod error;
pub mod io;
pub mod ohttp;
pub mod output_substitution;
pub mod receive;
pub mod request;
pub mod send;
#[cfg(feature = "_test-utils")]
pub mod test_utils;
pub mod uri;

pub use payjoin::persist::NoopSessionPersister;

pub use crate::bitcoin_ffi::*;
pub use crate::ohttp::*;
pub use crate::output_substitution::*;
pub use crate::receive::*;
pub use crate::request::Request;
pub use crate::send::*;
#[cfg(feature = "_test-utils")]
pub use crate::test_utils::*;
pub use crate::uri::{PjUri, Uri, Url};
uniffi::setup_scaffolding!();

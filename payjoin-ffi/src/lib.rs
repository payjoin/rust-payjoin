#![crate_name = "payjoin_ffi"]

pub mod error;
pub mod ohttp;
pub mod output_substitution;
pub mod receive;
pub mod request;
pub mod request_handler;
pub mod send;
#[cfg(feature = "_test-utils")]
pub mod test_utils;
pub mod uri;
mod validation;

pub use payjoin::persist::InMemoryPersister;

pub use crate::ohttp::*;
pub use crate::output_substitution::*;
pub use crate::receive::*;
pub use crate::request::Request;
pub use crate::request_handler::*;
pub use crate::send::*;
#[cfg(feature = "_test-utils")]
pub use crate::test_utils::*;
pub use crate::uri::{PjUri, Uri, Url};
uniffi::setup_scaffolding!("payjoin");

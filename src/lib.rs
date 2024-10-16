#![crate_name = "payjoin_ffi"]

pub mod error;
pub mod io;
pub mod receive;
pub mod send;
pub mod types;
pub mod uri;

use crate::error::PayjoinError;
pub use crate::receive::v1::*;
pub use crate::receive::v2::*;
pub use crate::send::v1::*;
pub use crate::send::v2::*;
pub use crate::types::*;
pub use crate::uri::{PjUri, PjUriBuilder, Uri, Url};

#[cfg(feature = "uniffi")]
uniffi::include_scaffolding!("payjoin_ffi");

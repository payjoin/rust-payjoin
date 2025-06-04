//! Core Payjoin
//!
//! This module contains types and methods used to implement Payjoin.

#[cfg(feature = "v2")]
pub(crate) mod hpke;
#[cfg(feature = "v2")]
pub mod persist;
#[cfg(feature = "v2")]
pub use crate::hpke::{HpkeKeyPair, HpkePublicKey};
#[cfg(feature = "v2")]
pub(crate) mod ohttp;
#[cfg(feature = "v2")]
pub use crate::ohttp::OhttpKeys;

pub(crate) mod output_substitution;
#[cfg(feature = "v1")]
pub use output_substitution::OutputSubstitution;
#[cfg(feature = "io")]
#[cfg_attr(docsrs, doc(cfg(feature = "io")))]
pub mod io;

pub mod error;
pub mod version;
pub use error::ImplementationError;
pub use version::Version;

pub mod receive;
pub mod send;
pub extern crate bitcoin;
pub(crate) mod error_codes;
pub(crate) mod psbt;
mod request;
pub use request::*;
pub(crate) mod into_url;
pub use into_url::{Error as IntoUrlError, IntoUrl};
pub(crate) mod uri;
pub use uri::{PjParseError, PjUri, Uri, UriExt};
pub use url::{ParseError, Url};

/// 4M block size limit with base64 encoding overhead => maximum reasonable size of content-length
/// 4_000_000 * 4 / 3 fits in u32
pub const MAX_CONTENT_LENGTH: usize = 4_000_000 * 4 / 3;

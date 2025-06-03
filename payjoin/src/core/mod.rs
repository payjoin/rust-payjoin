//! Core Payjoin
//!
//! This module contains types and methods used to implement Payjoin.
pub(crate) mod error;
pub use error::ImplementationError;

pub(crate) mod version;
pub use version::Version;

#[cfg(feature = "v2")]
pub(crate) mod hpke;
#[cfg(feature = "v2")]
pub use hpke::{HpkeKeyPair, HpkePublicKey};

#[cfg(feature = "v2")]
pub mod persist;

#[cfg(feature = "v2")]
pub(crate) mod ohttp;
#[cfg(feature = "v2")]
pub use ohttp::OhttpKeys;

#[cfg(any(feature = "v2", feature = "directory"))]
pub(crate) mod bech32;

#[cfg(feature = "_core")]
pub(crate) mod into_url;
#[cfg(feature = "_core")]
pub use into_url::{Error as IntoUrlError, IntoUrl};

#[cfg(feature = "io")]
#[cfg_attr(docsrs, doc(cfg(feature = "io")))]
pub mod io;

#[cfg(feature = "_core")]
pub(crate) mod output_substitution;
#[cfg(feature = "v1")]
pub use output_substitution::OutputSubstitution;

#[cfg(feature = "_core")]
pub(crate) mod request;
#[cfg(feature = "_core")]
pub use request::*;

#[cfg(feature = "_core")]
pub(crate) mod error_codes;

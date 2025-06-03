#![cfg_attr(docsrs, feature(doc_cfg))]

//! # Payjoin implementation in Rust
//!
//! Supercharge payment batching to save you fees and preserve your privacy.
//!
//! This library implements both [BIP 78 Payjoin V1](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) and [BIP 77 Payjoin V2](https://github.com/bitcoin/bips/blob/master/bip-0077.md).
//!
//! Only the latest BIP 77 Payjoin V2 is enabled by default. To use BIP 78 Payjoin V1, enable the `v1` feature.
//!
//! The library is perfectly IO-agnostic — in fact, it does no IO by default without the `io` feature.
//!
//! Types relevant to a Payjoin Directory as defined in BIP 77 are available in the [`directory`] module enabled by
//!  the `directory` feature.
//!
//! ## Disclaimer ⚠️ WIP
//!
//! **Use at your own risk. This crate has not yet been reviewed by independent Rust and Bitcoin security professionals.**

#[cfg(not(any(feature = "directory", feature = "v1", feature = "v2")))]
compile_error!("At least one of the features ['directory', 'v1', 'v2'] must be enabled");

#[cfg(feature = "_core")]
pub extern crate bitcoin;

#[cfg(feature = "_core")]
pub mod receive;
#[cfg(feature = "_core")]
pub mod send;

#[cfg(feature = "directory")]
#[cfg_attr(docsrs, doc(cfg(feature = "directory")))]
pub mod directory;
#[cfg(feature = "_core")]
mod uri;
#[cfg(feature = "_core")]
pub(crate) mod psbt;

#[cfg(feature = "_core")]
pub use uri::{PjParseError, PjUri, Uri, UriExt};
#[cfg(feature = "_core")]
pub use url::{ParseError, Url};
#[cfg(feature = "_core")]
pub mod core;

#[cfg(feature = "_core")]
pub use crate::core::*;
/// 4M block size limit with base64 encoding overhead => maximum reasonable size of content-length
/// 4_000_000 * 4 / 3 fits in u32
pub const MAX_CONTENT_LENGTH: usize = 4_000_000 * 4 / 3;

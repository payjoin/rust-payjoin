#![cfg_attr(docsrs, feature(doc_cfg))]

//! # Payjoin implementation in Rust
//!
//! Supercharge payment batching to save you fees and preserve your privacy.
//!
//! This library implements both [BIP 78 Payjoin V1](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki) and [BIP 77 Payjoin V2](https://github.com/bitcoin/bips/blob/master/bip-0077.md).
//!
//! Only the latest BIP 77 Payjoin V2 is enabled by default. To use BIP 78 Payjoin V1, enable the `v1` feature.
//!
//! The main API is organized by version and operation type:
//! - Sending Payjoins: [`send::v1`] and [`send::v2`] modules
//! - Receiving Payjoins: [`receive::v1`] and [`receive::v2`] modules
//!
//! For most use cases, we recommend using the v2 modules as they are backwards compatible and provide the most convenient experience for users and implementers.
//!
//! # Example Usage
//!
//! See the [payjoin-cli] crate for a complete example of how to use this library in practice.
//!
//! [payjoin-cli]: https://github.com/payjoin/rust-payjoin/tree/master/payjoin-cli
//! The CLI demonstrates both sending and receiving payjoins using both v1 and v2 implementations.
//!
//! ## Additional Features
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

#[cfg(any(feature = "v2", feature = "directory"))]
pub(crate) mod bech32;
#[cfg(feature = "directory")]
#[cfg_attr(docsrs, doc(cfg(feature = "directory")))]
pub mod directory;

#[cfg(feature = "_core")]
pub(crate) mod core;
#[cfg(feature = "_core")]
pub use crate::core::*;

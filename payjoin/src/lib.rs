#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(
    docsrs,
    doc(
        html_logo_url = "https://raw.githubusercontent.com/payjoin/rust-payjoin/master/static/monad.svg"
    )
)]
//! # Rust Payjoin Library
//!
//! The main Payjoin Dev Kit (PDK) library which implements Async Payjoin. The library implements
//! Payjoin session persistence support and IO utilities for interacting with OHTTP relays to make
//! integration plug-and-play.
//!
//! Both sender and receiver construct design follow [The Typestate Pattern in Rust](https://cliffle.com/blog/rust-typestate/),
//! where higher-level [`Sender`] and [`Receiver`] structs are transitioned through
//! consecutive states which represent a specific step they can be on over the course of a Payjoin
//! session. See the documentation of state implementations for more information.
//!
//! ## Cargo Features
//! - `v2`: all constructs for [BIP 77: Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
//!   send and receive operations. Note that IO for fetching OHTTP keys from the Payjoin directory is not enabled here,
//!   and requires you to bring your own implementation and HTTP client unless you choose to use ours
//!   with the `io` feature.
//! - `v1`: all constructs for [BIP 78: Simple Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki)
//!   send and receive operations.
//! - `io`: helper functions for fetching and parsing OHTTP keys.
//! - `directory`: type for identifying Payjoin Directory entries as defined in BIP 77.
//!
//! Only the `v2` feature is enabled by default.
//!
//! [`Sender`]: crate::send::v2::Sender
//! [`Receiver`]: crate::receive::v2::Receiver

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

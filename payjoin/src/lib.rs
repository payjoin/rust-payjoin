//! # Payjoin implementation in Rust
//!
//! **Important: this crate is WIP!**
//!
//! While I don't think there's a huge risk running it, don't rely on its security for now!
//! Please at least review the code that verifies there's no overpayment and let me know you did.
//!
//! This is a library and an example binary implementing BIP78 Payjoin.
//! The library is perfectly IO-agnostic - in fact, it does no IO.
//! The primary goal of such design is to make it easy to unit test.
//! While we're not there yet, it already has infinitely more tests than the Payjoin PR against Electrum. :P
//!
//! Additional advantage is it doesn't care whether you use `async`, blocking, `tokio`, `sync-std` `hyper`, `actix` or whatever.
//! There are already too many frameworks in Rust so it's best avoiding directly introducing them into library code.
//!
//! To use this library as a sender (client, payer), you need to enable `send` Cargo feature.
//!
//! To use this library as a receiver (server, payee), you need to enable `receive` Cargo feature.

#[cfg(feature = "_core")]
pub extern crate bitcoin;

#[cfg(feature = "_core")]
pub mod receive;
#[cfg(feature = "_core")]
pub mod send;

#[cfg(feature = "v2")]
pub(crate) mod hpke;
#[cfg(feature = "v2")]
pub use crate::hpke::{HpkeKeyPair, HpkePublicKey};
#[cfg(feature = "v2")]
pub(crate) mod ohttp;
#[cfg(feature = "v2")]
pub use crate::ohttp::OhttpKeys;
#[cfg(any(feature = "v2", feature = "directory"))]
pub(crate) mod bech32;
#[cfg(feature = "directory")]
pub mod directory;

#[cfg(feature = "io")]
pub mod io;
#[cfg(feature = "_core")]
pub(crate) mod psbt;
#[cfg(feature = "_core")]
mod request;
#[cfg(feature = "_core")]
pub use request::*;
#[cfg(feature = "_core")]
mod uri;

#[cfg(feature = "base64")]
pub use bitcoin::base64;
#[cfg(feature = "_core")]
pub use uri::{PjParseError, PjUri, Uri, UriExt};
#[cfg(feature = "_core")]
pub use url::{ParseError, Url};

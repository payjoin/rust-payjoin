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

pub extern crate bitcoin;

#[cfg(feature = "receive")]
pub mod receive;
#[cfg(feature = "receive")]
pub use crate::receive::Error;

#[cfg(feature = "send")]
pub mod send;

#[cfg(feature = "v2")]
pub(crate) mod hpke;
#[cfg(feature = "v2")]
pub(crate) mod ohttp;
#[cfg(feature = "v2")]
pub use crate::ohttp::OhttpKeys;

#[cfg(feature = "io")]
pub mod io;

#[cfg(any(feature = "send", feature = "receive"))]
pub(crate) mod psbt;
#[cfg(any(feature = "send", all(feature = "receive", feature = "v2")))]
mod request;
#[cfg(any(feature = "send", all(feature = "receive", feature = "v2")))]
pub use request::*;

mod uri;

#[cfg(feature = "base64")]
pub use bitcoin::base64;
pub use uri::{PjParseError, PjUri, PjUriBuilder, Uri, UriExt};
pub use url::{ParseError, Url};

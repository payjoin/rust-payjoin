//! # PayJoin implementation in Rust
//! 
//! **Important: this crate is WIP!**
//!
//! While I don't think there's a huge risk running it, don't rely on its security for now!
//! Please at least review the code that verifies there's no overpayment and let me know you did.
//! 
//! This is a library and an example binary implementing BIP78 PayJoin.
//! The library is perfectly IO-agnostic - in fact, it does no IO.
//! The primary goal of such design is to make it easy to unit test.
//! While we're not there yet, it already has infinitely more tests than the PayJoin PR against Electrum. :P
//! 
//! Additional advantage is it doesn't care whether you use `async`, blocking, `tokio`, `sync-std` `hyper`, `actix` or whatever.
//! There are already too many frameworks in Rust so it's best avoiding directly introducing them into library code.
//! The library currently only contains sender implementation but I want to add receiver too.
//!
//! To use this library as a sender (client, payer), you need to enable `sender` Cargo feature.
//! To use this library as a receiver (server, payee), you need to implement it and send a PR.

pub extern crate bitcoin;

#[cfg(feature = "sender")]
pub mod sender;
#[cfg(feature = "receiver")]
pub mod receiver;

pub(crate) mod input_type;
mod uri;
pub(crate) mod weight;
pub(crate) mod fee_rate;
pub(crate) mod psbt;

pub use uri::{Uri, PjUri, UriExt, PjUriExt, PjParseError};

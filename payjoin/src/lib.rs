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
//!
//! To use this library as a sender (client, payer), you need to enable `send` Cargo feature.
//!
//! To use this library as a receiver (server, payee), you need to enable `receive` Cargo feature.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[macro_use]
extern crate alloc;

// May depend on crate features and we don't want to bother with it
#[allow(unused)]
#[cfg(feature = "std")]
use std::error::Error as StdError;
#[cfg(feature = "std")]
use std::io;

#[allow(unused)]
#[cfg(not(feature = "std"))]
use core2::error::Error as StdError;
#[cfg(not(feature = "std"))]
use core2::io;

// use core::{borrow, fmt};

pub extern crate bitcoin;

#[cfg(feature = "receive")]
pub mod receive;
pub use crate::receive::Error;
#[cfg(feature = "send")]
pub mod send;

#[cfg(any(feature = "send", feature = "receive"))]
pub(crate) mod fee_rate;
#[cfg(any(feature = "send", feature = "receive"))]
pub(crate) mod input_type;
#[cfg(any(feature = "send", feature = "receive"))]
pub(crate) mod psbt;
mod uri;
#[cfg(any(feature = "send", feature = "receive"))]
pub(crate) mod weight;

pub use uri::{PjParseError, PjUri, PjUriExt, Uri, UriExt};

#[rustfmt::skip]
mod prelude {
    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, Cow, ToOwned}, slice, rc};

    #[cfg(all(not(feature = "std"), not(test), any(not(rust_v_1_60), target_has_atomic = "ptr")))]
    pub use alloc::sync;

    #[cfg(any(feature = "std", test))]
    pub use std::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, Cow, ToOwned}, slice, rc, sync};

    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(any(feature = "std", test))]
    pub use std::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(feature = "std")]
    pub use std::io::sink;
}

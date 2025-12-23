#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(
    docsrs,
    doc(
        html_logo_url = "https://raw.githubusercontent.com/payjoin/rust-payjoin/master/static/monad.svg"
    )
)]

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

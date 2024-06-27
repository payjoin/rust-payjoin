#![crate_name = "payjoin_ffi"]

pub mod error;
pub mod io;
pub mod receive;
pub mod send;
pub mod types;
pub mod uri;

use crate::error::PayjoinError;
#[cfg(feature = "uniffi")]
use crate::receive::v1::{
    CanBroadcast, IsOutputKnown, IsScriptOwned, ProcessPartiallySignedTransaction,
};
#[allow(unused_imports)]
use crate::receive::v1::{
    Headers, MaybeInputsOwned, MaybeInputsSeen, MaybeMixedInputScripts, OutputsUnknown,
    PayjoinProposal, ProvisionalProposal, UncheckedProposal,
};
#[allow(unused_imports)]
use crate::receive::v2::{
    ActiveSession, ClientResponse, RequestResponse, SessionInitializer, V2MaybeInputsOwned,
    V2MaybeInputsSeen, V2MaybeMixedInputScripts, V2OutputsUnknown, V2PayjoinProposal,
    V2ProvisionalProposal, V2UncheckedProposal,
};
#[allow(unused_imports)]
use crate::send::v1::{
    ContextV1, RequestBuilder, RequestContext, RequestContextV1, RequestContextV2,
};
#[allow(unused_imports)]
use crate::send::v2::ContextV2;
#[allow(unused_imports)]
use crate::types::{Network, OhttpKeys, OutPoint, Request, TxOut};
#[allow(unused_imports)]
use crate::uri::{PjUri, Uri, Url};

#[cfg(feature = "uniffi")]
uniffi::include_scaffolding!("payjoin_ffi");

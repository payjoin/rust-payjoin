#![crate_name = "payjoin_ffi"]

pub mod error;
pub mod receive;
pub mod send;
pub mod transaction;
mod types;
pub mod uri;

use crate::error::PayjoinError;
#[allow(unused_imports)]
use crate::receive::v2::{
    ClientResponse, Enrolled, Enroller, RequestResponse, V2MaybeInputsOwned, V2MaybeInputsSeen,
    V2MaybeMixedInputScripts, V2OutputsUnknown, V2PayjoinProposal, V2ProvisionalProposal,
    V2UncheckedProposal,
};
use crate::receive::{
    CanBroadcast, Headers, IsOutputKnown, IsScriptOwned, MaybeInputsOwned, MaybeInputsSeen,
    MaybeMixedInputScripts, OutputsUnknown, PayjoinProposal, ProcessPartiallySignedTransaction,
    ProvisionalProposal, UncheckedProposal,
};
use crate::send::v2::ContextV2;
use crate::send::{ContextV1, RequestBuilder, RequestContext, RequestContextV1, RequestContextV2};
use crate::transaction::{PartiallySignedTransaction, Transaction};
use crate::types::{Address, Amount, FeeRate, Network, OutPoint, Request, ScriptBuf, TxOut, Txid};
use crate::uri::{PjUri, Uri, Url};

uniffi::include_scaffolding!("payjoin_ffi");

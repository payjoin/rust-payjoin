use bitcoin::Psbt;
use serde::{Deserialize, Serialize};

use super::SenderWithReplyKey;
use crate::send::multiparty::{FinalizeContext, GetContext};

// TODO: create replay and session history for multiparty sender

#[derive(Clone, Serialize, Deserialize)]
pub enum SenderSessionEvent {
    CreatedReplyKey(SenderWithReplyKey),
    V2GetContext(GetContext),
    ProposalReceived(Psbt),
    FinalizeContext(FinalizeContext),
    SessionInvalid(String),
}

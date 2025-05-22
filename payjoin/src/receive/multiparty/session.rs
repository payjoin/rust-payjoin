use crate::receive::{v1, v2::SessionContext};

use super::{MaybeInputsOwned, MaybeInputsSeen, OutputsUnknown, PayjoinProposal, ProvisionalProposal, UncheckedProposal, WantsInputs, WantsOutputs};

pub enum ReceiverSessionEvent {
    Created(SessionContext),
    UncheckedProposal(UncheckedProposal),
    MaybeInputsOwned(MaybeInputsOwned),
    MaybeInputsSeen(MaybeInputsSeen),
    OutputsUnknown(OutputsUnknown),
    WantsOutputs(WantsOutputs),
    WantsInputs(WantsInputs),
    ProvisionalProposal(ProvisionalProposal),
    PayjoinProposal(PayjoinProposal),
    SessionInvalid(String),
}

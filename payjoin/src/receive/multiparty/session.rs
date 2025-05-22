use super::{
    MaybeInputsOwned, MaybeInputsSeen, OutputsUnknown, PayjoinProposal, ProvisionalProposal,
    UncheckedProposal, WantsInputs, WantsOutputs,
};
use crate::receive::v2::SessionContext;

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

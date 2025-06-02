use std::fmt::{self, Display};

use serde::{Deserialize, Serialize};

use super::{Receiver, SessionContext, WithContext};
use crate::persist::{self};
use crate::receive::v1;
use crate::uri::ShortId;

/// Opaque key type for the receiver
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverToken(ShortId);

impl Display for ReceiverToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl From<Receiver<WithContext>> for ReceiverToken {
    fn from(receiver: Receiver<WithContext>) -> Self { ReceiverToken(receiver.context.id()) }
}

impl AsRef<[u8]> for ReceiverToken {
    fn as_ref(&self) -> &[u8] { self.0.as_bytes() }
}

impl persist::Value for Receiver<WithContext> {
    type Key = ReceiverToken;

    fn key(&self) -> Self::Key { ReceiverToken(self.context.id()) }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Represents a piece of information that the receiver has obtained from the session
/// Each event can be used to transition the receiver state machine to a new state
pub enum SessionEvent {
    Created(SessionContext),
    UncheckedProposal(v1::UncheckedProposal),
    MaybeInputsOwned(v1::MaybeInputsOwned),
    MaybeInputsSeen(v1::MaybeInputsSeen),
    OutputsUnknown(v1::OutputsUnknown),
    WantsOutputs(v1::WantsOutputs),
    WantsInputs(v1::WantsInputs),
    ProvisionalProposal(v1::ProvisionalProposal),
    PayjoinProposal(v1::PayjoinProposal),
    /// Session is invalid. This is a irrecoverable error. Fallback tx should be broadcasted.
    /// TODO this should be any error type that is impl std::error and works well with serde, or as a fallback can be formatted as a string
    /// Reason being in some cases we still want to preserve the error b/c we can action on it. For now this is a terminal state and there is nothing to replay and is saved to be displayed.
    /// b/c its a terminal state and there is nothing to replay. So serialization will be lossy and that is fine.
    SessionInvalid(String),
}

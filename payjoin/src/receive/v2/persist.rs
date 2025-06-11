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
    UncheckedProposal((v1::UncheckedProposal, Option<crate::HpkePublicKey>)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receive::v1::test::unchecked_proposal_from_test_vector;
    use crate::receive::v2::test::SHARED_CONTEXT;

    #[test]
    fn test_session_event_serialization_roundtrip() {
        let unchecked_proposal = unchecked_proposal_from_test_vector();
        let maybe_inputs_owned = unchecked_proposal.clone().assume_interactive_receiver();
        let maybe_inputs_seen = maybe_inputs_owned
            .clone()
            .check_inputs_not_owned(|_| Ok(false))
            .expect("No inputs should be owned");
        let outputs_unknown = maybe_inputs_seen
            .clone()
            .check_no_inputs_seen_before(|_| Ok(false))
            .expect("No inputs should be seen before");
        let wants_outputs = outputs_unknown
            .clone()
            .identify_receiver_outputs(|_| Ok(true))
            .expect("Outputs should be identified");
        let wants_inputs = wants_outputs.clone().commit_outputs();
        let provisional_proposal = wants_inputs.clone().commit_inputs();
        let payjoin_proposal = provisional_proposal
            .clone()
            .finalize_proposal(|psbt| Ok(psbt.clone()), None, None)
            .expect("Payjoin proposal should be finalized");

        let test_cases = vec![
            SessionEvent::Created(SHARED_CONTEXT.clone()),
            SessionEvent::UncheckedProposal((unchecked_proposal.clone(), None)),
            SessionEvent::UncheckedProposal((
                unchecked_proposal,
                Some(crate::HpkeKeyPair::gen_keypair().1),
            )),
            SessionEvent::MaybeInputsOwned(maybe_inputs_owned),
            SessionEvent::MaybeInputsSeen(maybe_inputs_seen),
            SessionEvent::OutputsUnknown(outputs_unknown),
            SessionEvent::WantsOutputs(wants_outputs),
            SessionEvent::WantsInputs(wants_inputs),
            SessionEvent::ProvisionalProposal(provisional_proposal),
            SessionEvent::PayjoinProposal(payjoin_proposal),
        ];

        for event in test_cases {
            let serialized = serde_json::to_string(&event).expect("Serialization should not fail");
            let deserialized: SessionEvent =
                serde_json::from_str(&serialized).expect("Deserialization should not fail");
            assert_eq!(event, deserialized);
        }
    }
}

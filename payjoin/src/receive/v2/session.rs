use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use super::{Receiver, ReceiverState, SessionContext, UninitializedReceiver};
use crate::output_substitution::OutputSubstitution;
use crate::persist::PersistedSession;
use crate::receive::v1;
use crate::receive::v2::{id, subdir};
use crate::PjUri;

#[derive(Debug)]
/// Errors that can occur when replaying a receiver event log
pub enum ReceiverReplayError {
    /// Session expired
    SessionExpired(SystemTime),
    /// Invalid combination of state and event
    InvalidStateAndEvent(ReceiverState, ReceiverSessionEvent),
}

impl std::fmt::Display for ReceiverReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{:?}", self) }
}
impl std::error::Error for ReceiverReplayError {}

/// Replay a receiver event log to get the receiver in its current state [ReceiverState]
/// and a session history [SessionHistory]
pub fn replay_receiver_event_log<P>(
    persister: P,
) -> Result<(ReceiverState, SessionHistory), ReceiverReplayError>
where
    P: PersistedSession + Clone,
    P::SessionEvent: From<ReceiverSessionEvent> + Clone,
    ReceiverSessionEvent: From<P::SessionEvent>,
{
    // TODO: fix this
    let logs = persister.load().unwrap();
    let mut receiver = ReceiverState::Uninitialized(Receiver { state: UninitializedReceiver {} });
    let mut history = SessionHistory::new(Vec::new());

    for log in logs {
        history.events.push(log.clone().into());
        // TODO: remove clone
        match receiver.clone().process_event(log.into()) {
            Ok(next_receiver) => {
                receiver = next_receiver;
            }
            Err(_e) => {
                // All error cases are terminal. Close the session in its current state
                persister.close().unwrap();
                break;
            }
        }
    }

    Ok((receiver, history))
}

#[derive(Clone)]
pub struct SessionHistory {
    events: Vec<ReceiverSessionEvent>,
}

impl SessionHistory {
    fn new(events: Vec<ReceiverSessionEvent>) -> Self { Self { events } }

    pub fn pj_uri<'a>(&self) -> Option<PjUri<'a>> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::Created(session_context) => {
                // TODO this code was copied from ReceiverWithContext::pj_uri. Should be deduped
                use crate::uri::{PayjoinExtras, UrlExt};
                let id = id(&session_context.s);
                let mut pj = subdir(&session_context.directory, &id).clone();
                pj.set_receiver_pubkey(session_context.s.public_key().clone());
                pj.set_ohttp(session_context.ohttp_keys.clone());
                pj.set_exp(session_context.expiry);
                let extras = PayjoinExtras {
                    endpoint: pj,
                    output_substitution: OutputSubstitution::Disabled,
                };
                Some(bitcoin_uri::Uri::with_extras(session_context.address.clone(), extras))
            }
            _ => None,
        })
    }

    pub fn payment_amount(&self) -> Option<bitcoin::Amount> { self.pj_uri().map(|uri| uri.amount)? }

    pub fn payment_address(&self) -> Option<bitcoin::Address<bitcoin::address::NetworkChecked>> {
        self.pj_uri().map(|uri| uri.address)
    }

    pub fn proposal_txid(&self) -> Option<bitcoin::Txid> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::ProvisionalProposal(proposal) =>
                Some(proposal.payjoin_psbt.unsigned_tx.compute_txid()),
            _ => None,
        })
    }

    pub fn fallback_txid(&self) -> Option<bitcoin::Txid> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::UncheckedProposal(proposal) =>
                Some(proposal.psbt.unsigned_tx.compute_txid()),
            _ => None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// represents a piece of information that the reciever has learned about the session
/// Each event can be used to transition the receiver state machine to a new state
pub enum ReceiverSessionEvent {
    /// Receiver was created
    Created(SessionContext),
    /// Receiver read a proposal from a directory
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
    /// Reason being in some cases we still want to preserve the error b/c the cause the session to fail but these are terminal states we dont need them to be structured or well typed
    /// b/c its a terminal state and there is nothing to replay. So serialization will be lossy and that is fine.
    SessionInvalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receive::v1::test::{
        maybe_inputs_owned_from_test_vector, maybe_inputs_seen_from_test_vector,
        outputs_unknown_from_test_vector, payjoin_proposal_from_test_vector,
        provisional_proposal_from_test_vector, unchecked_proposal_from_test_vector,
        wants_inputs_from_test_vector, wants_outputs_from_test_vector,
    };
    use crate::receive::v2::test::SHARED_CONTEXT;

    #[test]
    fn test_receiver_session_event_serialization() {
        let event = ReceiverSessionEvent::Created(SHARED_CONTEXT.clone());
        let serialized = serde_json::to_string(&event).unwrap();
        let deserialized: ReceiverSessionEvent = serde_json::from_str(&serialized).unwrap();

        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_session_event_serialization_roundtrip() {
        let unchecked_proposal = unchecked_proposal_from_test_vector();

        // Test serialization roundtrip for each session event
        let test_cases = vec![
            ReceiverSessionEvent::UncheckedProposal(unchecked_proposal.clone()),
            ReceiverSessionEvent::MaybeInputsOwned(maybe_inputs_owned_from_test_vector()),
            ReceiverSessionEvent::MaybeInputsSeen(maybe_inputs_seen_from_test_vector()),
            ReceiverSessionEvent::OutputsUnknown(outputs_unknown_from_test_vector()),
            ReceiverSessionEvent::WantsOutputs(wants_outputs_from_test_vector(
                unchecked_proposal.clone(),
            )),
            ReceiverSessionEvent::WantsInputs(wants_inputs_from_test_vector()),
            ReceiverSessionEvent::ProvisionalProposal(provisional_proposal_from_test_vector(
                unchecked_proposal.clone(),
            )),
            ReceiverSessionEvent::PayjoinProposal(payjoin_proposal_from_test_vector(
                unchecked_proposal.clone(),
            )),
        ];

        // Test serialization roundtrip for each case
        for event in test_cases {
            let serialized = serde_json::to_string(&event).unwrap();
            let deserialized: ReceiverSessionEvent = serde_json::from_str(&serialized).unwrap();
            assert_eq!(event, deserialized);
        }
    }
}

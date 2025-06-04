use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use super::{Receiver, ReceiverState, SessionContext, UninitializedReceiver};
use crate::output_substitution::OutputSubstitution;
use crate::persist::SessionPersister;
use crate::receive::v1;
use crate::receive::v2::{id, subdir};
use crate::{HpkePublicKey, ImplementationError, PjUri};

#[derive(Debug)]
/// Errors that can occur when replaying a receiver event log
pub enum ReceiverReplayError {
    /// Session expired
    SessionExpired(SystemTime),
    /// Invalid combination of state and event
    InvalidStateAndEvent(ReceiverState, ReceiverSessionEvent),
    /// Persistence failure
    PersistenceFailure(ImplementationError),
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
    P: SessionPersister + Clone,
    P::SessionEvent: From<ReceiverSessionEvent> + Clone,
    ReceiverSessionEvent: From<P::SessionEvent>,
{
    let logs =
        persister.load().map_err(|e| ReceiverReplayError::PersistenceFailure(Box::new(e)))?;
    let mut receiver = ReceiverState::Uninitialized(Receiver { state: UninitializedReceiver {} });
    let mut history = SessionHistory::default();

    for log in logs {
        history.events.push(log.clone().into());
        // TODO: remove clone
        match receiver.clone().process_event(log.into()) {
            Ok(next_receiver) => {
                receiver = next_receiver;
            }
            Err(_e) => {
                // All error cases are terminal. Close the session in its current state
                persister
                    .close()
                    .map_err(|e| ReceiverReplayError::PersistenceFailure(Box::new(e)))?;
                break;
            }
        }
    }

    Ok((receiver, history))
}

#[derive(Clone, Default)]
pub struct SessionHistory {
    pub(crate) events: Vec<ReceiverSessionEvent>,
}

impl SessionHistory {
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
            ReceiverSessionEvent::UncheckedProposal((proposal, _)) =>
                Some(proposal.psbt.unsigned_tx.compute_txid()),
            _ => None,
        })
    }

    pub fn session_invalid(&self) -> Option<String> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::SessionInvalid(e) => Some(e.clone()),
            _ => None,
        })
    }

    pub fn original_psbt(&self) -> Option<bitcoin::Psbt> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::UncheckedProposal((proposal, _)) => Some(proposal.psbt.clone()),
            _ => None,
        })
    }

    pub fn proposed_payjoin_psbt(&self) -> Option<bitcoin::Psbt> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::PayjoinProposal(proposal) => Some(proposal.psbt().clone()),
            _ => None,
        })
    }

    pub fn psbt_with_contributed_inputs(&self) -> Option<bitcoin::Psbt> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::ProvisionalProposal(proposal) =>
                Some(proposal.payjoin_psbt.clone()),
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
    UncheckedProposal((v1::UncheckedProposal, HpkePublicKey)),
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
    use crate::persist::tests::InMemoryTestPersister;
    use crate::receive::v1::test::{
        maybe_inputs_owned_from_test_vector, maybe_inputs_seen_from_test_vector,
        outputs_unknown_from_test_vector, payjoin_proposal_from_test_vector,
        provisional_proposal_from_test_vector, unchecked_proposal_from_test_vector,
        wants_inputs_from_test_vector, wants_outputs_from_test_vector,
    };
    use crate::receive::v2::test::SHARED_CONTEXT;
    use crate::receive::v2::{
        PayjoinProposal, ProvisionalProposal, ReceiverWithContext, UncheckedProposal,
    };
    use crate::HpkeKeyPair;

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
        let reply_key = HpkeKeyPair::gen_keypair().1;

        // Test serialization roundtrip for each session event
        let test_cases = vec![
            ReceiverSessionEvent::UncheckedProposal((
                unchecked_proposal.clone(),
                reply_key.clone(),
            )),
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

    struct SessionHistoryExpectedOutcome {
        payment_address: Option<bitcoin::Address<bitcoin::address::NetworkChecked>>,
        payment_amount: Option<bitcoin::Amount>,
        fallback_txid: Option<bitcoin::Txid>,
        original_psbt: Option<bitcoin::Psbt>,
        proposed_payjoin_psbt: Option<bitcoin::Psbt>,
        psbt_with_contributed_inputs: Option<bitcoin::Psbt>,
    }

    struct SessionHistoryTest {
        events: Vec<ReceiverSessionEvent>,
        expected_session_history: SessionHistoryExpectedOutcome,
        expected_receiver_state: ReceiverState,
    }

    fn run_session_history_test(test: SessionHistoryTest) {
        let persister = InMemoryTestPersister::<ReceiverSessionEvent>::default();
        for event in test.events {
            persister.save_event(&event).expect("In memory persister shouldn't fail");
        }

        let (receiver, session_history) =
            replay_receiver_event_log(persister).expect("In memory persister shouldn't fail");
        assert_eq!(receiver, test.expected_receiver_state);

        // Check expected session history
        // assert_eq!(session_history.pj_uri(), test.expected_session_history.payment_address);
        assert_eq!(session_history.payment_amount(), test.expected_session_history.payment_amount);
        assert_eq!(session_history.fallback_txid(), test.expected_session_history.fallback_txid);
        assert_eq!(session_history.original_psbt(), test.expected_session_history.original_psbt);
        assert_eq!(
            session_history.proposed_payjoin_psbt(),
            test.expected_session_history.proposed_payjoin_psbt
        );
        assert_eq!(
            session_history.psbt_with_contributed_inputs(),
            test.expected_session_history.psbt_with_contributed_inputs
        );
    }

    #[test]
    fn test_replaying_session_creation() {
        let session_context = SHARED_CONTEXT.clone();
        let event = ReceiverSessionEvent::Created(SHARED_CONTEXT.clone());

        let test = SessionHistoryTest {
            events: vec![event],
            expected_session_history: SessionHistoryExpectedOutcome {
                payment_address: Some(session_context.address.clone()),
                payment_amount: None,
                fallback_txid: None,
                original_psbt: None,
                proposed_payjoin_psbt: None,
                psbt_with_contributed_inputs: None,
            },
            expected_receiver_state: ReceiverState::WithContext(Receiver {
                state: ReceiverWithContext { context: session_context },
            }),
        };
        run_session_history_test(test);
    }

    #[test]
    fn test_replaying_unchecked_proposal() {
        let reply_key = HpkeKeyPair::gen_keypair().1;
        let session_context =
            SessionContext { e: Some(reply_key.clone()), ..SHARED_CONTEXT.clone() };
        let test = SessionHistoryTest {
            events: vec![
                ReceiverSessionEvent::Created(session_context.clone()),
                ReceiverSessionEvent::UncheckedProposal((
                    unchecked_proposal_from_test_vector(),
                    reply_key.clone(),
                )),
            ],
            expected_session_history: SessionHistoryExpectedOutcome {
                payment_address: Some(session_context.address.clone()),
                payment_amount: None,
                fallback_txid: Some(
                    unchecked_proposal_from_test_vector().psbt.unsigned_tx.compute_txid(),
                ),
                original_psbt: Some(unchecked_proposal_from_test_vector().psbt.clone()),
                proposed_payjoin_psbt: None,
                psbt_with_contributed_inputs: None,
            },
            expected_receiver_state: ReceiverState::UncheckedProposal(Receiver {
                state: UncheckedProposal {
                    v1: unchecked_proposal_from_test_vector(),
                    context: session_context,
                },
            }),
        };
        run_session_history_test(test);
    }

    #[test]
    fn test_contributed_inputs() {
        let reply_key = HpkeKeyPair::gen_keypair().1;
        let session_context =
            SessionContext { e: Some(reply_key.clone()), ..SHARED_CONTEXT.clone() };

        let test = SessionHistoryTest {
            events: vec![
                ReceiverSessionEvent::Created(session_context.clone()),
                ReceiverSessionEvent::UncheckedProposal((
                    unchecked_proposal_from_test_vector(),
                    reply_key.clone(),
                )),
                ReceiverSessionEvent::MaybeInputsOwned(maybe_inputs_owned_from_test_vector()),
                ReceiverSessionEvent::MaybeInputsSeen(maybe_inputs_seen_from_test_vector()),
                ReceiverSessionEvent::OutputsUnknown(outputs_unknown_from_test_vector()),
                ReceiverSessionEvent::WantsOutputs(wants_outputs_from_test_vector(
                    unchecked_proposal_from_test_vector(),
                )),
                ReceiverSessionEvent::WantsInputs(wants_inputs_from_test_vector()),
                ReceiverSessionEvent::ProvisionalProposal(provisional_proposal_from_test_vector(
                    unchecked_proposal_from_test_vector(),
                )),
            ],
            expected_session_history: SessionHistoryExpectedOutcome {
                payment_address: Some(session_context.address.clone()),
                payment_amount: None,
                fallback_txid: Some(
                    unchecked_proposal_from_test_vector().psbt.unsigned_tx.compute_txid(),
                ),
                original_psbt: Some(unchecked_proposal_from_test_vector().psbt.clone()),
                proposed_payjoin_psbt: None,
                psbt_with_contributed_inputs: Some(
                    provisional_proposal_from_test_vector(unchecked_proposal_from_test_vector())
                        .payjoin_psbt
                        .clone(),
                ),
            },
            expected_receiver_state: ReceiverState::ProvisionalProposal(Receiver {
                state: ProvisionalProposal {
                    v1: provisional_proposal_from_test_vector(unchecked_proposal_from_test_vector()),
                    context: session_context,
                },
            }),
        };
        run_session_history_test(test);
    }

    #[test]
    fn test_payjoin_proposal() {
        let reply_key = HpkeKeyPair::gen_keypair().1;
        let session_context =
            SessionContext { e: Some(reply_key.clone()), ..SHARED_CONTEXT.clone() };
        let test = SessionHistoryTest {
            events: vec![
                ReceiverSessionEvent::Created(session_context.clone()),
                ReceiverSessionEvent::UncheckedProposal((
                    unchecked_proposal_from_test_vector(),
                    reply_key.clone(),
                )),
                ReceiverSessionEvent::MaybeInputsOwned(maybe_inputs_owned_from_test_vector()),
                ReceiverSessionEvent::MaybeInputsSeen(maybe_inputs_seen_from_test_vector()),
                ReceiverSessionEvent::OutputsUnknown(outputs_unknown_from_test_vector()),
                ReceiverSessionEvent::WantsOutputs(wants_outputs_from_test_vector(
                    unchecked_proposal_from_test_vector(),
                )),
                ReceiverSessionEvent::WantsInputs(wants_inputs_from_test_vector()),
                ReceiverSessionEvent::ProvisionalProposal(provisional_proposal_from_test_vector(
                    unchecked_proposal_from_test_vector(),
                )),
                ReceiverSessionEvent::PayjoinProposal(payjoin_proposal_from_test_vector(
                    unchecked_proposal_from_test_vector(),
                )),
            ],
            expected_session_history: SessionHistoryExpectedOutcome {
                payment_address: Some(session_context.address.clone()),
                payment_amount: None,
                fallback_txid: Some(
                    unchecked_proposal_from_test_vector().psbt.unsigned_tx.compute_txid(),
                ),
                original_psbt: Some(unchecked_proposal_from_test_vector().psbt.clone()),
                proposed_payjoin_psbt: Some(
                    payjoin_proposal_from_test_vector(unchecked_proposal_from_test_vector())
                        .psbt()
                        .clone(),
                ),
                psbt_with_contributed_inputs: Some(
                    provisional_proposal_from_test_vector(unchecked_proposal_from_test_vector())
                        .payjoin_psbt
                        .clone(),
                ),
            },
            expected_receiver_state: ReceiverState::PayjoinProposal(Receiver {
                state: PayjoinProposal {
                    v1: payjoin_proposal_from_test_vector(unchecked_proposal_from_test_vector()),
                    context: session_context,
                },
            }),
        };
        run_session_history_test(test);
    }
}

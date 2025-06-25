use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use super::{Receiver, ReceiverTypeState, SessionContext, UninitializedReceiver};
use crate::output_substitution::OutputSubstitution;
use crate::persist::SessionPersister;
use crate::receive::v2::{extract_err_req, subdir, SessionError};
use crate::receive::{v1, JsonReply};
use crate::{ImplementationError, IntoUrl, PjUri, Request};

/// Errors that can occur when replaying a receiver event log
#[derive(Debug)]
pub struct ReplayError(InternalReplayError);

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use InternalReplayError::*;
        match &self.0 {
            SessionExpired(expiry) => write!(f, "Session expired at {expiry:?}"),
            InvalidStateAndEvent(state, event) => write!(
                f,
                "Invalid combination of state ({state:?}) and event ({event:?}) during replay",
            ),
            PersistenceFailure(e) => write!(f, "Persistence failure: {e}"),
        }
    }
}
impl std::error::Error for ReplayError {}

impl From<InternalReplayError> for ReplayError {
    fn from(e: InternalReplayError) -> Self { ReplayError(e) }
}

#[derive(Debug)]
pub(crate) enum InternalReplayError {
    /// Session expired
    SessionExpired(SystemTime),
    /// Invalid combination of state and event
    InvalidStateAndEvent(Box<ReceiverTypeState>, Box<SessionEvent>),
    /// Application storage error
    PersistenceFailure(ImplementationError),
}

/// Replay a receiver event log to get the receiver in its current state [ReceiverTypeState]
/// and a session history [SessionHistory]
pub fn replay_event_log<P>(
    persister: &P,
) -> Result<(ReceiverTypeState, SessionHistory), ReplayError>
where
    P: SessionPersister,
    P::SessionEvent: Into<SessionEvent> + Clone,
{
    let logs = persister
        .load()
        .map_err(|e| InternalReplayError::PersistenceFailure(Box::new(e).into()))?;
    let mut receiver =
        ReceiverTypeState::Uninitialized(Receiver { state: UninitializedReceiver {} });
    let mut history = SessionHistory::default();

    for event in logs {
        history.events.push(event.clone().into());
        receiver = receiver.process_event(event.into()).map_err(|e| {
            if let Err(storage_err) = persister.close() {
                return InternalReplayError::PersistenceFailure(Box::new(storage_err)).into();
            }
            e
        })?;
    }

    Ok((receiver, history))
}

/// A collection of events that have occurred during a receiver's session.
/// It is obtained by calling [replay_event_log].
#[derive(Default, Clone)]
pub struct SessionHistory {
    events: Vec<SessionEvent>,
}

impl SessionHistory {
    /// Receiver session Payjoin URI
    pub fn pj_uri<'a>(&self) -> Option<PjUri<'a>> {
        self.events.iter().find_map(|event| match event {
            SessionEvent::Created(session_context) => {
                // TODO this code was copied from ReceiverWithContext::pj_uri. Should be deduped
                use crate::uri::{PayjoinExtras, UrlExt};
                let id = session_context.id();
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

    /// Fallback transaction from the session if present
    pub fn fallback_tx(&self) -> Option<bitcoin::Transaction> {
        self.events.iter().find_map(|event| match event {
            SessionEvent::MaybeInputsOwned(proposal) =>
                Some(proposal.extract_tx_to_schedule_broadcast()),
            _ => None,
        })
    }

    /// Psbt with receiver contributed inputs
    pub fn psbt_with_contributed_inputs(&self) -> Option<bitcoin::Psbt> {
        self.events.iter().find_map(|event| match event {
            SessionEvent::ProvisionalProposal(proposal) => Some(proposal.payjoin_psbt.clone()),
            _ => None,
        })
    }

    /// Terminal error from the session if present
    pub fn terminal_error(&self) -> Option<(String, Option<JsonReply>)> {
        self.events.iter().find_map(|event| match event {
            SessionEvent::SessionInvalid(err_str, reply) => Some((err_str.clone(), reply.clone())),
            _ => None,
        })
    }

    /// Extract the error request to be posted on the directory if an error occurred.
    /// To process the response, use [crate::receive::v2::process_err_res]
    pub fn extract_err_req(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<Option<(Request, ohttp::ClientResponse)>, SessionError> {
        let session_context = match self.session_context() {
            Some(session_context) => session_context,
            None => return Ok(None),
        };
        let json_reply = match self.terminal_error() {
            Some((_, Some(json_reply))) => json_reply,
            _ => return Ok(None),
        };
        let (req, ctx) = extract_err_req(&json_reply, ohttp_relay, session_context)?;
        Ok(Some((req, ctx)))
    }

    pub fn session_context(&self) -> Option<&SessionContext> {
        self.events.iter().find_map(|event| match event {
            SessionEvent::Created(session_context) => Some(session_context),
            _ => None,
        })
    }
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
    SessionInvalid(String, Option<JsonReply>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::test_utils::InMemoryTestPersister;
    use crate::receive::v1::test::unchecked_proposal_from_test_vector;
    use crate::receive::v2::test::SHARED_CONTEXT;
    use crate::receive::v2::{
        MaybeInputsOwned, PayjoinProposal, ProvisionalProposal, UncheckedProposal, WithContext,
    };

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

    struct SessionHistoryExpectedOutcome {
        psbt_with_contributed_inputs: Option<bitcoin::Psbt>,
        fallback_tx: Option<bitcoin::Transaction>,
    }

    struct SessionHistoryTest {
        events: Vec<SessionEvent>,
        expected_session_history: SessionHistoryExpectedOutcome,
        expected_receiver_state: ReceiverTypeState,
    }

    fn run_session_history_test(test: SessionHistoryTest) {
        let persister = InMemoryTestPersister::<SessionEvent>::default();
        for event in test.events {
            persister.save_event(&event).expect("In memory persister shouldn't fail");
        }

        let (receiver, session_history) =
            replay_event_log(&persister).expect("In memory persister shouldn't fail");
        assert_eq!(receiver, test.expected_receiver_state);
        assert_eq!(
            session_history.psbt_with_contributed_inputs(),
            test.expected_session_history.psbt_with_contributed_inputs
        );
        assert_eq!(session_history.fallback_tx(), test.expected_session_history.fallback_tx);
    }

    #[test]
    fn test_replaying_session_creation() {
        let session_context = SHARED_CONTEXT.clone();
        let test = SessionHistoryTest {
            events: vec![SessionEvent::Created(session_context.clone())],
            expected_session_history: SessionHistoryExpectedOutcome {
                psbt_with_contributed_inputs: None,
                fallback_tx: None,
            },
            expected_receiver_state: ReceiverTypeState::WithContext(Receiver {
                state: WithContext { context: session_context },
            }),
        };
        run_session_history_test(test);
    }

    #[test]
    fn test_replaying_unchecked_proposal() {
        let session_context = SHARED_CONTEXT.clone();

        let test = SessionHistoryTest {
            events: vec![
                SessionEvent::Created(session_context.clone()),
                SessionEvent::UncheckedProposal((unchecked_proposal_from_test_vector(), None)),
            ],
            expected_session_history: SessionHistoryExpectedOutcome {
                psbt_with_contributed_inputs: None,
                fallback_tx: None,
            },
            expected_receiver_state: ReceiverTypeState::UncheckedProposal(Receiver {
                state: UncheckedProposal {
                    v1: unchecked_proposal_from_test_vector(),
                    context: session_context,
                },
            }),
        };
        run_session_history_test(test);
    }

    #[test]
    fn test_replaying_unchecked_proposal_with_reply_key() {
        let session_context = SHARED_CONTEXT.clone();

        let test = SessionHistoryTest {
            events: vec![
                SessionEvent::Created(session_context.clone()),
                SessionEvent::UncheckedProposal((
                    unchecked_proposal_from_test_vector(),
                    session_context.e.clone(),
                )),
            ],
            expected_session_history: SessionHistoryExpectedOutcome {
                psbt_with_contributed_inputs: None,
                fallback_tx: None,
            },
            expected_receiver_state: ReceiverTypeState::UncheckedProposal(Receiver {
                state: UncheckedProposal {
                    v1: unchecked_proposal_from_test_vector(),
                    context: session_context,
                },
            }),
        };
        run_session_history_test(test);
    }

    #[test]
    fn getting_fallback_tx() {
        let session_context = SHARED_CONTEXT.clone();
        let mut events = vec![];
        let unchecked_proposal = unchecked_proposal_from_test_vector();
        let maybe_inputs_owned = unchecked_proposal.clone().assume_interactive_receiver();
        let expected_fallback = maybe_inputs_owned.extract_tx_to_schedule_broadcast();

        events.push(SessionEvent::Created(session_context.clone()));
        events.push(SessionEvent::UncheckedProposal((unchecked_proposal, None)));
        events.push(SessionEvent::MaybeInputsOwned(maybe_inputs_owned.clone()));

        let test = SessionHistoryTest {
            events,
            expected_session_history: SessionHistoryExpectedOutcome {
                psbt_with_contributed_inputs: None,
                fallback_tx: Some(expected_fallback),
            },
            expected_receiver_state: ReceiverTypeState::MaybeInputsOwned(Receiver {
                state: MaybeInputsOwned { v1: maybe_inputs_owned, context: session_context },
            }),
        };
        run_session_history_test(test);
    }

    #[test]
    fn test_contributed_inputs() {
        let session_context = SHARED_CONTEXT.clone();
        let mut events = vec![];

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
        let expected_fallback = maybe_inputs_owned.extract_tx_to_schedule_broadcast();

        events.push(SessionEvent::Created(session_context.clone()));
        events.push(SessionEvent::UncheckedProposal((unchecked_proposal, None)));
        events.push(SessionEvent::MaybeInputsOwned(maybe_inputs_owned));
        events.push(SessionEvent::MaybeInputsSeen(maybe_inputs_seen));
        events.push(SessionEvent::OutputsUnknown(outputs_unknown));
        events.push(SessionEvent::WantsOutputs(wants_outputs));
        events.push(SessionEvent::WantsInputs(wants_inputs));
        events.push(SessionEvent::ProvisionalProposal(provisional_proposal.clone()));

        let test = SessionHistoryTest {
            events,
            expected_session_history: SessionHistoryExpectedOutcome {
                psbt_with_contributed_inputs: Some(provisional_proposal.payjoin_psbt.clone()),
                fallback_tx: Some(expected_fallback),
            },
            expected_receiver_state: ReceiverTypeState::ProvisionalProposal(Receiver {
                state: ProvisionalProposal { v1: provisional_proposal, context: session_context },
            }),
        };
        run_session_history_test(test);
    }

    #[test]
    fn test_payjoin_proposal() {
        let session_context = SHARED_CONTEXT.clone();
        let mut events = vec![];

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
        let expected_fallback = maybe_inputs_owned.extract_tx_to_schedule_broadcast();

        events.push(SessionEvent::Created(session_context.clone()));
        events.push(SessionEvent::UncheckedProposal((unchecked_proposal, None)));
        events.push(SessionEvent::MaybeInputsOwned(maybe_inputs_owned));
        events.push(SessionEvent::MaybeInputsSeen(maybe_inputs_seen));
        events.push(SessionEvent::OutputsUnknown(outputs_unknown));
        events.push(SessionEvent::WantsOutputs(wants_outputs));
        events.push(SessionEvent::WantsInputs(wants_inputs));
        events.push(SessionEvent::ProvisionalProposal(provisional_proposal.clone()));
        events.push(SessionEvent::PayjoinProposal(payjoin_proposal.clone()));

        let test = SessionHistoryTest {
            events,
            expected_session_history: SessionHistoryExpectedOutcome {
                psbt_with_contributed_inputs: Some(provisional_proposal.payjoin_psbt.clone()),
                fallback_tx: Some(expected_fallback),
            },
            expected_receiver_state: ReceiverTypeState::PayjoinProposal(Receiver {
                state: PayjoinProposal { v1: payjoin_proposal, context: session_context },
            }),
        };
        run_session_history_test(test);
    }
}

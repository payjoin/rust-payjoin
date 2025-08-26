use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use super::{ReceiveSession, SessionContext};
use crate::output_substitution::OutputSubstitution;
use crate::persist::SessionPersister;
use crate::receive::v2::{extract_err_req, SessionError};
use crate::receive::{common, JsonReply, Original, PsbtContext};
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
    InvalidStateAndEvent(Box<ReceiveSession>, Box<SessionEvent>),
    /// Application storage error
    PersistenceFailure(ImplementationError),
}

/// Replay a receiver event log to get the receiver in its current state [ReceiveSession]
/// and a session history [SessionHistory]
pub fn replay_event_log<P>(persister: &P) -> Result<(ReceiveSession, SessionHistory), ReplayError>
where
    P: SessionPersister,
    P::SessionEvent: Into<SessionEvent> + Clone,
{
    let logs = persister
        .load()
        .map_err(|e| InternalReplayError::PersistenceFailure(ImplementationError::new(e)))?;
    let mut receiver = ReceiveSession::Uninitialized;
    let mut history = SessionHistory::default();

    for event in logs {
        history.events.push(event.clone().into());
        receiver = receiver.process_event(event.into()).map_err(|e| {
            if let Err(storage_err) = persister.close() {
                return InternalReplayError::PersistenceFailure(ImplementationError::new(
                    storage_err,
                ))
                .into();
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
            SessionEvent::Created(session_context) =>
                Some(crate::receive::v2::pj_uri(session_context, OutputSubstitution::Disabled)),
            _ => None,
        })
    }

    fn get_unchecked_proposal(&self) -> Option<Original> {
        self.events.iter().find_map(|event| match event {
            SessionEvent::UncheckedProposal(proposal) => Some(proposal.0.clone()),
            _ => None,
        })
    }

    /// Fallback transaction from the session if present
    pub fn fallback_tx(&self) -> Option<bitcoin::Transaction> {
        self.events.iter().find_map(|event| match event {
            SessionEvent::MaybeInputsOwned() => Some(
                self.get_unchecked_proposal()
                    .expect("Should exist if this event is present")
                    .psbt
                    .extract_tx_unchecked_fee_rate(),
            ),
            _ => None,
        })
    }

    /// Psbt with fee contributions applied
    pub fn psbt_ready_for_signing(&self) -> Option<bitcoin::Psbt> {
        self.events.iter().find_map(|event| match event {
            SessionEvent::ProvisionalProposal(psbt_context) =>
                Some(psbt_context.payjoin_psbt.clone()),
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

    /// Construct the error request to be posted on the directory if an error occurred.
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

    fn session_context(&self) -> Option<&SessionContext> {
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
    UncheckedProposal((Original, Option<crate::HpkePublicKey>)),
    MaybeInputsOwned(),
    MaybeInputsSeen(),
    OutputsUnknown(),
    WantsOutputs(common::WantsOutputs),
    WantsInputs(common::WantsInputs),
    WantsFeeRange(common::WantsFeeRange),
    ProvisionalProposal(PsbtContext),
    PayjoinProposal(bitcoin::Psbt),
    /// Session is invalid. This is a irrecoverable error. Fallback tx should be broadcasted.
    /// TODO this should be any error type that is impl std::error and works well with serde, or as a fallback can be formatted as a string
    /// Reason being in some cases we still want to preserve the error b/c we can action on it. For now this is a terminal state and there is nothing to replay and is saved to be displayed.
    /// b/c its a terminal state and there is nothing to replay. So serialization will be lossy and that is fine.
    SessionInvalid(String, Option<JsonReply>),
}

#[cfg(test)]
mod tests {
    use payjoin_test_utils::{BoxError, EXAMPLE_URL};

    use super::*;
    use crate::persist::test_utils::InMemoryTestPersister;
    use crate::persist::NoopSessionPersister;
    use crate::receive::tests::original_from_test_vector;
    use crate::receive::v2::test::SHARED_CONTEXT;
    use crate::receive::v2::{
        Initialized, MaybeInputsOwned, PayjoinProposal, ProvisionalProposal, Receiver,
        UncheckedProposal,
    };

    fn unchecked_receiver_from_test_vector() -> Receiver<UncheckedProposal> {
        Receiver {
            state: UncheckedProposal {
                original: original_from_test_vector(),
                session_context: SHARED_CONTEXT.clone(),
            },
        }
    }

    #[test]
    fn test_session_event_serialization_roundtrip() {
        let persister = NoopSessionPersister::<SessionEvent>::default();

        let original = original_from_test_vector();
        let unchecked_proposal = unchecked_receiver_from_test_vector();
        let maybe_inputs_owned = unchecked_proposal
            .clone()
            .assume_interactive_receiver()
            .save(&persister)
            .expect("Save should not fail");
        let maybe_inputs_seen = maybe_inputs_owned
            .clone()
            .check_inputs_not_owned(&mut |_| Ok(false))
            .save(&persister)
            .expect("No inputs should be owned");
        let outputs_unknown = maybe_inputs_seen
            .clone()
            .check_no_inputs_seen_before(&mut |_| Ok(false))
            .save(&persister)
            .expect("No inputs should be seen before");
        let wants_outputs = outputs_unknown
            .clone()
            .identify_receiver_outputs(&mut |_| Ok(true))
            .save(&persister)
            .expect("Outputs should be identified");
        let wants_inputs =
            wants_outputs.clone().commit_outputs().save(&persister).expect("Save should not fail");
        let wants_fee_range =
            wants_inputs.clone().commit_inputs().save(&persister).expect("Save should not fail");
        let provisional_proposal = wants_fee_range
            .clone()
            .apply_fee_range(None, None)
            .save(&persister)
            .expect("Save should not fail");
        let payjoin_proposal = provisional_proposal
            .clone()
            .finalize_proposal(|psbt| Ok(psbt.clone()))
            .save(&persister)
            .expect("Payjoin proposal should be finalized");

        let test_cases = vec![
            SessionEvent::Created(SHARED_CONTEXT.clone()),
            SessionEvent::UncheckedProposal((original.clone(), None)),
            SessionEvent::UncheckedProposal((original, Some(crate::HpkeKeyPair::gen_keypair().1))),
            SessionEvent::MaybeInputsOwned(),
            SessionEvent::MaybeInputsSeen(),
            SessionEvent::OutputsUnknown(),
            SessionEvent::WantsOutputs(wants_outputs.state.inner.clone()),
            SessionEvent::WantsInputs(wants_inputs.state.inner.clone()),
            SessionEvent::WantsFeeRange(wants_fee_range.state.inner.clone()),
            SessionEvent::ProvisionalProposal(provisional_proposal.state.psbt_context.clone()),
            SessionEvent::PayjoinProposal(payjoin_proposal.psbt().clone()),
        ];

        for event in test_cases {
            let serialized = serde_json::to_string(&event).expect("Serialization should not fail");
            let deserialized: SessionEvent =
                serde_json::from_str(&serialized).expect("Deserialization should not fail");
            assert_eq!(event, deserialized);
        }
    }

    struct SessionHistoryExpectedOutcome {
        psbt_with_fee_contributions: Option<bitcoin::Psbt>,
        fallback_tx: Option<bitcoin::Transaction>,
    }

    struct SessionHistoryTest {
        events: Vec<SessionEvent>,
        expected_session_history: SessionHistoryExpectedOutcome,
        expected_receiver_state: ReceiveSession,
    }

    fn run_session_history_test(test: SessionHistoryTest) -> Result<(), BoxError> {
        let persister = InMemoryTestPersister::<SessionEvent>::default();
        for event in test.events {
            persister.save_event(event)?;
        }

        let (receiver, session_history) = replay_event_log(&persister)?;
        assert_eq!(receiver, test.expected_receiver_state);
        assert_eq!(
            session_history.psbt_ready_for_signing(),
            test.expected_session_history.psbt_with_fee_contributions
        );
        assert_eq!(session_history.fallback_tx(), test.expected_session_history.fallback_tx);
        Ok(())
    }

    #[test]
    fn test_replaying_session_creation() -> Result<(), BoxError> {
        let session_context = SHARED_CONTEXT.clone();
        let test = SessionHistoryTest {
            events: vec![SessionEvent::Created(session_context.clone())],
            expected_session_history: SessionHistoryExpectedOutcome {
                psbt_with_fee_contributions: None,
                fallback_tx: None,
            },
            expected_receiver_state: ReceiveSession::Initialized(Receiver {
                state: Initialized { context: session_context },
            }),
        };
        run_session_history_test(test)
    }

    #[test]
    fn test_replaying_unchecked_proposal() -> Result<(), BoxError> {
        let session_context = SHARED_CONTEXT.clone();
        let original = original_from_test_vector();

        let test = SessionHistoryTest {
            events: vec![
                SessionEvent::Created(session_context.clone()),
                SessionEvent::UncheckedProposal((original.clone(), None)),
            ],
            expected_session_history: SessionHistoryExpectedOutcome {
                psbt_with_fee_contributions: None,
                fallback_tx: None,
            },
            expected_receiver_state: ReceiveSession::UncheckedProposal(Receiver {
                state: UncheckedProposal { original, session_context },
            }),
        };
        run_session_history_test(test)
    }

    #[test]
    fn test_replaying_unchecked_proposal_expiry() {
        let now = SystemTime::now();
        let context = SessionContext { expiry: now, ..SHARED_CONTEXT.clone() };
        let original = original_from_test_vector();

        let test = SessionHistoryTest {
            events: vec![
                SessionEvent::Created(context.clone()),
                SessionEvent::UncheckedProposal((original.clone(), None)),
            ],
            expected_session_history: SessionHistoryExpectedOutcome {
                psbt_with_fee_contributions: None,
                fallback_tx: None,
            },
            expected_receiver_state: ReceiveSession::UncheckedProposal(Receiver {
                state: UncheckedProposal { original, session_context: context },
            }),
        };
        let session_history = run_session_history_test(test);

        match session_history {
            Err(error) => assert_eq!(
                error.to_string(),
                ReplayError::from(InternalReplayError::SessionExpired(now)).to_string()
            ),
            Ok(_) => panic!("Expected session expiry error, got success"),
        }
    }

    #[test]
    fn test_replaying_unchecked_proposal_with_reply_key() -> Result<(), BoxError> {
        let session_context = SHARED_CONTEXT.clone();
        let original = original_from_test_vector();

        let test = SessionHistoryTest {
            events: vec![
                SessionEvent::Created(session_context.clone()),
                SessionEvent::UncheckedProposal((original.clone(), session_context.e.clone())),
            ],
            expected_session_history: SessionHistoryExpectedOutcome {
                psbt_with_fee_contributions: None,
                fallback_tx: None,
            },
            expected_receiver_state: ReceiveSession::UncheckedProposal(Receiver {
                state: UncheckedProposal { original, session_context },
            }),
        };
        run_session_history_test(test)
    }

    #[test]
    fn getting_fallback_tx() -> Result<(), BoxError> {
        let persister = NoopSessionPersister::<SessionEvent>::default();
        let session_context = SHARED_CONTEXT.clone();
        let mut events = vec![];
        let original = original_from_test_vector();
        let maybe_inputs_owned = unchecked_receiver_from_test_vector()
            .assume_interactive_receiver()
            .save(&persister)
            .unwrap();
        let expected_fallback = maybe_inputs_owned.extract_tx_to_schedule_broadcast();

        events.push(SessionEvent::Created(session_context.clone()));
        events.push(SessionEvent::UncheckedProposal((original.clone(), None)));
        events.push(SessionEvent::MaybeInputsOwned());

        let test = SessionHistoryTest {
            events,
            expected_session_history: SessionHistoryExpectedOutcome {
                psbt_with_fee_contributions: None,
                fallback_tx: Some(expected_fallback),
            },
            expected_receiver_state: ReceiveSession::MaybeInputsOwned(Receiver {
                state: MaybeInputsOwned { original, session_context },
            }),
        };
        run_session_history_test(test)
    }

    #[test]
    fn test_contributed_inputs() -> Result<(), BoxError> {
        let persister = InMemoryTestPersister::<SessionEvent>::default();
        let session_context = SHARED_CONTEXT.clone();
        let mut events = vec![];

        let original = original_from_test_vector();
        let maybe_inputs_owned = unchecked_receiver_from_test_vector()
            .assume_interactive_receiver()
            .save(&persister)
            .unwrap();
        let maybe_inputs_seen = maybe_inputs_owned
            .clone()
            .check_inputs_not_owned(&mut |_| Ok(false))
            .save(&persister)
            .expect("No inputs should be owned");
        let outputs_unknown = maybe_inputs_seen
            .clone()
            .check_no_inputs_seen_before(&mut |_| Ok(false))
            .save(&persister)
            .expect("No inputs should be seen before");
        let wants_outputs = outputs_unknown
            .clone()
            .identify_receiver_outputs(&mut |_| Ok(true))
            .save(&persister)
            .expect("Outputs should be identified");
        let wants_inputs =
            wants_outputs.clone().commit_outputs().save(&persister).expect("Save should not fail");
        let wants_fee_range =
            wants_inputs.clone().commit_inputs().save(&persister).expect("Save should not fail");
        let provisional_proposal = wants_fee_range
            .clone()
            .apply_fee_range(None, None)
            .save(&persister)
            .expect("Contributed inputs should be valid");
        let expected_fallback = maybe_inputs_owned.extract_tx_to_schedule_broadcast();

        events.push(SessionEvent::Created(session_context.clone()));
        events.push(SessionEvent::UncheckedProposal((original.clone(), None)));
        events.push(SessionEvent::MaybeInputsOwned());
        events.push(SessionEvent::MaybeInputsSeen());
        events.push(SessionEvent::OutputsUnknown());
        events.push(SessionEvent::WantsOutputs(wants_outputs.state.inner.clone()));
        events.push(SessionEvent::WantsInputs(wants_inputs.state.inner.clone()));
        events.push(SessionEvent::WantsFeeRange(wants_fee_range.state.inner.clone()));
        events.push(SessionEvent::ProvisionalProposal(
            provisional_proposal.state.psbt_context.clone(),
        ));

        let test = SessionHistoryTest {
            events,
            expected_session_history: SessionHistoryExpectedOutcome {
                psbt_with_fee_contributions: Some(
                    provisional_proposal.state.psbt_context.payjoin_psbt.clone(),
                ),
                fallback_tx: Some(expected_fallback),
            },
            expected_receiver_state: ReceiveSession::ProvisionalProposal(Receiver {
                state: ProvisionalProposal {
                    psbt_context: provisional_proposal.state.psbt_context.clone(),
                    session_context,
                },
            }),
        };
        run_session_history_test(test)
    }

    #[test]
    fn test_payjoin_proposal() -> Result<(), BoxError> {
        let persister = NoopSessionPersister::<SessionEvent>::default();
        let session_context = SHARED_CONTEXT.clone();
        let mut events = vec![];

        let original = original_from_test_vector();
        let maybe_inputs_owned = unchecked_receiver_from_test_vector()
            .assume_interactive_receiver()
            .save(&persister)
            .unwrap();
        let maybe_inputs_seen = maybe_inputs_owned
            .clone()
            .check_inputs_not_owned(&mut |_| Ok(false))
            .save(&persister)
            .expect("No inputs should be owned");
        let outputs_unknown = maybe_inputs_seen
            .clone()
            .check_no_inputs_seen_before(&mut |_| Ok(false))
            .save(&persister)
            .expect("No inputs should be seen before");
        let wants_outputs = outputs_unknown
            .clone()
            .identify_receiver_outputs(&mut |_| Ok(true))
            .save(&persister)
            .expect("Outputs should be identified");
        let wants_inputs =
            wants_outputs.clone().commit_outputs().save(&persister).expect("Save should not fail");
        let wants_fee_range =
            wants_inputs.clone().commit_inputs().save(&persister).expect("Save should not fail");
        let provisional_proposal = wants_fee_range
            .clone()
            .apply_fee_range(None, None)
            .save(&persister)
            .expect("Contributed inputs should be valid");
        let payjoin_proposal = provisional_proposal
            .clone()
            .finalize_proposal(|psbt| Ok(psbt.clone()))
            .save(&persister)
            .expect("Payjoin proposal should be finalized");
        let expected_fallback = maybe_inputs_owned.extract_tx_to_schedule_broadcast();

        events.push(SessionEvent::Created(session_context.clone()));
        events.push(SessionEvent::UncheckedProposal((original.clone(), None)));
        events.push(SessionEvent::MaybeInputsOwned());
        events.push(SessionEvent::MaybeInputsSeen());
        events.push(SessionEvent::OutputsUnknown());
        events.push(SessionEvent::WantsOutputs(wants_outputs.state.inner.clone()));
        events.push(SessionEvent::WantsInputs(wants_inputs.state.inner.clone()));
        events.push(SessionEvent::WantsFeeRange(wants_fee_range.state.inner.clone()));
        events.push(SessionEvent::ProvisionalProposal(
            provisional_proposal.state.psbt_context.clone(),
        ));
        events.push(SessionEvent::PayjoinProposal(payjoin_proposal.psbt().clone()));

        let test = SessionHistoryTest {
            events,
            expected_session_history: SessionHistoryExpectedOutcome {
                psbt_with_fee_contributions: Some(
                    provisional_proposal.state.psbt_context.payjoin_psbt.clone(),
                ),
                fallback_tx: Some(expected_fallback),
            },
            expected_receiver_state: ReceiveSession::PayjoinProposal(Receiver {
                state: PayjoinProposal { psbt: payjoin_proposal.psbt().clone(), session_context },
            }),
        };
        run_session_history_test(test)
    }

    #[test]
    fn test_session_history_uri() -> Result<(), BoxError> {
        let session_context = SHARED_CONTEXT.clone();
        let events = vec![SessionEvent::Created(session_context.clone())];

        let uri =
            SessionHistory { events }.pj_uri().expect("SHARED_CONTEXT should contain valid uri");

        assert_ne!(uri.extras.pj_param.endpoint(), EXAMPLE_URL.clone());
        assert_eq!(uri.extras.output_substitution, OutputSubstitution::Disabled);

        Ok(())
    }
}

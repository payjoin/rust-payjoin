use serde::{Deserialize, Serialize};

use super::{ReceiveSession, SessionContext};
use crate::error::{InternalReplayError, ReplayError};
use crate::output_substitution::OutputSubstitution;
use crate::persist::SessionPersister;
use crate::receive::v2::{extract_err_req, SessionError};
use crate::receive::{common, InputPair, JsonReply, OriginalPayload, PsbtContext};
use crate::{ImplementationError, IntoUrl, PjUri, Request};

/// Replay a receiver event log to get the receiver in its current state [ReceiveSession]
/// and a session history [SessionHistory]
pub fn replay_event_log<P>(
    persister: &P,
) -> Result<(ReceiveSession, SessionHistory), ReplayError<ReceiveSession, SessionEvent>>
where
    P: SessionPersister,
    P::SessionEvent: Into<SessionEvent> + Clone,
    P::SessionEvent: From<SessionEvent>,
{
    let mut logs = persister
        .load()
        .map_err(|e| InternalReplayError::PersistenceFailure(ImplementationError::new(e)))?;

    let first_event = logs.next().ok_or(InternalReplayError::NoEvents)?.into();
    let mut session_events = vec![first_event.clone()];
    let mut receiver = match first_event {
        SessionEvent::Created(context) => ReceiveSession::new(context),
        _ => return Err(InternalReplayError::InvalidEvent(Box::new(first_event), None).into()),
    };
    for event in logs {
        session_events.push(event.clone().into());
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

    let history = SessionHistory::new(session_events.clone());
    let ctx = history.session_context();
    if ctx.expiration.elapsed() {
        return Err(InternalReplayError::Expired(ctx.expiration).into());
    }

    Ok((receiver, history))
}

/// A collection of events that have occurred during a receiver's session.
/// It is obtained by calling [replay_event_log].
#[derive(Debug, Clone)]
pub struct SessionHistory {
    events: Vec<SessionEvent>,
}

impl SessionHistory {
    pub(crate) fn new(events: Vec<SessionEvent>) -> Self {
        debug_assert!(!events.is_empty(), "Session event log must contain at least one event");
        Self { events }
    }

    /// Receiver session Payjoin URI
    pub fn pj_uri<'a>(&self) -> PjUri<'a> {
        self.events
            .iter()
            .find_map(|event| match event {
                SessionEvent::Created(session_context) =>
                    Some(crate::receive::v2::pj_uri(session_context, OutputSubstitution::Disabled)),
                _ => None,
            })
            .expect("Session event log must contain at least one event with pj_uri")
    }

    fn get_unchecked_proposal(&self) -> Option<OriginalPayload> {
        self.events.iter().find_map(|event| match event {
            SessionEvent::UncheckedOriginalPayload { original, .. } => Some(original.clone()),
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
        // FIXME ideally this should be more like a method of
        // Receiver<UncheckedOriginalPayload> and subsequent states instead of the
        // history as a whole since it doesn't make sense to call it before,
        // reaching that state.
        if !self.received_sender_proposal() {
            return Ok(None);
        }

        let session_context = self.session_context();
        let json_reply = match self.terminal_error() {
            Some((_, Some(json_reply))) => json_reply,
            _ => return Ok(None),
        };
        let (req, ctx) = extract_err_req(&json_reply, ohttp_relay, &session_context)?;
        Ok(Some((req, ctx)))
    }

    fn received_sender_proposal(&self) -> bool {
        self.events
            .iter()
            .any(|event| matches!(event, SessionEvent::UncheckedOriginalPayload { .. }))
    }

    fn session_context(&self) -> SessionContext {
        let mut initial_session_context = self
            .events
            .iter()
            .find_map(|event| match event {
                SessionEvent::Created(session_context) => Some(session_context.clone()),
                _ => None,
            })
            .expect("Session event log must contain at least one event with session_context");

        initial_session_context.reply_key = self.events.iter().find_map(|event| match event {
            SessionEvent::UncheckedOriginalPayload { reply_key, .. } => reply_key.clone(),
            _ => None,
        });

        initial_session_context
    }

    // Helper method to query the current status of the session.
    pub fn status(&self) -> SessionStatus {
        if self.session_context().expiration.elapsed() {
            return SessionStatus::Expired;
        }
        match self.events.last() {
            Some(SessionEvent::Closed(outcome)) => match outcome {
                SessionOutcome::Success => SessionStatus::Completed,
                SessionOutcome::Failure | SessionOutcome::Cancel => SessionStatus::Failed,
            },
            _ => SessionStatus::Active,
        }
    }
}

// Represents the status of a session that can be inferred from the information in the session
// event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    Active,
    Expired,
    Failed,
    Completed,
}

/// Represents a piece of information that the receiver has obtained from the session
/// Each event can be used to transition the receiver state machine to a new state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionEvent {
    Created(SessionContext),
    UncheckedOriginalPayload {
        original: OriginalPayload,
        reply_key: Option<crate::HpkePublicKey>,
    },
    MaybeInputsOwned(),
    MaybeInputsSeen(),
    OutputsUnknown(),
    WantsOutputs(Vec<usize>),
    WantsInputs(common::WantsInputs),
    WantsFeeRange(Vec<InputPair>),
    ProvisionalProposal(PsbtContext),
    PayjoinProposal(bitcoin::Psbt),
    /// Session is invalid. This is a irrecoverable error. Fallback tx should be broadcasted.
    /// TODO this should be any error type that is impl std::error and works well with serde, or as a fallback can be formatted as a string
    /// Reason being in some cases we still want to preserve the error b/c we can action on it. For now this is a terminal state and there is nothing to replay and is saved to be displayed.
    /// b/c its a terminal state and there is nothing to replay. So serialization will be lossy and that is fine.
    SessionInvalid(String, Option<JsonReply>),
    Closed(SessionOutcome),
}

/// Represents all possible outcomes for a closed Payjoin session
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionOutcome {
    /// Payjoin completed successfully
    /// TODO: this should include the sender's witnesses once tx monitoring is implemented
    /// (this will ensure the payjoin txid can be computed)
    Success,
    /// Payjoin failed to complete due to a counterparty deviation from the protocol
    Failure,
    /// Payjoin was cancelled by the user
    Cancel,
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use payjoin_test_utils::{BoxError, EXAMPLE_URL};

    use super::*;
    use crate::persist::test_utils::InMemoryTestPersister;
    use crate::persist::NoopSessionPersister;
    use crate::receive::tests::original_from_test_vector;
    use crate::receive::v2::test::{mock_err, SHARED_CONTEXT};
    use crate::receive::v2::{
        Initialized, MaybeInputsOwned, PayjoinProposal, ProvisionalProposal, Receiver,
        UncheckedOriginalPayload,
    };

    fn unchecked_receiver_from_test_vector() -> Receiver<UncheckedOriginalPayload> {
        Receiver {
            state: UncheckedOriginalPayload { original: original_from_test_vector() },
            session_context: SHARED_CONTEXT.clone(),
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
            SessionEvent::UncheckedOriginalPayload { original: original.clone(), reply_key: None },
            SessionEvent::UncheckedOriginalPayload {
                original,
                reply_key: Some(crate::HpkeKeyPair::gen_keypair().1),
            },
            SessionEvent::MaybeInputsOwned(),
            SessionEvent::MaybeInputsSeen(),
            SessionEvent::OutputsUnknown(),
            SessionEvent::WantsOutputs(wants_outputs.state.inner.owned_vouts.clone()),
            SessionEvent::WantsInputs(wants_inputs.state.inner.clone()),
            SessionEvent::WantsFeeRange(wants_fee_range.state.inner.receiver_inputs.clone()),
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
        expected_status: SessionStatus,
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
        assert_eq!(session_history.status(), test.expected_session_history.expected_status);
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
                expected_status: SessionStatus::Active,
            },
            expected_receiver_state: ReceiveSession::Initialized(Receiver {
                state: Initialized {},
                session_context,
            }),
        };
        run_session_history_test(test)
    }

    #[test]
    fn test_replaying_session_creation_with_expired_session() -> Result<(), BoxError> {
        let expiration = (SystemTime::now() - Duration::from_secs(1)).try_into().unwrap();
        let session_context = SessionContext { expiration, ..SHARED_CONTEXT.clone() };
        let persister = InMemoryTestPersister::<SessionEvent>::default();
        persister.save_event(SessionEvent::Created(session_context))?;

        let err = replay_event_log(&persister).expect_err("session should be expired");
        let expected_err: ReplayError<ReceiveSession, SessionEvent> =
            InternalReplayError::Expired(expiration).into();
        assert_eq!(err.to_string(), expected_err.to_string());
        Ok(())
    }

    #[test]
    fn test_replaying_unchecked_proposal() -> Result<(), BoxError> {
        let session_context = SHARED_CONTEXT.clone();
        let original = original_from_test_vector();
        let reply_key = Some(crate::HpkeKeyPair::gen_keypair().1);

        let test = SessionHistoryTest {
            events: vec![
                SessionEvent::Created(session_context.clone()),
                SessionEvent::UncheckedOriginalPayload {
                    original: original.clone(),
                    reply_key: reply_key.clone(),
                },
            ],
            expected_session_history: SessionHistoryExpectedOutcome {
                psbt_with_fee_contributions: None,
                fallback_tx: None,
                expected_status: SessionStatus::Active,
            },
            expected_receiver_state: ReceiveSession::UncheckedOriginalPayload(Receiver {
                state: UncheckedOriginalPayload { original },
                session_context: SessionContext { reply_key, ..session_context },
            }),
        };
        run_session_history_test(test)
    }

    #[test]
    fn test_replaying_unchecked_proposal_with_reply_key() -> Result<(), BoxError> {
        let session_context = SHARED_CONTEXT.clone();
        let original = original_from_test_vector();
        let reply_key = Some(crate::HpkeKeyPair::gen_keypair().1);

        let test = SessionHistoryTest {
            events: vec![
                SessionEvent::Created(session_context.clone()),
                SessionEvent::UncheckedOriginalPayload {
                    original: original.clone(),
                    reply_key: reply_key.clone(),
                },
            ],
            expected_session_history: SessionHistoryExpectedOutcome {
                psbt_with_fee_contributions: None,
                fallback_tx: None,
                expected_status: SessionStatus::Active,
            },
            expected_receiver_state: ReceiveSession::UncheckedOriginalPayload(Receiver {
                state: UncheckedOriginalPayload { original },
                session_context: SessionContext { reply_key, ..session_context },
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
        let reply_key = Some(crate::HpkeKeyPair::gen_keypair().1);

        events.push(SessionEvent::Created(session_context.clone()));
        events.push(SessionEvent::UncheckedOriginalPayload {
            original: original.clone(),
            reply_key: reply_key.clone(),
        });
        events.push(SessionEvent::MaybeInputsOwned());

        let test = SessionHistoryTest {
            events,
            expected_session_history: SessionHistoryExpectedOutcome {
                psbt_with_fee_contributions: None,
                fallback_tx: Some(expected_fallback),
                expected_status: SessionStatus::Active,
            },
            expected_receiver_state: ReceiveSession::MaybeInputsOwned(Receiver {
                state: MaybeInputsOwned { original },
                session_context: SessionContext { reply_key, ..session_context },
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
        let reply_key = Some(crate::HpkeKeyPair::gen_keypair().1);

        events.push(SessionEvent::Created(session_context.clone()));
        events.push(SessionEvent::UncheckedOriginalPayload {
            original: original.clone(),
            reply_key: reply_key.clone(),
        });
        events.push(SessionEvent::MaybeInputsOwned());
        events.push(SessionEvent::MaybeInputsSeen());
        events.push(SessionEvent::OutputsUnknown());
        events.push(SessionEvent::WantsOutputs(wants_outputs.state.inner.owned_vouts.clone()));
        events.push(SessionEvent::WantsInputs(wants_inputs.state.inner.clone()));
        events
            .push(SessionEvent::WantsFeeRange(wants_fee_range.state.inner.receiver_inputs.clone()));
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
                expected_status: SessionStatus::Active,
            },
            expected_receiver_state: ReceiveSession::ProvisionalProposal(Receiver {
                state: ProvisionalProposal {
                    psbt_context: provisional_proposal.state.psbt_context.clone(),
                },
                session_context: SessionContext { reply_key, ..session_context },
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
        let reply_key = Some(crate::HpkeKeyPair::gen_keypair().1);

        events.push(SessionEvent::Created(session_context.clone()));
        events.push(SessionEvent::UncheckedOriginalPayload {
            original: original.clone(),
            reply_key: reply_key.clone(),
        });
        events.push(SessionEvent::MaybeInputsOwned());
        events.push(SessionEvent::MaybeInputsSeen());
        events.push(SessionEvent::OutputsUnknown());
        events.push(SessionEvent::WantsOutputs(wants_outputs.state.inner.owned_vouts.clone()));
        events.push(SessionEvent::WantsInputs(wants_inputs.state.inner.clone()));
        events
            .push(SessionEvent::WantsFeeRange(wants_fee_range.state.inner.receiver_inputs.clone()));
        events.push(SessionEvent::ProvisionalProposal(
            provisional_proposal.state.psbt_context.clone(),
        ));
        events.push(SessionEvent::PayjoinProposal(payjoin_proposal.psbt().clone()));
        events.push(SessionEvent::Closed(SessionOutcome::Success));

        let test = SessionHistoryTest {
            events,
            expected_session_history: SessionHistoryExpectedOutcome {
                psbt_with_fee_contributions: Some(
                    provisional_proposal.state.psbt_context.payjoin_psbt.clone(),
                ),
                fallback_tx: Some(expected_fallback),
                expected_status: SessionStatus::Completed,
            },
            expected_receiver_state: ReceiveSession::PayjoinProposal(Receiver {
                state: PayjoinProposal { psbt: payjoin_proposal.psbt().clone() },
                session_context: SessionContext { reply_key, ..session_context },
            }),
        };
        run_session_history_test(test)
    }

    #[test]
    fn test_session_history_uri() -> Result<(), BoxError> {
        let session_context = SHARED_CONTEXT.clone();
        let events = vec![SessionEvent::Created(session_context.clone())];

        let uri = SessionHistory { events }.pj_uri();

        assert_ne!(uri.extras.pj_param.endpoint().0, EXAMPLE_URL.clone());
        assert_eq!(uri.extras.output_substitution, OutputSubstitution::Disabled);

        Ok(())
    }

    #[test]
    fn test_skipped_session_extract_err_request() -> Result<(), BoxError> {
        let ohttp_relay = EXAMPLE_URL.as_str();
        let mock_err = mock_err();

        let session_history = SessionHistory { events: vec![SessionEvent::MaybeInputsOwned()] };
        let err_req = session_history.extract_err_req(ohttp_relay)?;
        assert!(err_req.is_none());

        let session_history = SessionHistory {
            events: vec![
                SessionEvent::MaybeInputsOwned(),
                SessionEvent::SessionInvalid(mock_err.0.clone(), Some(mock_err.1.clone())),
            ],
        };

        let err_req = session_history.extract_err_req(ohttp_relay)?;
        assert!(err_req.is_none());

        let session_history = SessionHistory {
            events: vec![
                SessionEvent::Created(SHARED_CONTEXT.clone()),
                SessionEvent::MaybeInputsOwned(),
                SessionEvent::SessionInvalid(mock_err.0.clone(), Some(mock_err.1.clone())),
            ],
        };

        let err_req = session_history.extract_err_req(ohttp_relay)?;
        assert!(err_req.is_none());
        Ok(())
    }

    #[test]
    fn test_session_extract_err_req_reply_key() -> Result<(), BoxError> {
        let proposal = original_from_test_vector();
        let ohttp_relay = EXAMPLE_URL.as_str();
        let mock_err = mock_err();

        let session_history_one = SessionHistory {
            events: vec![
                SessionEvent::Created(SHARED_CONTEXT.clone()),
                SessionEvent::UncheckedOriginalPayload {
                    original: proposal.clone(),
                    reply_key: Some(crate::HpkeKeyPair::gen_keypair().1),
                },
                SessionEvent::SessionInvalid(mock_err.0.clone(), Some(mock_err.1.clone())),
            ],
        };

        let err_req_one = session_history_one.extract_err_req(ohttp_relay)?;
        assert!(err_req_one.is_some());

        let session_history_two = SessionHistory {
            events: vec![
                SessionEvent::Created(SHARED_CONTEXT.clone()),
                SessionEvent::UncheckedOriginalPayload {
                    original: proposal.clone(),
                    reply_key: Some(crate::HpkeKeyPair::gen_keypair().1),
                },
                SessionEvent::SessionInvalid(mock_err.0, Some(mock_err.1)),
            ],
        };

        let err_req_two = session_history_two.extract_err_req(ohttp_relay)?;
        assert!(err_req_two.is_some());
        assert_ne!(
            session_history_one.session_context().reply_key,
            session_history_two.session_context().reply_key
        );

        Ok(())
    }
}

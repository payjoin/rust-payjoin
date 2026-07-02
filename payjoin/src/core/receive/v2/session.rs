use serde::{Deserialize, Serialize};

use super::{ReceiveSession, SessionContext};
use crate::error::{InternalReplayError, ReplayError};
use crate::output_substitution::OutputSubstitution;
use crate::persist::{AsyncSessionPersister, SessionPersister};
use crate::receive::{InputPair, JsonReply, OriginalPayload, PsbtContext};
use crate::{ImplementationError, PjUri};

fn replay_events(
    mut logs: impl Iterator<Item = SessionEvent>,
) -> Result<(ReceiveSession, Vec<SessionEvent>), ReplayError<ReceiveSession, SessionEvent>> {
    let first_event = logs.next().ok_or(InternalReplayError::NoEvents)?;
    let mut session_events = vec![first_event.clone()];
    let mut receiver = match first_event {
        SessionEvent::Created(context) => ReceiveSession::new(context),
        _ => return Err(InternalReplayError::InvalidEvent(Box::new(first_event), None).into()),
    };

    for event in logs {
        session_events.push(event.clone());
        receiver = receiver.process_event(event)?;
    }
    Ok((receiver, session_events))
}

fn construct_history(
    session_events: Vec<SessionEvent>,
    receiver: &ReceiveSession,
) -> Result<SessionHistory, ReplayError<ReceiveSession, SessionEvent>> {
    let history = SessionHistory::new(session_events);
    // Closed sessions terminated before expiration; do not surface an expired error for them.
    if !matches!(receiver, ReceiveSession::Closed(_)) {
        let ctx = history.session_context();
        if ctx.expiration.elapsed() {
            return Err(InternalReplayError::Expired(ctx.expiration).into());
        }
    }
    Ok(history)
}

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
    let logs = persister
        .load()
        .map_err(|e| InternalReplayError::PersistenceFailure(ImplementationError::new(e)))?;

    let (receiver, session_events) = match replay_events(logs.map(|e| e.into())) {
        Ok(r) => r,
        Err(e) => {
            persister.close().map_err(|ce| {
                InternalReplayError::PersistenceFailure(ImplementationError::new(ce))
            })?;
            return Err(e);
        }
    };

    let history = construct_history(session_events, &receiver)?;
    Ok((receiver, history))
}

/// Async version of [replay_event_log]
pub async fn replay_event_log_async<P>(
    persister: &P,
) -> Result<(ReceiveSession, SessionHistory), ReplayError<ReceiveSession, SessionEvent>>
where
    P: AsyncSessionPersister,
    P::SessionEvent: Into<SessionEvent> + Clone,
    P::SessionEvent: From<SessionEvent>,
{
    let logs = persister
        .load()
        .await
        .map_err(|e| InternalReplayError::PersistenceFailure(ImplementationError::new(e)))?;

    let (receiver, session_events) = match replay_events(logs.map(|e| e.into())) {
        Ok(r) => r,
        Err(e) => {
            persister.close().await.map_err(|ce| {
                InternalReplayError::PersistenceFailure(ImplementationError::new(ce))
            })?;
            return Err(e);
        }
    };

    let history = construct_history(session_events, &receiver)?;
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
            SessionEvent::RetrievedOriginalPayload { original, .. } => Some(original.clone()),
            _ => None,
        })
    }

    /// Fallback transaction from the session if present
    pub fn fallback_tx(&self) -> Option<bitcoin::Transaction> {
        self.events.iter().find_map(|event| match event {
            SessionEvent::CheckedBroadcastSuitability() => Some(
                self.get_unchecked_proposal()
                    .expect("Should exist if this event is present")
                    .psbt
                    .extract_tx_unchecked_fee_rate(),
            ),
            _ => None,
        })
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
            SessionEvent::RetrievedOriginalPayload { reply_key, .. } => reply_key.clone(),
            _ => None,
        });

        initial_session_context
    }

    /// Helper method to query the current status of the session.
    pub fn status(&self) -> SessionStatus {
        // Terminal states take precedence over expiration: a session that has reached
        // a `Closed` outcome is done regardless of whether its expiration has elapsed.
        match self.events.last() {
            Some(SessionEvent::Closed(outcome)) => match outcome {
                SessionOutcome::Success(_) | SessionOutcome::PayjoinProposalSent =>
                    SessionStatus::Completed,
                SessionOutcome::Aborted => SessionStatus::Failed,
                SessionOutcome::FallbackBroadcasted => SessionStatus::FallbackBroadcasted,
            },
            Some(SessionEvent::Cancelled | SessionEvent::ProtocolFailed) =>
                SessionStatus::PendingFallback,
            _ if self.session_context().expiration.elapsed() => SessionStatus::Expired,
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
    FallbackBroadcasted,
    PendingFallback,
}

/// Represents a piece of information that the receiver has obtained from the session
/// Each event can be used to transition the receiver state machine to a new state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionEvent {
    Created(SessionContext),
    RetrievedOriginalPayload { original: OriginalPayload, reply_key: Option<crate::HpkePublicKey> },
    CheckedBroadcastSuitability(),
    CheckedInputsNotOwned(),
    CheckedNoInputsSeenBefore(),
    IdentifiedReceiverOutputs(Vec<usize>),
    CommittedOutputs(Vec<bitcoin::TxOut>),
    CommittedInputs(Vec<InputPair>),
    AppliedFeeRange(PsbtContext),
    FinalizedProposal(bitcoin::Psbt),
    GotReplyableError(JsonReply),
    PostedPayjoinProposal(),
    Cancelled,
    ProtocolFailed,
    Closed(SessionOutcome),
}

/// Represents all possible outcomes for a closed Payjoin session
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionOutcome {
    /// Payjoin completed successfully
    Success(Vec<(bitcoin::ScriptBuf, bitcoin::Witness)>),
    /// Payjoin was not successful
    Aborted,
    /// Fallback transaction was broadcasted
    FallbackBroadcasted,
    /// Payjoin proposal was sent, but its broadcast status cannot be tracked because
    /// the sender is using non-SegWit inputs which will change the transaction ID
    /// of the proposal
    PayjoinProposalSent,
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use payjoin_test_utils::{BoxError, EXAMPLE_URL};

    use super::*;
    use crate::persist::{InMemoryAsyncPersister, InMemoryPersister};
    use crate::receive::tests::original_from_test_vector;
    use crate::receive::v2::test::{mock_err, SHARED_CONTEXT};
    use crate::receive::v2::{
        Initialized, MaybeInputsOwned, PendingFallback, ProvisionalProposal, Receiver,
        UncheckedOriginalPayload,
    };
    use crate::receive::{InternalPayloadError, PayloadError};

    fn unchecked_receiver_from_test_vector() -> Receiver<UncheckedOriginalPayload> {
        Receiver {
            state: UncheckedOriginalPayload { original: original_from_test_vector() },
            session_context: SHARED_CONTEXT.clone(),
        }
    }

    #[test]
    fn test_session_event_serialization_roundtrip() {
        let persister = InMemoryPersister::<SessionEvent>::default();

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
            SessionEvent::RetrievedOriginalPayload { original: original.clone(), reply_key: None },
            SessionEvent::RetrievedOriginalPayload {
                original,
                reply_key: Some(crate::HpkeKeyPair::gen_keypair().1),
            },
            SessionEvent::CheckedBroadcastSuitability(),
            SessionEvent::CheckedInputsNotOwned(),
            SessionEvent::CheckedNoInputsSeenBefore(),
            SessionEvent::IdentifiedReceiverOutputs(wants_outputs.state.inner.owned_vouts.clone()),
            SessionEvent::CommittedOutputs(
                wants_outputs.state.inner.payjoin_psbt.unsigned_tx.output,
            ),
            SessionEvent::CommittedInputs(wants_fee_range.state.inner.receiver_inputs.clone()),
            SessionEvent::AppliedFeeRange(provisional_proposal.state.psbt_context.clone()),
            SessionEvent::FinalizedProposal(payjoin_proposal.psbt().clone()),
            SessionEvent::GotReplyableError(mock_err()),
            SessionEvent::Cancelled,
            SessionEvent::ProtocolFailed,
        ];

        for event in test_cases {
            let serialized = serde_json::to_string(&event).expect("Serialization should not fail");
            let deserialized: SessionEvent =
                serde_json::from_str(&serialized).expect("Deserialization should not fail");
            assert_eq!(event, deserialized);
        }
    }

    #[derive(Clone)]
    struct SessionHistoryExpectedOutcome {
        fallback_tx: Option<bitcoin::Transaction>,
        expected_status: SessionStatus,
    }

    #[derive(Clone)]
    struct SessionHistoryTest {
        events: Vec<SessionEvent>,
        expected_session_history: SessionHistoryExpectedOutcome,
        expected_receiver_state: ReceiveSession,
    }

    fn verify_session_result(
        session_result: Result<
            (ReceiveSession, SessionHistory),
            crate::error::ReplayError<ReceiveSession, SessionEvent>,
        >,
        test: &SessionHistoryTest,
    ) {
        let (receiver, session_history) = session_result.expect("replay should succeed");
        assert_eq!(receiver, test.expected_receiver_state);
        assert_eq!(session_history.fallback_tx(), test.expected_session_history.fallback_tx);
        assert_eq!(session_history.status(), test.expected_session_history.expected_status);
        let expected_reply_key = test.events.iter().find_map(|event| match event {
            SessionEvent::RetrievedOriginalPayload { reply_key, .. } => reply_key.clone(),
            _ => None,
        });
        assert_eq!(session_history.session_context().reply_key, expected_reply_key);
    }

    fn run_session_history_test(test: &SessionHistoryTest) {
        let persister = InMemoryPersister::<SessionEvent>::default();
        for event in test.events.clone() {
            persister.save_event(event).expect("In memory persister shouldn't fail");
        }
        verify_session_result(replay_event_log(&persister), test);
    }

    async fn run_session_history_test_async(test: &SessionHistoryTest) {
        let persister = InMemoryAsyncPersister::<SessionEvent>::default();
        for event in test.events.clone() {
            persister.save_event(event).await.expect("In memory persister shouldn't fail");
        }
        verify_session_result(replay_event_log_async(&persister).await, test);
    }

    #[tokio::test]
    async fn test_replaying_session_creation() {
        let session_context = SHARED_CONTEXT.clone();
        let test = SessionHistoryTest {
            events: vec![SessionEvent::Created(session_context.clone())],
            expected_session_history: SessionHistoryExpectedOutcome {
                fallback_tx: None,
                expected_status: SessionStatus::Active,
            },
            expected_receiver_state: ReceiveSession::Initialized(Receiver {
                state: Initialized {},
                session_context,
            }),
        };
        run_session_history_test(&test);
        run_session_history_test_async(&test).await;
    }

    #[tokio::test]
    async fn test_replaying_session_creation_with_expired_session() {
        let expiration = (SystemTime::now() - Duration::from_secs(1)).try_into().unwrap();
        let session_context = SessionContext { expiration, ..SHARED_CONTEXT.clone() };

        let persister = InMemoryPersister::<SessionEvent>::default();
        persister
            .save_event(SessionEvent::Created(session_context.clone()))
            .expect("in memory persister save should not fail");
        let err = replay_event_log(&persister).expect_err("session should be expired");
        let expected_err: ReplayError<ReceiveSession, SessionEvent> =
            InternalReplayError::Expired(expiration).into();
        assert_eq!(err.to_string(), expected_err.to_string());

        let persister = InMemoryAsyncPersister::<SessionEvent>::default();
        persister
            .save_event(SessionEvent::Created(session_context))
            .await
            .expect("in memory async persister save should not fail");
        let err = replay_event_log_async(&persister).await.expect_err("session should be expired");
        let expected_err: ReplayError<ReceiveSession, SessionEvent> =
            InternalReplayError::Expired(expiration).into();
        assert_eq!(err.to_string(), expected_err.to_string());
    }

    #[test]
    fn status_prefers_closed_outcome_over_expired() {
        let expiration = (SystemTime::now() - Duration::from_secs(1)).try_into().unwrap();
        let session_context = SessionContext { expiration, ..SHARED_CONTEXT.clone() };

        let success = SessionHistory::new(vec![
            SessionEvent::Created(session_context.clone()),
            SessionEvent::Closed(SessionOutcome::Success(vec![])),
        ]);
        assert_eq!(success.status(), SessionStatus::Completed);

        let aborted = SessionHistory::new(vec![
            SessionEvent::Created(session_context.clone()),
            SessionEvent::Closed(SessionOutcome::Aborted),
        ]);
        assert_eq!(aborted.status(), SessionStatus::Failed);

        let fallback = SessionHistory::new(vec![
            SessionEvent::Created(session_context.clone()),
            SessionEvent::Closed(SessionOutcome::FallbackBroadcasted),
        ]);
        assert_eq!(fallback.status(), SessionStatus::FallbackBroadcasted);

        // Sessions that never reached a terminal state still report Expired.
        let still_open = SessionHistory::new(vec![SessionEvent::Created(session_context)]);
        assert_eq!(still_open.status(), SessionStatus::Expired);
    }

    #[tokio::test]
    async fn test_replaying_closed_session_past_expiration_is_not_expired() {
        let expiration = (SystemTime::now() - Duration::from_secs(1)).try_into().unwrap();
        let session_context = SessionContext { expiration, ..SHARED_CONTEXT.clone() };

        let persister = InMemoryPersister::<SessionEvent>::default();
        persister
            .save_event(SessionEvent::Created(session_context.clone()))
            .expect("in memory persister save should not fail");
        persister
            .save_event(SessionEvent::Closed(SessionOutcome::Success(vec![])))
            .expect("in memory persister save should not fail");
        let (state, _) =
            replay_event_log(&persister).expect("closed session should replay successfully");
        assert!(matches!(state, ReceiveSession::Closed(SessionOutcome::Success(_))));

        let persister = InMemoryAsyncPersister::<SessionEvent>::default();
        persister
            .save_event(SessionEvent::Created(session_context))
            .await
            .expect("in memory async persister save should not fail");
        persister
            .save_event(SessionEvent::Closed(SessionOutcome::Success(vec![])))
            .await
            .expect("in memory async persister save should not fail");
        let (state, _) = replay_event_log_async(&persister)
            .await
            .expect("closed session should replay successfully");
        assert!(matches!(state, ReceiveSession::Closed(SessionOutcome::Success(_))));
    }

    #[tokio::test]
    async fn test_replaying_session_with_missing_created_event() {
        let persister = InMemoryPersister::<SessionEvent>::default();
        persister
            .save_event(SessionEvent::CheckedBroadcastSuitability())
            .expect("in memory persister save should not fail");
        assert!(!persister.inner.lock().expect("session read should succeed").is_closed);
        let err = replay_event_log(&persister).expect_err("session replay should be fail");
        let expected_err: ReplayError<ReceiveSession, SessionEvent> =
            InternalReplayError::InvalidEvent(
                Box::new(SessionEvent::CheckedBroadcastSuitability()),
                None,
            )
            .into();
        assert_eq!(err.to_string(), expected_err.to_string());
        assert!(persister.inner.lock().expect("lock should not be poisoned").is_closed);

        let persister = InMemoryAsyncPersister::<SessionEvent>::default();
        persister
            .save_event(SessionEvent::CheckedBroadcastSuitability())
            .await
            .expect("in memory async persister save should not fail");
        assert!(!persister.inner.lock().await.is_closed);
        let err =
            replay_event_log_async(&persister).await.expect_err("session replay should be fail");
        let expected_err: ReplayError<ReceiveSession, SessionEvent> =
            InternalReplayError::InvalidEvent(
                Box::new(SessionEvent::CheckedBroadcastSuitability()),
                None,
            )
            .into();
        assert_eq!(err.to_string(), expected_err.to_string());
        assert!(persister.inner.lock().await.is_closed);
    }

    #[test]
    fn replaying_empty_identified_receiver_outputs_errors() {
        let persister = InMemoryPersister::<SessionEvent>::default();
        let session_context = SHARED_CONTEXT.clone();
        let original = original_from_test_vector();

        for event in [
            SessionEvent::Created(session_context),
            SessionEvent::RetrievedOriginalPayload { original, reply_key: None },
            SessionEvent::CheckedBroadcastSuitability(),
            SessionEvent::CheckedInputsNotOwned(),
            SessionEvent::CheckedNoInputsSeenBefore(),
            SessionEvent::IdentifiedReceiverOutputs(vec![]),
        ] {
            persister.save_event(event).expect("in memory persister save should not fail");
        }

        let err = replay_event_log(&persister).expect_err("session replay should fail");
        let expected_err: ReplayError<ReceiveSession, SessionEvent> =
            InternalReplayError::InvalidEventPayload(
                "IdentifiedReceiverOutputs must include at least one output".to_string(),
            )
            .into();
        assert_eq!(err.to_string(), expected_err.to_string());
        assert!(persister.inner.lock().expect("lock should not be poisoned").is_closed);
    }

    #[test]
    fn replaying_committed_outputs_without_change_output_errors() {
        let persister = InMemoryPersister::<SessionEvent>::default();
        let session_context = SHARED_CONTEXT.clone();
        let original = original_from_test_vector();
        let committed_outputs = vec![original.psbt.unsigned_tx.output[0].clone()];

        for event in [
            SessionEvent::Created(session_context),
            SessionEvent::RetrievedOriginalPayload { original, reply_key: None },
            SessionEvent::CheckedBroadcastSuitability(),
            SessionEvent::CheckedInputsNotOwned(),
            SessionEvent::CheckedNoInputsSeenBefore(),
            SessionEvent::IdentifiedReceiverOutputs(vec![1]),
            SessionEvent::CommittedOutputs(committed_outputs),
        ] {
            persister.save_event(event).expect("in memory persister save should not fail");
        }

        let err = replay_event_log(&persister).expect_err("session replay should fail");
        let expected_err: ReplayError<ReceiveSession, SessionEvent> =
            InternalReplayError::InvalidEventPayload(
                "CommittedOutputs has 1 outputs, but receiver change output index is 1".to_string(),
            )
            .into();
        assert_eq!(err.to_string(), expected_err.to_string());
        assert!(persister.inner.lock().expect("lock should not be poisoned").is_closed);
    }

    #[tokio::test]
    async fn test_replaying_unchecked_proposal() {
        let session_context = SHARED_CONTEXT.clone();
        let original = original_from_test_vector();
        let reply_key = Some(crate::HpkeKeyPair::gen_keypair().1);

        let test = SessionHistoryTest {
            events: vec![
                SessionEvent::Created(session_context.clone()),
                SessionEvent::RetrievedOriginalPayload {
                    original: original.clone(),
                    reply_key: reply_key.clone(),
                },
            ],
            expected_session_history: SessionHistoryExpectedOutcome {
                fallback_tx: None,
                expected_status: SessionStatus::Active,
            },
            expected_receiver_state: ReceiveSession::UncheckedOriginalPayload(Receiver {
                state: UncheckedOriginalPayload { original },
                session_context: SessionContext { reply_key, ..session_context },
            }),
        };
        run_session_history_test(&test);
        run_session_history_test_async(&test).await;
    }

    #[tokio::test]
    async fn test_replaying_unchecked_proposal_with_reply_key() {
        let session_context = SHARED_CONTEXT.clone();
        let original = original_from_test_vector();
        let reply_key = Some(crate::HpkeKeyPair::gen_keypair().1);

        let test = SessionHistoryTest {
            events: vec![
                SessionEvent::Created(session_context.clone()),
                SessionEvent::RetrievedOriginalPayload {
                    original: original.clone(),
                    reply_key: reply_key.clone(),
                },
            ],
            expected_session_history: SessionHistoryExpectedOutcome {
                fallback_tx: None,
                expected_status: SessionStatus::Active,
            },
            expected_receiver_state: ReceiveSession::UncheckedOriginalPayload(Receiver {
                state: UncheckedOriginalPayload { original },
                session_context: SessionContext { reply_key, ..session_context },
            }),
        };
        run_session_history_test(&test);
        run_session_history_test_async(&test).await;
    }

    #[tokio::test]
    async fn getting_fallback_tx() {
        let persister = InMemoryPersister::<SessionEvent>::default();
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
        events.push(SessionEvent::RetrievedOriginalPayload {
            original: original.clone(),
            reply_key: reply_key.clone(),
        });
        events.push(SessionEvent::CheckedBroadcastSuitability());

        let test = SessionHistoryTest {
            events,
            expected_session_history: SessionHistoryExpectedOutcome {
                fallback_tx: Some(expected_fallback),
                expected_status: SessionStatus::Active,
            },
            expected_receiver_state: ReceiveSession::MaybeInputsOwned(Receiver {
                state: MaybeInputsOwned { original },
                session_context: SessionContext { reply_key, ..session_context },
            }),
        };
        run_session_history_test(&test);
        run_session_history_test_async(&test).await;
    }

    #[tokio::test]
    async fn replaying_cancelled_session_enters_pending_fallback() {
        let session_context = SHARED_CONTEXT.clone();
        let original = original_from_test_vector();
        let reply_key = Some(crate::HpkeKeyPair::gen_keypair().1);
        let expected_fallback = original.psbt.clone().extract_tx_unchecked_fee_rate();

        let test = SessionHistoryTest {
            events: vec![
                SessionEvent::Created(session_context.clone()),
                SessionEvent::RetrievedOriginalPayload {
                    original: original.clone(),
                    reply_key: reply_key.clone(),
                },
                SessionEvent::CheckedBroadcastSuitability(),
                SessionEvent::Cancelled,
            ],
            expected_session_history: SessionHistoryExpectedOutcome {
                fallback_tx: Some(expected_fallback.clone()),
                expected_status: SessionStatus::PendingFallback,
            },
            expected_receiver_state: ReceiveSession::PendingFallback(Receiver {
                state: PendingFallback { fallback_tx: expected_fallback },
                session_context: SessionContext { reply_key, ..session_context },
            }),
        };
        run_session_history_test(&test);
        run_session_history_test_async(&test).await;
    }

    #[tokio::test]
    async fn replaying_protocol_failed_session_enters_pending_fallback() {
        let session_context = SHARED_CONTEXT.clone();
        let original = original_from_test_vector();
        let reply_key = Some(crate::HpkeKeyPair::gen_keypair().1);
        let expected_fallback = original.psbt.clone().extract_tx_unchecked_fee_rate();

        let test = SessionHistoryTest {
            events: vec![
                SessionEvent::Created(session_context.clone()),
                SessionEvent::RetrievedOriginalPayload {
                    original: original.clone(),
                    reply_key: reply_key.clone(),
                },
                SessionEvent::CheckedBroadcastSuitability(),
                SessionEvent::ProtocolFailed,
            ],
            expected_session_history: SessionHistoryExpectedOutcome {
                fallback_tx: Some(expected_fallback.clone()),
                expected_status: SessionStatus::PendingFallback,
            },
            expected_receiver_state: ReceiveSession::PendingFallback(Receiver {
                state: PendingFallback { fallback_tx: expected_fallback },
                session_context: SessionContext { reply_key, ..session_context },
            }),
        };
        run_session_history_test(&test);
        run_session_history_test_async(&test).await;
    }

    #[test]
    fn event_log_distinguishes_abort_outcome() {
        let session_context = SHARED_CONTEXT.clone();
        let original = original_from_test_vector();

        // Cancel scenario: log contains Cancelled event
        let cancel_events = vec![
            SessionEvent::Created(session_context.clone()),
            SessionEvent::RetrievedOriginalPayload { original: original.clone(), reply_key: None },
            SessionEvent::CheckedBroadcastSuitability(),
            SessionEvent::Cancelled,
            SessionEvent::Closed(SessionOutcome::Aborted),
        ];
        let cancel_history = SessionHistory { events: cancel_events };
        let cancel_is_cancel =
            cancel_history.events.iter().any(|e| matches!(e, SessionEvent::Cancelled));
        let cancel_is_failure =
            cancel_history.events.iter().any(|e| matches!(e, SessionEvent::ProtocolFailed));
        assert!(cancel_is_cancel);
        assert!(!cancel_is_failure);

        // Failure scenario: log contains ProtocolFailed event
        let fail_events = vec![
            SessionEvent::Created(session_context.clone()),
            SessionEvent::RetrievedOriginalPayload { original: original.clone(), reply_key: None },
            SessionEvent::CheckedBroadcastSuitability(),
            SessionEvent::ProtocolFailed,
            SessionEvent::Closed(SessionOutcome::Aborted),
        ];
        let fail_history = SessionHistory { events: fail_events };
        let fail_is_cancel =
            fail_history.events.iter().any(|e| matches!(e, SessionEvent::Cancelled));
        let fail_is_failure =
            fail_history.events.iter().any(|e| matches!(e, SessionEvent::ProtocolFailed));
        assert!(!fail_is_cancel);
        assert!(fail_is_failure);
    }

    #[tokio::test]
    async fn test_contributed_inputs() {
        let persister = InMemoryPersister::<SessionEvent>::default();
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
        events.push(SessionEvent::RetrievedOriginalPayload {
            original: original.clone(),
            reply_key: reply_key.clone(),
        });
        events.push(SessionEvent::CheckedBroadcastSuitability());
        events.push(SessionEvent::CheckedInputsNotOwned());
        events.push(SessionEvent::CheckedNoInputsSeenBefore());
        events.push(SessionEvent::IdentifiedReceiverOutputs(
            wants_outputs.state.inner.owned_vouts.clone(),
        ));
        events.push(SessionEvent::CommittedOutputs(
            wants_outputs.state.inner.payjoin_psbt.unsigned_tx.output,
        ));
        events.push(SessionEvent::CommittedInputs(
            wants_fee_range.state.inner.receiver_inputs.clone(),
        ));
        events.push(SessionEvent::AppliedFeeRange(provisional_proposal.state.psbt_context.clone()));

        let test = SessionHistoryTest {
            events,
            expected_session_history: SessionHistoryExpectedOutcome {
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
        run_session_history_test(&test);
        run_session_history_test_async(&test).await;
    }

    #[tokio::test]
    async fn test_payjoin_proposal() {
        let persister = InMemoryPersister::<SessionEvent>::default();
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
        events.push(SessionEvent::RetrievedOriginalPayload {
            original: original.clone(),
            reply_key: reply_key.clone(),
        });
        events.push(SessionEvent::CheckedBroadcastSuitability());
        events.push(SessionEvent::CheckedInputsNotOwned());
        events.push(SessionEvent::CheckedNoInputsSeenBefore());
        events.push(SessionEvent::IdentifiedReceiverOutputs(
            wants_outputs.state.inner.owned_vouts.clone(),
        ));
        events.push(SessionEvent::CommittedOutputs(
            wants_outputs.state.inner.payjoin_psbt.unsigned_tx.output,
        ));
        events.push(SessionEvent::CommittedInputs(
            wants_fee_range.state.inner.receiver_inputs.clone(),
        ));
        events.push(SessionEvent::AppliedFeeRange(provisional_proposal.state.psbt_context.clone()));
        events.push(SessionEvent::FinalizedProposal(payjoin_proposal.psbt().clone()));
        events.push(SessionEvent::Closed(SessionOutcome::Success(vec![])));

        let test = SessionHistoryTest {
            events,
            expected_session_history: SessionHistoryExpectedOutcome {
                fallback_tx: Some(expected_fallback),
                expected_status: SessionStatus::Completed,
            },
            expected_receiver_state: ReceiveSession::Closed(SessionOutcome::Success(vec![])),
        };
        run_session_history_test(&test);
        run_session_history_test_async(&test).await;
    }

    #[tokio::test]
    async fn test_session_fatal_error() {
        let persister = InMemoryPersister::<SessionEvent>::default();
        let session_context = SHARED_CONTEXT.clone();
        let mut events = vec![];

        let original = original_from_test_vector();
        // Original PSBT is not broadcastable
        let _unbroadcastable = unchecked_receiver_from_test_vector()
            .check_broadcast_suitability(None, |_| Ok(false))
            .save(&persister)
            .expect_err("Unbroadcastable should error");
        // NOTE: it would be good to assert against the internal error type but InternalPersistedError is private
        let expected_error = PayloadError(InternalPayloadError::OriginalPsbtNotBroadcastable);
        let reply_key = Some(crate::HpkeKeyPair::gen_keypair().1);

        events.push(SessionEvent::Created(session_context.clone()));
        events.push(SessionEvent::RetrievedOriginalPayload {
            original: original.clone(),
            reply_key: reply_key.clone(),
        });
        events.push(SessionEvent::GotReplyableError((&expected_error).into()));
        events.push(SessionEvent::Closed(SessionOutcome::Aborted));

        let test = SessionHistoryTest {
            events,
            expected_session_history: SessionHistoryExpectedOutcome {
                fallback_tx: None,
                expected_status: SessionStatus::Failed,
            },
            expected_receiver_state: ReceiveSession::Closed(SessionOutcome::Aborted),
        };
        run_session_history_test(&test);
        run_session_history_test_async(&test).await;
    }

    #[tokio::test]
    async fn test_session_transient_error() {
        let persister = InMemoryPersister::<SessionEvent>::default();
        let session_context = SHARED_CONTEXT.clone();
        let mut events = vec![];

        let original = original_from_test_vector();
        // Mock some implementation error
        let _maybe_broadcastable = unchecked_receiver_from_test_vector()
            .check_broadcast_suitability(None, |_| Err("mock error".into()))
            .save(&persister)
            .expect_err("Mock error should error");
        // NOTE: it would be good to assert against the internal error type but InternalPersistedError is private

        let reply_key = Some(crate::HpkeKeyPair::gen_keypair().1);

        events.push(SessionEvent::Created(session_context.clone()));
        events.push(SessionEvent::RetrievedOriginalPayload {
            original: original.clone(),
            reply_key: reply_key.clone(),
        });

        let test = SessionHistoryTest {
            events,
            expected_session_history: SessionHistoryExpectedOutcome {
                fallback_tx: None,
                expected_status: SessionStatus::Active,
            },
            expected_receiver_state: ReceiveSession::UncheckedOriginalPayload(Receiver {
                state: UncheckedOriginalPayload { original },
                session_context: SessionContext { reply_key, ..session_context },
            }),
        };
        run_session_history_test(&test);
        run_session_history_test_async(&test).await;
    }

    #[test]
    fn test_session_history_uri() -> Result<(), BoxError> {
        let session_context = SHARED_CONTEXT.clone();
        let events = vec![SessionEvent::Created(session_context.clone())];

        let uri = SessionHistory { events }.pj_uri();

        assert_ne!(uri.extras.pj_param.endpoint().as_str(), EXAMPLE_URL);
        assert_eq!(uri.extras.output_substitution, OutputSubstitution::Disabled);

        Ok(())
    }

    #[test]
    fn test_session_history_fallback_broadcasted() -> Result<(), BoxError> {
        let session_context = SHARED_CONTEXT.clone();
        let events = vec![
            SessionEvent::Created(session_context.clone()),
            SessionEvent::Closed(SessionOutcome::FallbackBroadcasted),
        ];
        let status = SessionHistory { events }.status();

        assert_eq!(status, SessionStatus::FallbackBroadcasted);

        Ok(())
    }
}

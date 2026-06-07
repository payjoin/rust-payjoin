use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::{ReceiveSession, SessionContext};
use crate::error::{InternalReplayError, ReplayError};
use crate::output_substitution::OutputSubstitution;
#[cfg(feature = "std")]
use crate::persist::AsyncSessionPersister;
use crate::persist::SessionPersister;
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
            return Err(InternalReplayError::Expired(ctx.expiration, history.fallback_tx()).into());
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
#[cfg(feature = "std")]
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
#[non_exhaustive]
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
#[allow(clippy::large_enum_variant)]
pub enum SessionEvent {
    Created(SessionContext),
    RetrievedOriginalPayload { original: OriginalPayload, reply_key: Option<crate::HpkePublicKey> },
    CheckedBroadcastSuitability(),
    CheckedInputsNotOwned(),
    CheckedNoInputsSeenBefore(),
    IdentifiedReceiverOutputs(Vec<usize>),
    CommittedOutputs { outputs: Vec<bitcoin::TxOut>, change_vout: usize },
    CommittedInputs { receiver_inputs: Vec<InputPair>, payjoin_psbt: bitcoin::Psbt },
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
    use std::str::FromStr;
    use std::time::{Duration, SystemTime};

    use bitcoin::hashes::Hash;
    use bitcoin::key::rand::rngs::StdRng;
    use bitcoin::key::rand::SeedableRng;
    use payjoin_test_utils::{BoxError, EXAMPLE_URL};

    use super::*;
    use crate::persist::{InMemoryAsyncPersister, InMemoryPersister};
    use crate::receive::tests::original_from_test_vector;
    use crate::receive::v2::test::{mock_err, SHARED_CONTEXT};
    use crate::receive::v2::{
        Initialized, MaybeInputsOwned, PendingFallback, ProvisionalProposal, Receiver,
        UncheckedOriginalPayload, WantsOutputs,
    };
    use crate::receive::{InternalPayloadError, PayloadError};

    fn unchecked_receiver_from_test_vector() -> Receiver<UncheckedOriginalPayload> {
        Receiver {
            state: UncheckedOriginalPayload { original: original_from_test_vector() },
            session_context: SHARED_CONTEXT.clone(),
        }
    }
    #[cfg(feature = "v1")]
    use crate::core::OutputSubstitution;

    // Drives a fresh v2 receiver to `WantsOutputs`, persisting each step. Vout 1 is
    // owned, so a single-script substitution succeeds.
    fn wants_outputs_with_persister(
        persister: &InMemoryPersister<SessionEvent>,
        original: OriginalPayload,
    ) -> Receiver<WantsOutputs> {
        let receiver_script = original.psbt.unsigned_tx.output[1].script_pubkey.clone();
        // Seed the events preceding the directly-constructed receiver so replay can reach it.
        persister
            .save_event(SessionEvent::Created(SHARED_CONTEXT.clone()))
            .expect("In memory persister shouldn't fail");
        persister
            .save_event(SessionEvent::RetrievedOriginalPayload {
                original: original.clone(),
                reply_key: None,
            })
            .expect("In memory persister shouldn't fail");
        let receiver = Receiver {
            state: UncheckedOriginalPayload { original },
            session_context: SHARED_CONTEXT.clone(),
        };
        let maybe_inputs_owned =
            receiver.assume_interactive_receiver().save(persister).expect("Save should not fail");
        let maybe_inputs_seen = maybe_inputs_owned
            .check_inputs_not_owned(&mut |_| Ok(false))
            .save(persister)
            .expect("No inputs should be owned");
        let outputs_unknown = maybe_inputs_seen
            .check_no_inputs_seen_before(&mut |_| Ok(false))
            .save(persister)
            .expect("No inputs should be seen before");
        outputs_unknown
            .identify_receiver_outputs(&mut |script| Ok(script == receiver_script.as_script()))
            .save(persister)
            .expect("Outputs should be identified")
    }

    // A non-degenerate substitution: the interleave shuffle can move the drain (and thus
    // `change_vout`) off its original index.
    fn replacement_outputs() -> (Vec<bitcoin::TxOut>, bitcoin::ScriptBuf) {
        let drain_script =
            bitcoin::ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array([0x11; 32]));
        let outputs = vec![
            bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50_000),
                script_pubkey: drain_script.clone(),
            },
            bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(10_000),
                script_pubkey: bitcoin::ScriptBuf::new_p2wsh(
                    &bitcoin::WScriptHash::from_byte_array([0x22; 32]),
                ),
            },
            bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(10_000),
                script_pubkey: bitcoin::ScriptBuf::new_p2wsh(
                    &bitcoin::WScriptHash::from_byte_array([0x33; 32]),
                ),
            },
        ];
        (outputs, drain_script)
    }

    // Replay must reproduce the post-substitution `change_vout`. It rebuilds from the
    // persisted delta, so a lossy reconstruction would diverge from the live control.
    #[test]
    fn test_replay_to_wants_inputs_matches_live() {
        // thread_rng only moves the drain off owned_vouts[0] on some draws, so seed the
        // shuffle to fix the asserted state and guarantee the drain (and change_vout) moves.
        const SEED: u64 = 0;

        let persister = InMemoryPersister::<SessionEvent>::default();
        let wants_outputs = wants_outputs_with_persister(&persister, original_from_test_vector());
        let owned_vout = wants_outputs.state.inner.owned_vouts[0];

        let (outputs, drain_script) = replacement_outputs();
        let mut rng = StdRng::seed_from_u64(SEED);
        let inner = wants_outputs
            .state
            .inner
            .replace_receiver_outputs_with_rng(outputs, drain_script.as_script(), &mut rng)
            .expect("Substitution should succeed");
        let live_wants_inputs = Receiver {
            state: WantsOutputs { inner },
            session_context: wants_outputs.session_context,
        }
        .commit_outputs()
        .save(&persister)
        .expect("Save should not fail");

        assert_ne!(
            live_wants_inputs.state.inner.proposal.change_vout, owned_vout,
            "seed must move the drain off owned_vouts[0]"
        );

        let (replayed, _) = replay_event_log(&persister).expect("replay should succeed");
        let replayed = match replayed {
            ReceiveSession::WantsInputs(r) => r,
            other => panic!("Expected WantsInputs, got {other:?}"),
        };
        assert_eq!(replayed, live_wants_inputs, "replayed WantsInputs must equal the live state");
    }

    // Replay at `WantsFeeRange` must reproduce the contributed inputs and the
    // RNG-driven change increment.
    #[test]
    fn test_replay_to_wants_fee_range_matches_live() {
        let persister = InMemoryPersister::<SessionEvent>::default();
        let wants_outputs = wants_outputs_with_persister(&persister, original_from_test_vector());

        let (outputs, drain_script) = replacement_outputs();
        let wants_inputs = wants_outputs
            .replace_receiver_outputs(outputs, drain_script.as_script())
            .expect("Substitution should succeed")
            .commit_outputs()
            .save(&persister)
            .expect("Save should not fail");

        let proposal_psbt =
            bitcoin::Psbt::from_str(payjoin_test_utils::RECEIVER_INPUT_CONTRIBUTION)
                .expect("valid proposal psbt");
        let input = InputPair::new(
            proposal_psbt.unsigned_tx.input[1].clone(),
            proposal_psbt.inputs[1].clone(),
            None,
        )
        .expect("valid input pair");
        let live_wants_fee_range = wants_inputs
            .contribute_inputs([input])
            .expect("Contribution should succeed")
            .commit_inputs()
            .save(&persister)
            .expect("Save should not fail");

        let (replayed, _) = replay_event_log(&persister).expect("replay should succeed");
        let replayed = match replayed {
            ReceiveSession::WantsFeeRange(r) => r,
            other => panic!("Expected WantsFeeRange, got {other:?}"),
        };
        assert_eq!(
            replayed, live_wants_fee_range,
            "replayed WantsFeeRange must equal the live state"
        );
    }

    // The sender aims `additional_fee_contribution` at owned vout 1; BIP78 says ignore
    // it. The nulling lives in `OriginalContext::new`, which both live and replay route
    // through, so resuming at `WantsOutputs` proves replay sanitizes like live.
    #[test]
    fn test_replay_to_wants_outputs_nulls_owned_fee_contribution() {
        let persister = InMemoryPersister::<SessionEvent>::default();
        let mut original = original_from_test_vector();
        original.params.additional_fee_contribution = Some((bitcoin::Amount::from_sat(182), 1));

        let live_wants_outputs = wants_outputs_with_persister(&persister, original);
        assert_eq!(
            live_wants_outputs.state.inner.original.params.additional_fee_contribution, None,
            "live identify must drop a fee contribution pointed at an owned output"
        );

        let (replayed, _) = replay_event_log(&persister).expect("replay should succeed");
        let replayed = match replayed {
            ReceiveSession::WantsOutputs(r) => r,
            other => panic!("Expected WantsOutputs, got {other:?}"),
        };
        assert_eq!(
            replayed.state.inner.original.params.additional_fee_contribution, None,
            "replay must apply the same owned-vout nulling as live"
        );
        assert_eq!(replayed, live_wants_outputs, "replayed WantsOutputs must equal the live state");
    }

    // Events up to (excluding) `IdentifiedReceiverOutputs`, from which the malformed
    // payload tests below diverge.
    fn events_to_outputs_unknown() -> Vec<SessionEvent> {
        vec![
            SessionEvent::Created(SHARED_CONTEXT.clone()),
            SessionEvent::RetrievedOriginalPayload {
                original: original_from_test_vector(),
                reply_key: None,
            },
            SessionEvent::CheckedBroadcastSuitability(),
            SessionEvent::CheckedInputsNotOwned(),
            SessionEvent::CheckedNoInputsSeenBefore(),
        ]
    }

    fn expect_invalid_payload_on_replay(events: Vec<SessionEvent>) {
        let persister = InMemoryPersister::<SessionEvent>::default();
        for event in events {
            persister.save_event(event).expect("In memory persister shouldn't fail");
        }
        let err = replay_event_log(&persister).expect_err("replay should reject the payload");
        assert!(
            err.to_string().starts_with("Invalid event payload"),
            "expected an invalid-payload error, got: {err}"
        );
    }

    // Regression tests: an event log is only as trustworthy as its storage, so replaying
    // a malformed payload must produce a ReplayError instead of panicking in a later
    // typestate (`owned_vouts[0]` or an out-of-bounds `output[change_vout]`).
    #[test]
    fn replay_rejects_empty_owned_vouts() {
        let mut events = events_to_outputs_unknown();
        events.push(SessionEvent::IdentifiedReceiverOutputs(vec![]));
        expect_invalid_payload_on_replay(events);
    }

    #[test]
    fn replay_rejects_out_of_bounds_owned_vout() {
        let mut events = events_to_outputs_unknown();
        let output_count = original_from_test_vector().psbt.unsigned_tx.output.len();
        events.push(SessionEvent::IdentifiedReceiverOutputs(vec![output_count]));
        expect_invalid_payload_on_replay(events);
    }

    #[test]
    fn replay_rejects_out_of_bounds_change_vout() {
        let mut events = events_to_outputs_unknown();
        let outputs = original_from_test_vector().psbt.unsigned_tx.output.clone();
        let change_vout = outputs.len();
        events.push(SessionEvent::IdentifiedReceiverOutputs(vec![1]));
        events.push(SessionEvent::CommittedOutputs { outputs, change_vout });
        expect_invalid_payload_on_replay(events);
    }

    #[test]
    fn replay_rejects_committed_psbt_missing_change_vout() {
        let mut events = events_to_outputs_unknown();
        let original = original_from_test_vector();
        let outputs = original.psbt.unsigned_tx.output.clone();
        events.push(SessionEvent::IdentifiedReceiverOutputs(vec![1]));
        events.push(SessionEvent::CommittedOutputs { outputs, change_vout: 1 });
        // A committed PSBT with too few outputs no longer contains the predecessor's
        // change vout.
        let mut truncated = original.psbt.clone();
        truncated.unsigned_tx.output.truncate(1);
        truncated.outputs.truncate(1);
        events.push(SessionEvent::CommittedInputs {
            receiver_inputs: vec![],
            payjoin_psbt: truncated,
        });
        expect_invalid_payload_on_replay(events);
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
            SessionEvent::CommittedOutputs {
                outputs: wants_inputs.state.inner.proposal.payjoin_psbt.unsigned_tx.output.clone(),
                change_vout: wants_inputs.state.inner.proposal.change_vout,
            },
            SessionEvent::CommittedInputs {
                receiver_inputs: wants_fee_range.state.inner.proposal.receiver_inputs.clone(),
                payjoin_psbt: wants_fee_range.state.inner.proposal.payjoin_psbt.clone(),
            },
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
            InternalReplayError::Expired(expiration, None).into();
        assert_eq!(err.to_string(), expected_err.to_string());

        let persister = InMemoryAsyncPersister::<SessionEvent>::default();
        persister
            .save_event(SessionEvent::Created(session_context))
            .await
            .expect("in memory async persister save should not fail");
        let err = replay_event_log_async(&persister).await.expect_err("session should be expired");
        let expected_err: ReplayError<ReceiveSession, SessionEvent> =
            InternalReplayError::Expired(expiration, None).into();
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
        events.push(SessionEvent::CommittedOutputs {
            outputs: wants_inputs.state.inner.proposal.payjoin_psbt.unsigned_tx.output.clone(),
            change_vout: wants_inputs.state.inner.proposal.change_vout,
        });
        events.push(SessionEvent::CommittedInputs {
            receiver_inputs: wants_fee_range.state.inner.proposal.receiver_inputs.clone(),
            payjoin_psbt: wants_fee_range.state.inner.proposal.payjoin_psbt.clone(),
        });
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
        events.push(SessionEvent::CommittedOutputs {
            outputs: wants_inputs.state.inner.proposal.payjoin_psbt.unsigned_tx.output.clone(),
            change_vout: wants_inputs.state.inner.proposal.change_vout,
        });
        events.push(SessionEvent::CommittedInputs {
            receiver_inputs: wants_fee_range.state.inner.proposal.receiver_inputs.clone(),
            payjoin_psbt: wants_fee_range.state.inner.proposal.payjoin_psbt.clone(),
        });
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
    #[cfg(feature = "v1")]
    fn test_session_history_uri() -> Result<(), BoxError> {
        let session_context = SHARED_CONTEXT.clone();
        let events = vec![SessionEvent::Created(session_context.clone())];

        let binding = SessionHistory { events };
        let uri = binding.pj_uri();

        assert_ne!(uri.extras.pj_param.endpoint().as_str(), EXAMPLE_URL);
        #[cfg(feature = "v1")]
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

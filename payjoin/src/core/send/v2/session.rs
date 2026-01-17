use crate::error::{InternalReplayError, ReplayError};
use crate::persist::{AsyncSessionPersister, SessionPersister};
use crate::send::v2::{SendSession, SessionContext};
use crate::uri::v2::PjParam;
use crate::ImplementationError;

fn replay_events(
    mut logs: impl Iterator<Item = SessionEvent>,
) -> Result<(SendSession, Vec<SessionEvent>), ReplayError<SendSession, SessionEvent>> {
    let first_event = logs.next().ok_or(InternalReplayError::NoEvents)?;
    let mut session_events = vec![first_event.clone()];
    let mut sender = match first_event {
        SessionEvent::Created(session_context) => SendSession::new(*session_context),
        _ => return Err(InternalReplayError::InvalidEvent(Box::new(first_event), None).into()),
    };

    for session_event in logs {
        session_events.push(session_event.clone());
        sender = sender.clone().process_event(session_event)?;
    }
    Ok((sender, session_events))
}

fn construct_history(
    session_events: Vec<SessionEvent>,
) -> Result<SessionHistory, ReplayError<SendSession, SessionEvent>> {
    let history = SessionHistory::new(session_events);
    let pj_param = history.pj_param();
    if pj_param.expiration().elapsed() {
        return Err(InternalReplayError::Expired(pj_param.expiration()).into());
    }
    Ok(history)
}

/// Replay a sender event log to get the sender in its current state [SendSession]
/// and a session history [SessionHistory]
pub fn replay_event_log<P>(
    persister: &P,
) -> Result<(SendSession, SessionHistory), ReplayError<SendSession, SessionEvent>>
where
    P: SessionPersister,
    P::SessionEvent: Into<SessionEvent> + Clone,
    P::SessionEvent: From<SessionEvent>,
{
    let logs = persister
        .load()
        .map_err(|e| InternalReplayError::PersistenceFailure(ImplementationError::new(e)))?;

    let (sender, session_events) = match replay_events(logs.map(|e| e.into())) {
        Ok(r) => r,
        Err(e) => {
            persister.close().map_err(|ce| {
                InternalReplayError::PersistenceFailure(ImplementationError::new(ce))
            })?;
            return Err(e);
        }
    };

    let history = construct_history(session_events)?;
    Ok((sender, history))
}

/// Async version of [replay_event_log]
pub async fn replay_event_log_async<P>(
    persister: &P,
) -> Result<(SendSession, SessionHistory), ReplayError<SendSession, SessionEvent>>
where
    P: AsyncSessionPersister,
    P::SessionEvent: Into<SessionEvent> + Clone,
    P::SessionEvent: From<SessionEvent>,
{
    let logs = persister
        .load()
        .await
        .map_err(|e| InternalReplayError::PersistenceFailure(ImplementationError::new(e)))?;

    let (sender, session_events) = match replay_events(logs.map(|e| e.into())) {
        Ok(r) => r,
        Err(e) => {
            persister.close().await.map_err(|ce| {
                InternalReplayError::PersistenceFailure(ImplementationError::new(ce))
            })?;
            return Err(e);
        }
    };

    let history = construct_history(session_events)?;
    Ok((sender, history))
}

#[derive(Debug, Clone)]
pub struct SessionHistory {
    events: Vec<SessionEvent>,
}

impl SessionHistory {
    pub(crate) fn new(events: Vec<SessionEvent>) -> Self {
        debug_assert!(!events.is_empty(), "Session event log must contain at least one event");
        Self { events }
    }

    /// Fallback transaction from the session
    pub fn fallback_tx(&self) -> bitcoin::Transaction {
        self.events
            .iter()
            .find_map(|event| match event {
                SessionEvent::Created(session_context) => Some(
                    session_context.psbt_ctx.original_psbt.clone().extract_tx_unchecked_fee_rate(),
                ),
                _ => None,
            })
            .expect("Session event log must contain at least one event with fallback_tx")
    }

    pub fn pj_param(&self) -> &PjParam {
        self.events
            .iter()
            .find_map(|event| match event {
                SessionEvent::Created(session_context) => Some(&session_context.pj_param),
                _ => None,
            })
            .expect("Session event log must contain at least one event with pj_param")
    }

    pub fn status(&self) -> SessionStatus {
        if self.pj_param().expiration().elapsed() {
            return SessionStatus::Expired;
        }

        match self.events.last() {
            Some(SessionEvent::Closed(outcome)) => match outcome {
                SessionOutcome::Success(_) => SessionStatus::Completed,
                SessionOutcome::Failure | SessionOutcome::Cancel => SessionStatus::Failed,
            },
            _ => SessionStatus::Active,
        }
    }
}

/// Represents the status of a session that can be inferred from the information in the session
/// event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    Expired,
    Active,
    Failed,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SessionEvent {
    /// Sender was created with session data
    Created(Box<SessionContext>),
    /// Sender POSTed the Original PSBT and is waiting to receive a Proposal PSBT
    PostedOriginalPsbt(),
    /// Closed successful or failed session
    Closed(SessionOutcome),
}

/// Represents all possible outcomes for a closed Payjoin session
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum SessionOutcome {
    /// Successful payjoin
    Success(bitcoin::Psbt),
    /// Payjoin failed to complete due to a counterparty deviation from the protocol
    Failure,
    /// Payjoin was cancelled by the user
    Cancel,
}

#[cfg(test)]
mod tests {
    use bitcoin::{FeeRate, ScriptBuf};
    use payjoin_test_utils::{KEM, KEY_ID, PARSED_ORIGINAL_PSBT, SYMMETRIC};
    use url::Url;

    use super::*;
    use crate::output_substitution::OutputSubstitution;
    use crate::persist::test_utils::{InMemoryAsyncTestPersister, InMemoryTestPersister};
    use crate::persist::NoopSessionPersister;
    use crate::send::v2::{Sender, SenderBuilder, SessionContext, WithReplyKey};
    use crate::send::PsbtContext;
    use crate::time::Time;
    use crate::{HpkeKeyPair, Uri, UriExt};

    /// Expired V2 Payjoin URI without Amount inspired by BIP 77 test vector
    const PJ_URI: &str = "bitcoin:2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7?pjos=0&pj=HTTPS://PAYJO.IN/TXJCGKTKXLUUZ%23EX1WKV8CEC-OH1QYPM59NK2LXXS4890SUAXXYT25Z2VAPHP0X7YEYCJXGWAG6UG9ZU6NQ-RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV";

    #[test]
    fn test_sender_session_event_serialization_roundtrip() {
        let keypair = HpkeKeyPair::gen_keypair();
        let id = crate::uri::ShortId::try_from(&b"12345670"[..]).expect("valid short id");
        let endpoint = url::Url::parse("http://localhost:1234").expect("valid url");
        let expiration =
            Time::from_now(std::time::Duration::from_secs(60)).expect("expiration should be valid");
        let pj_param = crate::uri::v2::PjParam::new(
            endpoint,
            id,
            expiration,
            crate::OhttpKeys(
                ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).expect("valid key config"),
            ),
            HpkeKeyPair::gen_keypair().1,
        );
        let sender_with_reply_key = Sender {
            state: WithReplyKey,
            session_context: SessionContext {
                pj_param: pj_param.clone(),
                psbt_ctx: PsbtContext {
                    original_psbt: PARSED_ORIGINAL_PSBT.clone(),
                    output_substitution: OutputSubstitution::Enabled,
                    fee_contribution: None,
                    min_fee_rate: FeeRate::ZERO,
                    payee: ScriptBuf::from(vec![0x00]),
                },
                reply_key: keypair.0.clone(),
            },
        };

        let test_cases = vec![
            SessionEvent::Created(Box::new(sender_with_reply_key.session_context.clone())),
            SessionEvent::PostedOriginalPsbt(),
            SessionEvent::Closed(SessionOutcome::Success(PARSED_ORIGINAL_PSBT.clone())),
            SessionEvent::Closed(SessionOutcome::Failure),
            SessionEvent::Closed(SessionOutcome::Cancel),
        ];

        for event in test_cases {
            let serialized = serde_json::to_string(&event).expect("Should serialize");
            let deserialized: SessionEvent =
                serde_json::from_str(&serialized).expect("Should deserialize");
            assert_eq!(event, deserialized);
        }
    }

    #[derive(Clone)]
    struct SessionHistoryExpectedOutcome {
        fallback_tx: bitcoin::Transaction,
        pj_param: PjParam,
        expected_status: SessionStatus,
    }

    #[derive(Clone)]
    struct SessionHistoryTest {
        events: Vec<SessionEvent>,
        expected_session_history: SessionHistoryExpectedOutcome,
        expected_sender_state: SendSession,
        expected_error: Option<String>,
    }

    fn verify_session_result(
        session_result: Result<
            (SendSession, SessionHistory),
            crate::error::ReplayError<SendSession, SessionEvent>,
        >,
        test: &SessionHistoryTest,
    ) {
        match session_result {
            Ok((sender_state, session_history)) => {
                assert!(test.expected_error.is_none(), "Expected an error but got Ok");
                assert_eq!(sender_state, test.expected_sender_state);
                assert_eq!(
                    session_history.fallback_tx(),
                    test.expected_session_history.fallback_tx
                );
                assert_eq!(session_history.pj_param(), &test.expected_session_history.pj_param);
                assert_eq!(SessionStatus::Active, test.expected_session_history.expected_status);
            }
            Err(e) => {
                let err_str = e.to_string();
                if let Some(expected) = &test.expected_error {
                    assert!(
                        err_str.contains(expected),
                        "Expected error containing '{expected}', got '{err_str}'"
                    );
                } else {
                    panic!("Unexpected error: {err_str}");
                }
                assert_eq!(
                    SendSession::Closed(SessionOutcome::Failure),
                    test.expected_sender_state
                );
                assert_eq!(test.expected_session_history.expected_status, SessionStatus::Expired);
            }
        }
    }

    fn run_session_history_test(test: &SessionHistoryTest) {
        let persister = InMemoryTestPersister::<SessionEvent>::default();
        for event in test.events.clone() {
            persister.save_event(event).expect("In memory persister shouldn't fail");
        }
        verify_session_result(replay_event_log(&persister), test);
    }

    async fn run_session_history_test_async(test: &SessionHistoryTest) {
        let persister = InMemoryAsyncTestPersister::<SessionEvent>::default();
        for event in test.events.clone() {
            persister.save_event(event).await.expect("In memory persister shouldn't fail");
        }
        verify_session_result(replay_event_log_async(&persister).await, test);
    }

    #[tokio::test]
    async fn test_sender_session_history_with_expired_session() {
        let psbt = PARSED_ORIGINAL_PSBT.clone();
        let sender = SenderBuilder::new(
            psbt.clone(),
            Uri::try_from(PJ_URI)
                .expect("Valid uri")
                .assume_checked()
                .check_pj_supported()
                .expect("Payjoin to be supported"),
        )
        .build_recommended(FeeRate::BROADCAST_MIN)
        .unwrap()
        .save(&NoopSessionPersister::default())
        .unwrap();
        let test = SessionHistoryTest {
            events: vec![SessionEvent::Created(Box::new(sender.session_context.clone()))],
            expected_session_history: SessionHistoryExpectedOutcome {
                fallback_tx: sender
                    .session_context
                    .psbt_ctx
                    .original_psbt
                    .clone()
                    .extract_tx_unchecked_fee_rate(),
                pj_param: sender.session_context.pj_param.clone(),
                expected_status: SessionStatus::Expired,
            },
            expected_sender_state: SendSession::Closed(SessionOutcome::Failure),
            expected_error: Some("Session expired at".to_string()),
        };
        run_session_history_test(&test);
        run_session_history_test_async(&test).await;
    }

    #[tokio::test]
    async fn test_sender_session_history_with_reply_key_event() {
        let psbt = PARSED_ORIGINAL_PSBT.clone();
        let mut sender = SenderBuilder::new(
            psbt.clone(),
            Uri::try_from(PJ_URI)
                .expect("Valid uri")
                .assume_checked()
                .check_pj_supported()
                .expect("Payjoin to be supported"),
        )
        .build_recommended(FeeRate::BROADCAST_MIN)
        .unwrap()
        .save(&NoopSessionPersister::default())
        .unwrap();
        sender.session_context.pj_param.expiration =
            Time::from_now(std::time::Duration::from_secs(60)).unwrap();
        let test = SessionHistoryTest {
            events: vec![SessionEvent::Created(Box::new(sender.session_context.clone()))],
            expected_session_history: SessionHistoryExpectedOutcome {
                fallback_tx: sender
                    .session_context
                    .psbt_ctx
                    .original_psbt
                    .clone()
                    .extract_tx_unchecked_fee_rate(),
                pj_param: sender.session_context.pj_param.clone(),
                expected_status: SessionStatus::Active,
            },
            expected_sender_state: SendSession::WithReplyKey(sender),
            expected_error: None,
        };
        run_session_history_test(&test);
        run_session_history_test_async(&test).await;
    }

    #[test]
    fn status_is_completed_for_closed_success() {
        let psbt = PARSED_ORIGINAL_PSBT.clone();
        let sender = SenderBuilder::new(
            psbt.clone(),
            Uri::try_from(PJ_URI)
                .expect("Valid uri")
                .assume_checked()
                .check_pj_supported()
                .expect("Payjoin to be supported"),
        )
        .build_recommended(FeeRate::BROADCAST_MIN)
        .unwrap()
        .save(&NoopSessionPersister::default())
        .unwrap();

        let reply_key = HpkeKeyPair::gen_keypair();
        let endpoint = Url::parse(&sender.endpoint()).expect("Could not parse url");
        let id = crate::uri::ShortId::try_from(&b"12345670"[..]).expect("valid short id");
        let expiration =
            Time::from_now(std::time::Duration::from_secs(60)).expect("Valid expiration");
        let pj_param = crate::uri::v2::PjParam::new(
            endpoint,
            id,
            expiration,
            crate::OhttpKeys(
                ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).expect("valid key config"),
            ),
            HpkeKeyPair::gen_keypair().1,
        );

        let with_reply_key = Sender {
            state: WithReplyKey,
            session_context: SessionContext {
                pj_param: pj_param.clone(),
                psbt_ctx: sender.session_context.psbt_ctx.clone(),
                reply_key: reply_key.0,
            },
        };

        let events = vec![
            SessionEvent::Created(Box::new(with_reply_key.session_context.clone())),
            SessionEvent::Closed(SessionOutcome::Success(PARSED_ORIGINAL_PSBT.clone())),
        ];

        let session = SessionHistory { events };
        assert_eq!(session.status(), SessionStatus::Completed);
    }

    #[tokio::test]
    async fn test_replaying_session_with_missing_created_event() {
        let persister = InMemoryTestPersister::<SessionEvent>::default();
        persister.save_event(SessionEvent::PostedOriginalPsbt());
        assert!(!persister.inner.read().expect("session read should succeed").is_closed);
        let err = replay_event_log(&persister).expect_err("session replay should be fail");
        let expected_err: ReplayError<SendSession, SessionEvent> =
            InternalReplayError::InvalidEvent(Box::new(SessionEvent::PostedOriginalPsbt()), None)
                .into();
        assert_eq!(err.to_string(), expected_err.to_string());
        assert!(persister.inner.read().expect("lock should not be poisoned").is_closed);

        let persister = InMemoryAsyncTestPersister::<SessionEvent>::default();
        persister.save_event(SessionEvent::PostedOriginalPsbt()).await;
        assert!(!persister.inner.read().await.is_closed);
        let err =
            replay_event_log_async(&persister).await.expect_err("session replay should be fail");
        let expected_err: ReplayError<SendSession, SessionEvent> =
            InternalReplayError::InvalidEvent(Box::new(SessionEvent::PostedOriginalPsbt()), None)
                .into();
        assert_eq!(err.to_string(), expected_err.to_string());
        assert!(persister.inner.read().await.is_closed);
    }
}

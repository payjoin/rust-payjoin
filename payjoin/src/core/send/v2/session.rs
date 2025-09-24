use super::WithReplyKey;
use crate::error::{InternalReplayError, ReplayError};
use crate::persist::SessionPersister;
use crate::send::v2::{PollingForProposal, SendSession};
use crate::uri::v2::PjParam;
use crate::ImplementationError;

pub fn replay_event_log<P>(
    persister: &P,
) -> Result<(SendSession, SessionHistory), ReplayError<SendSession, SessionEvent>>
where
    P: SessionPersister + Clone,
    P::SessionEvent: Into<SessionEvent> + Clone,
    P::SessionEvent: From<SessionEvent>,
{
    let mut logs = persister
        .load()
        .map_err(|e| InternalReplayError::PersistenceFailure(ImplementationError::new(e)))?;
    let first_event = logs.next().ok_or(InternalReplayError::NoEvents)?.into();
    let mut session_events = vec![first_event.clone()];
    let mut sender = match first_event {
        SessionEvent::CreatedReplyKey(reply_key) => SendSession::new(reply_key),
        _ => return Err(InternalReplayError::InvalidEvent(Box::new(first_event), None).into()),
    };

    for log in logs {
        let session_event = log.into();
        session_events.push(session_event.clone());
        match sender.clone().process_event(session_event) {
            Ok(next_sender) => sender = next_sender,
            Err(_e) => {
                persister.close().map_err(|e| {
                    InternalReplayError::PersistenceFailure(ImplementationError::new(e))
                })?;
                break;
            }
        }
    }

    let history = SessionHistory::new(session_events.clone());
    let pj_param = history.pj_param();
    if pj_param.expiration().elapsed() {
        return Err(InternalReplayError::Expired(pj_param.expiration()).into());
    }
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
                SessionEvent::CreatedReplyKey(proposal) =>
                    Some(proposal.psbt_ctx.original_psbt.clone().extract_tx_unchecked_fee_rate()),
                _ => None,
            })
            .expect("Session event log must contain at least one event with fallback_tx")
    }

    pub fn pj_param(&self) -> &PjParam {
        self.events
            .iter()
            .find_map(|event| match event {
                SessionEvent::CreatedReplyKey(proposal) => Some(&proposal.pj_param),
                _ => None,
            })
            .expect("Session event log must contain at least one event with pj_param")
    }

    pub fn terminal_error(&self) -> Option<String> {
        self.events.iter().find_map(|event| match event {
            SessionEvent::SessionInvalid(error) => Some(error.clone()),
            _ => None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SessionEvent {
    /// Sender was created with a HPKE key pair
    CreatedReplyKey(WithReplyKey),
    /// Sender POST'd the original PSBT, and waiting to receive a Proposal PSBT using GET context
    PollingForProposal(PollingForProposal),
    /// Sender received a Proposal PSBT
    ProposalReceived(bitcoin::Psbt),
    /// Invalid session
    SessionInvalid(String),
}

#[cfg(test)]
mod tests {
    use bitcoin::{FeeRate, ScriptBuf};
    use payjoin_test_utils::{KEM, KEY_ID, PARSED_ORIGINAL_PSBT, SYMMETRIC};

    use super::*;
    use crate::output_substitution::OutputSubstitution;
    use crate::persist::test_utils::InMemoryTestPersister;
    #[cfg(feature = "v1")]
    use crate::send::v1::SenderBuilder;
    use crate::send::v2::Sender;
    use crate::send::PsbtContext;
    use crate::time::Time;
    use crate::{HpkeKeyPair, Uri, UriExt};

    const PJ_URI: &str =
        "bitcoin:2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7?amount=0.02&pjos=0&pj=HTTPS://EXAMPLE.COM/";

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
        let sender_with_reply_key = WithReplyKey {
            pj_param: pj_param.clone(),
            psbt_ctx: PsbtContext {
                original_psbt: PARSED_ORIGINAL_PSBT.clone(),
                output_substitution: OutputSubstitution::Enabled,
                fee_contribution: None,
                min_fee_rate: FeeRate::ZERO,
                payee: ScriptBuf::from(vec![0x00]),
            },
            reply_key: keypair.0.clone(),
        };

        let polling_for_proposal = PollingForProposal {
            pj_param: pj_param.clone(),
            psbt_ctx: PsbtContext {
                original_psbt: PARSED_ORIGINAL_PSBT.clone(),
                output_substitution: OutputSubstitution::Enabled,
                fee_contribution: None,
                min_fee_rate: FeeRate::ZERO,
                payee: ScriptBuf::from(vec![0x00]),
            },
            reply_key: keypair.0.clone(),
        };

        let test_cases = vec![
            SessionEvent::CreatedReplyKey(sender_with_reply_key.clone()),
            SessionEvent::PollingForProposal(polling_for_proposal.clone()),
            SessionEvent::ProposalReceived(PARSED_ORIGINAL_PSBT.clone()),
            SessionEvent::SessionInvalid("error message".to_string()),
        ];

        for event in test_cases {
            let serialized = serde_json::to_string(&event).expect("Should serialize");
            let deserialized: SessionEvent =
                serde_json::from_str(&serialized).expect("Should deserialize");
            assert_eq!(event, deserialized);
        }
    }

    struct SessionHistoryExpectedOutcome {
        fallback_tx: bitcoin::Transaction,
        pj_param: PjParam,
    }

    struct SessionHistoryTest {
        events: Vec<SessionEvent>,
        expected_session_history: SessionHistoryExpectedOutcome,
        expected_sender_state: SendSession,
        expected_error: Option<String>,
    }

    fn run_session_history_test(test: SessionHistoryTest) {
        let persister = InMemoryTestPersister::<SessionEvent>::default();
        for event in test.events {
            persister.save_event(event).expect("In memory persister shouldn't fail");
        }

        let (sender, session_history) =
            replay_event_log(&persister).expect("In memory persister shouldn't fail");
        assert_eq!(sender, test.expected_sender_state);
        assert_eq!(session_history.fallback_tx(), test.expected_session_history.fallback_tx);
        assert_eq!(*session_history.pj_param(), test.expected_session_history.pj_param);
        assert_eq!(session_history.terminal_error(), test.expected_error);
    }

    #[test]
    fn test_sender_session_history_with_expired_session() {
        // TODO(armins): how can we reduce the boilerplate for these tests?
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
        .unwrap();
        let reply_key = HpkeKeyPair::gen_keypair();
        let endpoint = sender.endpoint().0.clone();
        let id = crate::uri::ShortId::try_from(&b"12345670"[..]).expect("valid short id");
        let expiration =
            (std::time::SystemTime::now() - std::time::Duration::from_secs(1)).try_into().unwrap();
        let pj_param = crate::uri::v2::PjParam::new(
            endpoint,
            id,
            expiration,
            crate::OhttpKeys(
                ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).expect("valid key config"),
            ),
            reply_key.1,
        );
        let with_reply_key = WithReplyKey {
            pj_param: pj_param.clone(),
            psbt_ctx: sender.psbt_ctx.clone(),
            reply_key: reply_key.0,
        };
        let persister = InMemoryTestPersister::<SessionEvent>::default();
        persister
            .save_event(SessionEvent::CreatedReplyKey(with_reply_key))
            .expect("save_event should succeed");

        let err = replay_event_log(&persister).expect_err("session should be expired");
        let expected_err: ReplayError<SendSession, SessionEvent> =
            InternalReplayError::Expired(expiration).into();
        assert_eq!(err.to_string(), expected_err.to_string());
    }

    #[test]
    #[cfg(feature = "v1")]
    fn test_sender_session_history_with_reply_key_event() {
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
        .unwrap();
        let reply_key = HpkeKeyPair::gen_keypair();
        let endpoint = sender.endpoint().0.clone();
        let fallback_tx = sender.psbt_ctx.original_psbt.clone().extract_tx_unchecked_fee_rate();
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
        let with_reply_key = WithReplyKey {
            pj_param: pj_param.clone(),
            psbt_ctx: sender.psbt_ctx.clone(),
            reply_key: reply_key.0,
        };
        let sender = Sender { state: with_reply_key.clone() };
        let test = SessionHistoryTest {
            events: vec![SessionEvent::CreatedReplyKey(with_reply_key)],
            expected_session_history: SessionHistoryExpectedOutcome { fallback_tx, pj_param },
            expected_sender_state: SendSession::WithReplyKey(sender),
            expected_error: None,
        };
        run_session_history_test(test);
    }
}

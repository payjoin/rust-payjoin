use super::WithReplyKey;
use crate::persist::SessionPersister;
use crate::send::v2::{SendSession, V2GetContext};
use crate::uri::v2::PjParam;
use crate::ImplementationError;
/// Errors that can occur when replaying a sender event log
#[derive(Debug)]
pub struct ReplayError(InternalReplayError);

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use InternalReplayError::*;
        match &self.0 {
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
    /// Invalid combination of state and event
    InvalidStateAndEvent(Box<SendSession>, Box<SessionEvent>),
    /// Application storage error
    PersistenceFailure(ImplementationError),
}

pub fn replay_event_log<P>(persister: &P) -> Result<(SendSession, SessionHistory), ReplayError>
where
    P: SessionPersister + Clone,
    P::SessionEvent: Into<SessionEvent> + Clone,
    P::SessionEvent: From<SessionEvent>,
{
    let logs = persister
        .load()
        .map_err(|e| InternalReplayError::PersistenceFailure(ImplementationError::new(e)))?;

    let mut sender = SendSession::Uninitialized;
    let mut history = SessionHistory::default();
    for log in logs {
        let session_event = log.into();
        history.events.push(session_event.clone());
        let current_sender = std::mem::replace(&mut sender, SendSession::Uninitialized);
        match current_sender.process_event(session_event) {
            Ok(next_sender) => sender = next_sender,
            Err(_e) => {
                persister.close().map_err(|e| {
                    InternalReplayError::PersistenceFailure(ImplementationError::new(e))
                })?;
                break;
            }
        }
    }

    let pj_param = history.pj_param().expect("pj_param should be present");
    if std::time::SystemTime::now() > pj_param.expiration() {
        // Session has expired: close the session and persist a fatal error
        persister
            .save_event(SessionEvent::SessionInvalid("Session expired".to_string()).into())
            .map_err(|e| InternalReplayError::PersistenceFailure(ImplementationError::new(e)))?;
        persister
            .close()
            .map_err(|e| InternalReplayError::PersistenceFailure(ImplementationError::new(e)))?;

        return Ok((SendSession::TerminalFailure, history));
    }
    Ok((sender, history))
}

#[derive(Default, Clone)]
pub struct SessionHistory {
    events: Vec<SessionEvent>,
}

impl SessionHistory {
    /// Fallback transaction from the session if present
    pub fn fallback_tx(&self) -> Option<bitcoin::Transaction> {
        self.events.iter().find_map(|event| match event {
            SessionEvent::CreatedReplyKey(proposal) =>
                Some(proposal.psbt_ctx.original_psbt.clone().extract_tx_unchecked_fee_rate()),
            _ => None,
        })
    }

    pub fn pj_param(&self) -> Option<&PjParam> {
        self.events.iter().find_map(|event| match event {
            SessionEvent::CreatedReplyKey(proposal) => Some(&proposal.pj_param),
            _ => None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SessionEvent {
    /// Sender was created with a HPKE key pair
    CreatedReplyKey(WithReplyKey),
    /// Sender POST'd the original PSBT, and waiting to receive a Proposal PSBT using GET context
    V2GetContext(V2GetContext),
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
    use crate::send::v1::SenderBuilder;
    use crate::send::v2::Sender;
    use crate::send::PsbtContext;
    use crate::{HpkeKeyPair, Uri, UriExt};

    const PJ_URI: &str =
        "bitcoin:2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7?amount=0.02&pjos=0&pj=HTTPS://EXAMPLE.COM/";

    #[test]
    fn test_sender_session_event_serialization_roundtrip() {
        let keypair = HpkeKeyPair::gen_keypair();
        let id = crate::uri::ShortId::try_from(&b"12345670"[..]).expect("valid short id");
        let endpoint = url::Url::parse("http://localhost:1234").expect("valid url");
        let pj_param = crate::uri::v2::PjParam::new(
            endpoint,
            id,
            std::time::SystemTime::now() + std::time::Duration::from_secs(60),
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

        let v2_get_context = V2GetContext {
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
            SessionEvent::V2GetContext(v2_get_context.clone()),
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
        fallback_tx: Option<bitcoin::Transaction>,
        pj_param: Option<PjParam>,
    }

    struct SessionHistoryTest {
        events: Vec<SessionEvent>,
        expected_session_history: SessionHistoryExpectedOutcome,
        expected_sender_state: SendSession,
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
        assert_eq!(session_history.pj_param().cloned(), test.expected_session_history.pj_param);
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
        let endpoint = sender.endpoint().clone();
        let fallback_tx = sender.psbt_ctx.original_psbt.clone().extract_tx_unchecked_fee_rate();
        let id = crate::uri::ShortId::try_from(&b"12345670"[..]).expect("valid short id");
        let pj_param = crate::uri::v2::PjParam::new(
            endpoint,
            id,
            std::time::SystemTime::now() - std::time::Duration::from_secs(1),
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
        let test = SessionHistoryTest {
            events: vec![SessionEvent::CreatedReplyKey(with_reply_key)],
            expected_session_history: SessionHistoryExpectedOutcome {
                fallback_tx: Some(fallback_tx),
                pj_param: Some(pj_param),
            },
            expected_sender_state: SendSession::TerminalFailure,
        };
        run_session_history_test(test);
    }

    #[test]
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
        let endpoint = sender.endpoint().clone();
        let fallback_tx = sender.psbt_ctx.original_psbt.clone().extract_tx_unchecked_fee_rate();
        let id = crate::uri::ShortId::try_from(&b"12345670"[..]).expect("valid short id");
        let pj_param = crate::uri::v2::PjParam::new(
            endpoint,
            id,
            std::time::SystemTime::now() + std::time::Duration::from_secs(60),
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
            expected_session_history: SessionHistoryExpectedOutcome {
                fallback_tx: Some(fallback_tx),
                pj_param: Some(pj_param),
            },
            expected_sender_state: SendSession::WithReplyKey(sender),
        };
        run_session_history_test(test);
    }
}

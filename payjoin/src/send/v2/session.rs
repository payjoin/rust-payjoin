use url::Url;

use super::WithReplyKey;
use crate::persist::SessionPersister;
use crate::send::v2::{SenderTypeState, V2GetContext};
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
    InvalidStateAndEvent(Box<SenderTypeState>, Box<SessionEvent>),
    /// Application storage error
    PersistenceFailure(ImplementationError),
}

pub fn replay_event_log<P>(persister: &P) -> Result<(SenderTypeState, SessionHistory), ReplayError>
where
    P: SessionPersister + Clone,
    P::SessionEvent: Into<SessionEvent> + Clone,
{
    let logs = persister
        .load()
        .map_err(|e| InternalReplayError::PersistenceFailure(Box::new(e).into()))?;

    let mut sender = SenderTypeState::Uninitialized();
    let mut history = SessionHistory::default();
    for log in logs {
        history.events.push(log.clone().into());
        match sender.clone().process_event(log.into()) {
            Ok(next_sender) => sender = next_sender,
            Err(_e) => {
                persister
                    .close()
                    .map_err(|e| InternalReplayError::PersistenceFailure(Box::new(e)))?;
                break;
            }
        }
    }

    Ok((sender, history))
}

#[derive(Default, Clone)]
pub struct SessionHistory {
    events: Vec<SessionEvent>,
}

impl SessionHistory {
    pub fn endpoint(&self) -> Option<&Url> {
        self.events.iter().find_map(|event| match event {
            SessionEvent::V2GetContext(ctx) => Some(&ctx.endpoint),
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
    use payjoin_test_utils::PARSED_ORIGINAL_PSBT;

    use super::*;
    use crate::output_substitution::OutputSubstitution;
    use crate::send::v2::HpkeContext;
    use crate::send::{v1, PsbtContext};
    use crate::HpkeKeyPair;

    #[test]
    fn test_sender_session_event_serialization_roundtrip() {
        let endpoint = Url::parse("http://localhost:1234").expect("Valid URL");
        let keypair = HpkeKeyPair::gen_keypair();
        let sender_with_reply_key = WithReplyKey {
            v1: v1::Sender {
                psbt: PARSED_ORIGINAL_PSBT.clone(),
                endpoint: endpoint.clone(),
                output_substitution: OutputSubstitution::Enabled,
                fee_contribution: None,
                min_fee_rate: FeeRate::ZERO,
                payee: ScriptBuf::from(vec![0x00]),
            },
            reply_key: keypair.0.clone(),
        };

        let v2_get_context = V2GetContext {
            endpoint,
            psbt_ctx: PsbtContext {
                original_psbt: PARSED_ORIGINAL_PSBT.clone(),
                output_substitution: OutputSubstitution::Enabled,
                fee_contribution: None,
                min_fee_rate: FeeRate::ZERO,
                payee: ScriptBuf::from(vec![0x00]),
            },
            hpke_ctx: HpkeContext { receiver: keypair.clone().1, reply_pair: keypair },
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
}

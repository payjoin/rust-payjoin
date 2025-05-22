use bitcoin::{Psbt, ScriptBuf};
use serde::{Deserialize, Serialize};
use url::Url;

use super::{SenderState, SenderWithReplyKey, V2GetContext};
use crate::persist::SessionPersister;
use crate::ImplementationError;

#[derive(Debug)]
pub enum SenderReplayError {
    InvalidStateAndEvent(SenderState, SenderSessionEvent),
    PersistenceFailure(ImplementationError),
}

impl std::fmt::Display for SenderReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{:?}", self) }
}

impl std::error::Error for SenderReplayError {}

pub fn replay_sender_event_log<P>(
    persister: P,
) -> Result<(SenderState, SessionHistory), SenderReplayError>
where
    P: SessionPersister + Clone,
    P::SessionEvent: From<SenderSessionEvent> + Clone,
    SenderSessionEvent: From<P::SessionEvent>,
{
    let logs = persister.load().map_err(|e| SenderReplayError::PersistenceFailure(Box::new(e)))?;

    let mut sender = SenderState::Uninitialized();
    let mut history = SessionHistory::default();
    for log in logs {
        history.events.push(log.clone().into());
        match sender.clone().process_event(log.into()) {
            Ok(next_sender) => sender = next_sender,
            Err(_e) => {
                persister
                    .close()
                    .map_err(|e| SenderReplayError::PersistenceFailure(Box::new(e)))?;
                break;
            }
        }
    }

    Ok((sender, history))
}

#[derive(Default)]
pub struct SessionHistory {
    events: Vec<SenderSessionEvent>,
}

impl SessionHistory {
    fn sender_with_reply_key(&self) -> Option<&SenderWithReplyKey> {
        self.events.iter().find_map(|event| match event {
            SenderSessionEvent::CreatedReplyKey(sender_with_reply_key) =>
                Some(sender_with_reply_key),
            _ => None,
        })
    }

    pub fn payee_script(&self) -> Option<ScriptBuf> {
        self.sender_with_reply_key().map(|sender| sender.v1.payee.clone())
    }

    pub fn endpoint(&self) -> Option<&Url> {
        self.sender_with_reply_key().map(|sender| sender.v1.endpoint())
    }

    pub fn session_invalid(&self) -> Option<String> {
        self.events.iter().find_map(|event| match event {
            SenderSessionEvent::SessionInvalid(e) => Some(e.clone()),
            _ => None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SenderSessionEvent {
    /// Sender was created
    CreatedReplyKey(SenderWithReplyKey),
    /// Sender POST'd the original PSBT, and waiting to receive a Proposal PSBT using GET context
    V2GetContext(V2GetContext),
    /// Sender received a Proposal PSBT
    ProposalReceived(Psbt),
    /// Invalid session
    SessionInvalid(String),
}

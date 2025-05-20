use bitcoin::ScriptBuf;
use url::Url;

use super::{SenderSessionEvent, SenderState, SenderWithReplyKey};
use crate::persist::PersistedSession;

#[derive(Debug, Clone)]
pub enum SenderReplayError {
    InvalidStateAndEvent(SenderState, SenderSessionEvent),
}

impl std::fmt::Display for SenderReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{:?}", self) }
}

impl std::error::Error for SenderReplayError {}

pub fn replay_sender_event_log<P>(
    persister: P,
) -> Result<(SenderState, SessionHistory), SenderReplayError>
where
    P: PersistedSession + Clone,
    P::SessionEvent: From<SenderSessionEvent>,
    SenderSessionEvent: From<P::SessionEvent>,
{
    let logs = persister.load().unwrap();

    let mut sender = SenderState::Uninitialized();
    let mut history = SessionHistory::new(Vec::new());
    for log in logs {
        history.events.push(log.clone().into());
        match sender.clone().process_event(log.into()) {
            Ok(next_sender) => sender = next_sender,
            Err(_e) => {
                persister.close().unwrap();
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
    fn new(events: Vec<SenderSessionEvent>) -> Self { Self { events } }

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
}

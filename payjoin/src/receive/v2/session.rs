use std::time::SystemTime;

use super::{Receiver, ReceiverSessionEvent, ReceiverState, UninitializedReceiver};
use crate::output_substitution::OutputSubstitution;
use crate::persist::PersistedSession;
use crate::receive::v2::{id, subdir};
use crate::PjUri;

#[derive(Debug)]
/// Errors that can occur when replaying a receiver event log
pub enum ReceiverReplayError {
    /// Session expired
    SessionExpired(SystemTime),
    /// Invalid combination of state and event
    InvalidStateAndEvent(ReceiverState, ReceiverSessionEvent),
}

impl std::fmt::Display for ReceiverReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{:?}", self) }
}
impl std::error::Error for ReceiverReplayError {}

/// Replay a receiver event log to get the receiver in its current state [ReceiverState]
/// and a session history [SessionHistory]
pub fn replay_receiver_event_log<P>(
    persister: P,
) -> Result<(ReceiverState, SessionHistory), ReceiverReplayError>
where
    P: PersistedSession + Clone,
    P::SessionEvent: From<ReceiverSessionEvent>,
    ReceiverSessionEvent: From<P::SessionEvent>,
{
    // TODO: fix this
    let logs = persister.load().unwrap();
    let mut receiver = ReceiverState::Uninitialized(Receiver { state: UninitializedReceiver {} });
    let mut history = SessionHistory::new(Vec::new());

    for log in logs {
        history.events.push(log.clone().into());
        // TODO: remove clone
        match receiver.clone().process_event(log.into()) {
            Ok(next_receiver) => {
                receiver = next_receiver;
            }
            Err(_e) => {
                // All error cases are terminal. Close the session in its current state
                persister.close().unwrap();
                break;
            }
        }
    }

    Ok((receiver, history))
}

#[derive(Clone)]
pub struct SessionHistory {
    events: Vec<ReceiverSessionEvent>,
}

impl SessionHistory {
    fn new(events: Vec<ReceiverSessionEvent>) -> Self { Self { events } }

    pub fn pj_uri<'a>(&self) -> Option<PjUri<'a>> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::Created(session_context) => {
                // TODO this code was copied from ReceiverWithContext::pj_uri. Should be deduped
                use crate::uri::{PayjoinExtras, UrlExt};
                let id = id(&session_context.s);
                let mut pj = subdir(&session_context.directory, &id).clone();
                pj.set_receiver_pubkey(session_context.s.public_key().clone());
                pj.set_ohttp(session_context.ohttp_keys.clone());
                pj.set_exp(session_context.expiry);
                let extras = PayjoinExtras {
                    endpoint: pj,
                    output_substitution: OutputSubstitution::Disabled,
                };
                Some(bitcoin_uri::Uri::with_extras(session_context.address.clone(), extras))
            }
            _ => None,
        })
    }

    pub fn payment_amount(&self) -> Option<bitcoin::Amount> { self.pj_uri().map(|uri| uri.amount)? }

    pub fn payment_address(&self) -> Option<bitcoin::Address<bitcoin::address::NetworkChecked>> {
        self.pj_uri().map(|uri| uri.address)
    }

    pub fn proposal_txid(&self) -> Option<bitcoin::Txid> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::ProvisionalProposal(proposal) =>
                Some(proposal.payjoin_psbt.unsigned_tx.compute_txid()),
            _ => None,
        })
    }

    pub fn fallback_txid(&self) -> Option<bitcoin::Txid> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::UncheckedProposal(proposal) =>
                Some(proposal.psbt.unsigned_tx.compute_txid()),
            _ => None,
        })
    }
}

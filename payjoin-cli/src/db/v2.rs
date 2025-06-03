use std::sync::Arc;
use std::time::SystemTime;

use bitcoincore_rpc::jsonrpc::serde_json;
use payjoin::bitcoin::hex::DisplayHex;
use payjoin::persist::{Persister, SessionPersister, Value};
use payjoin::receive::v2::SessionEvent;
use payjoin::send::v2::{Sender, SenderToken, WithReplyKey};
use serde::{Deserialize, Serialize};
use sled::Tree;
use url::Url;

use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SessionWrapper<V> {
    pub(crate) completed_at: Option<SystemTime>,
    pub(crate) events: Vec<V>,
}

#[derive(Debug, Clone)]
pub struct SessionId([u8; 8]);

impl SessionId {
    pub fn new(id: u64) -> Self { Self(id.to_be_bytes()) }
}

impl AsRef<[u8]> for SessionId {
    fn as_ref(&self) -> &[u8] { self.0.as_ref() }
}

pub(crate) struct SenderPersister(Arc<Database>);
impl SenderPersister {
    pub fn new(db: Arc<Database>) -> Self { Self(db) }
}

impl Persister<Sender<WithReplyKey>> for SenderPersister {
    type Token = SenderToken;
    type Error = crate::db::error::Error;
    fn save(
        &mut self,
        value: Sender<WithReplyKey>,
    ) -> std::result::Result<SenderToken, Self::Error> {
        let send_tree = self.0 .0.open_tree("send_sessions")?;
        let key = value.key();
        let value = serde_json::to_vec(&value).map_err(Error::Serialize)?;
        send_tree.insert(key.clone(), value.as_slice())?;
        send_tree.flush()?;
        Ok(key)
    }

    fn load(&self, key: SenderToken) -> std::result::Result<Sender<WithReplyKey>, Self::Error> {
        let send_tree = self.0 .0.open_tree("send_sessions")?;
        let value = send_tree.get(key.as_ref())?.ok_or(Error::NotFound(key.to_string()))?;
        serde_json::from_slice(&value).map_err(Error::Deserialize)
    }
}

#[derive(Clone)]
pub(crate) struct ReceiverPersister {
    db: Arc<Database>,
    session_id: SessionId,
}
impl ReceiverPersister {
    pub fn new(db: Arc<Database>) -> crate::db::Result<Self> {
        let id = SessionId::new(db.0.generate_id()?);
        let recv_tree = db.0.open_tree("recv_sessions")?;
        let empty_session: SessionWrapper<SessionEvent> =
            SessionWrapper { completed_at: None, events: vec![] };
        let value = serde_json::to_vec(&empty_session).map_err(Error::Serialize)?;
        recv_tree.insert(id.as_ref(), value.as_slice())?;
        recv_tree.flush()?;

        Ok(Self { db: db.clone(), session_id: id })
    }

    pub fn from_id(db: Arc<Database>, id: SessionId) -> crate::db::Result<Self> {
        Ok(Self { db: db.clone(), session_id: id })
    }
}

impl SessionPersister for ReceiverPersister {
    type SessionEvent = SessionEvent;
    type InternalStorageError = crate::db::error::Error;

    fn save_event(
        &self,
        event: &SessionEvent,
    ) -> std::result::Result<(), Self::InternalStorageError> {
        let recv_tree = self.db.0.open_tree("recv_sessions")?;
        let key = self.session_id.as_ref();
        let session =
            recv_tree.get(key)?.ok_or(Error::NotFound(key.to_vec().to_lower_hex_string()))?;
        let mut session_wrapper: SessionWrapper<SessionEvent> =
            serde_json::from_slice(&session).map_err(Error::Deserialize)?;
        session_wrapper.events.push(event.clone());
        let value = serde_json::to_vec(&session_wrapper).map_err(Error::Serialize)?;
        recv_tree.insert(key, value.as_slice())?;
        recv_tree.flush()?;
        Ok(())
    }

    fn load(
        &self,
    ) -> std::result::Result<Box<dyn Iterator<Item = SessionEvent>>, Self::InternalStorageError>
    {
        let recv_tree = self.db.0.open_tree("recv_sessions")?;
        let session_wrapper = recv_tree.get(self.session_id.as_ref())?;
        let value = session_wrapper.expect("key should exist");
        let wrapper: SessionWrapper<SessionEvent> =
            serde_json::from_slice(&value).map_err(Error::Deserialize)?;
        Ok(Box::new(wrapper.events.into_iter()))
    }

    fn close(&self) -> std::result::Result<(), Self::InternalStorageError> {
        let recv_tree = self.db.0.open_tree("recv_sessions")?;
        let key = self.session_id.as_ref();
        if let Some(existing) = recv_tree.get(key)? {
            let mut wrapper: SessionWrapper<SessionEvent> =
                serde_json::from_slice(&existing).map_err(Error::Deserialize)?;
            wrapper.completed_at = Some(SystemTime::now());
            let value = serde_json::to_vec(&wrapper).map_err(Error::Serialize)?;
            recv_tree.insert(key, value.as_slice())?;
        }
        recv_tree.flush()?;
        Ok(())
    }
}

impl Database {
    pub(crate) fn get_recv_session_ids(&self) -> Result<Vec<SessionId>> {
        let recv_tree = self.0.open_tree("recv_sessions")?;
        let mut session_ids = Vec::new();
        for item in recv_tree.iter() {
            let (key, _) = item?;
            session_ids.push(SessionId::new(u64::from_be_bytes(
                key.as_ref().try_into().map_err(Error::TryFromSlice)?,
            )));
        }
        Ok(session_ids)
    }

    pub(crate) fn get_send_sessions(&self) -> Result<Vec<Sender<WithReplyKey>>> {
        let send_tree: Tree = self.0.open_tree("send_sessions")?;
        let mut sessions = Vec::new();
        for item in send_tree.iter() {
            let (_, value) = item?;
            let session: Sender<WithReplyKey> =
                serde_json::from_slice(&value).map_err(Error::Deserialize)?;
            sessions.push(session);
        }
        Ok(sessions)
    }

    pub(crate) fn get_send_session(&self, pj_url: &Url) -> Result<Option<Sender<WithReplyKey>>> {
        let send_tree = self.0.open_tree("send_sessions")?;
        if let Some(val) = send_tree.get(pj_url.as_str())? {
            let session: Sender<WithReplyKey> =
                serde_json::from_slice(&val).map_err(Error::Deserialize)?;
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn clear_send_session(&self, pj_url: &Url) -> Result<()> {
        let send_tree: Tree = self.0.open_tree("send_sessions")?;
        send_tree.remove(pj_url.as_str())?;
        send_tree.flush()?;
        Ok(())
    }
}

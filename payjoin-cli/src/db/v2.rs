use std::sync::Arc;
use std::time::SystemTime;

use bitcoincore_rpc::jsonrpc::serde_json;
use payjoin::bitcoin::hex::DisplayHex;
use payjoin::persist::SessionPersister;
use payjoin::receive::v2::SessionEvent as ReceiverSessionEvent;
use payjoin::send::v2::SessionEvent as SenderSessionEvent;
use serde::{Deserialize, Serialize};

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

#[derive(Clone)]
pub(crate) struct SenderPersister {
    db: Arc<Database>,
    session_id: SessionId,
}
impl SenderPersister {
    pub fn new(db: Arc<Database>) -> crate::db::Result<Self> {
        let id = SessionId::new(db.0.generate_id().unwrap());
        let send_tree = db.0.open_tree("send_sessions")?;
        let empty_session: SessionWrapper<SenderSessionEvent> =
            SessionWrapper { completed_at: None, events: vec![] };
        let value = serde_json::to_vec(&empty_session).map_err(Error::Serialize)?;
        send_tree.insert(id.as_ref(), value.as_slice())?;
        send_tree.flush()?;

        Ok(Self { db: db.clone(), session_id: id })
    }

    pub fn from_id(db: Arc<Database>, id: SessionId) -> crate::db::Result<Self> {
        Ok(Self { db: db.clone(), session_id: id })
    }
}

impl SessionPersister for SenderPersister {
    type SessionEvent = SenderSessionEvent;
    type InternalStorageError = crate::db::error::Error;
    fn save_event(
        &self,
        event: &SenderSessionEvent,
    ) -> std::result::Result<(), Self::InternalStorageError> {
        let send_tree = self.db.0.open_tree("send_sessions")?;
        let key = self.session_id.as_ref();
        let session = send_tree.get(key)?.expect("key should exist");
        let mut session_wrapper: SessionWrapper<SenderSessionEvent> =
            serde_json::from_slice(&session).map_err(Error::Deserialize)?;
        session_wrapper.events.push(event.clone());
        let value = serde_json::to_vec(&session_wrapper).map_err(Error::Serialize)?;
        send_tree.insert(key, value.as_slice())?;

        send_tree.flush()?;
        Ok(())
    }

    fn load(
        &self,
    ) -> std::result::Result<Box<dyn Iterator<Item = SenderSessionEvent>>, Self::InternalStorageError>
    {
        let send_tree = self.db.0.open_tree("send_sessions")?;
        let session_wrapper = send_tree.get(self.session_id.as_ref())?;
        let value = session_wrapper.expect("key should exist");
        let wrapper: SessionWrapper<SenderSessionEvent> =
            serde_json::from_slice(&value).map_err(Error::Deserialize)?;
        Ok(Box::new(wrapper.events.into_iter()))
    }

    fn close(&self) -> std::result::Result<(), Self::InternalStorageError> {
        let send_tree = self.db.0.open_tree("send_sessions")?;
        let key = self.session_id.as_ref();
        if let Some(existing) = send_tree.get(key)? {
            let mut wrapper: SessionWrapper<SenderSessionEvent> =
                serde_json::from_slice(&existing).map_err(Error::Deserialize)?;
            wrapper.completed_at = Some(SystemTime::now());
            let value = serde_json::to_vec(&wrapper).map_err(Error::Serialize)?;
            send_tree.insert(key, value.as_slice())?;
        }
        send_tree.flush()?;
        Ok(())
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
        let empty_session: SessionWrapper<ReceiverSessionEvent> =
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
    type SessionEvent = ReceiverSessionEvent;
    type InternalStorageError = crate::db::error::Error;

    fn save_event(
        &self,
        event: &ReceiverSessionEvent,
    ) -> std::result::Result<(), Self::InternalStorageError> {
        let recv_tree = self.db.0.open_tree("recv_sessions")?;
        let key = self.session_id.as_ref();
        let session =
            recv_tree.get(key)?.ok_or(Error::NotFound(key.to_vec().to_lower_hex_string()))?;
        let mut session_wrapper: SessionWrapper<ReceiverSessionEvent> =
            serde_json::from_slice(&session).map_err(Error::Deserialize)?;
        session_wrapper.events.push(event.clone());
        let value = serde_json::to_vec(&session_wrapper).map_err(Error::Serialize)?;
        recv_tree.insert(key, value.as_slice())?;
        recv_tree.flush()?;
        Ok(())
    }

    fn load(
        &self,
    ) -> std::result::Result<
        Box<dyn Iterator<Item = ReceiverSessionEvent>>,
        Self::InternalStorageError,
    > {
        let recv_tree = self.db.0.open_tree("recv_sessions")?;
        let session_wrapper = recv_tree.get(self.session_id.as_ref())?;
        let value = session_wrapper.expect("key should exist");
        let wrapper: SessionWrapper<ReceiverSessionEvent> =
            serde_json::from_slice(&value).map_err(Error::Deserialize)?;
        Ok(Box::new(wrapper.events.into_iter()))
    }

    fn close(&self) -> std::result::Result<(), Self::InternalStorageError> {
        let recv_tree = self.db.0.open_tree("recv_sessions")?;
        let key = self.session_id.as_ref();
        if let Some(existing) = recv_tree.get(key)? {
            let mut wrapper: SessionWrapper<ReceiverSessionEvent> =
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
            let (key, value) = item?;
            let wrapper: SessionWrapper<ReceiverSessionEvent> =
                serde_json::from_slice(&value).map_err(Error::Deserialize)?;
            if wrapper.completed_at.is_some() {
                continue;
            }
            session_ids.push(SessionId::new(u64::from_be_bytes(
                key.as_ref().try_into().map_err(Error::TryFromSlice)?,
            )));
        }
        Ok(session_ids)
    }

    pub(crate) fn get_send_session_ids(&self) -> Result<Vec<SessionId>> {
        let send_tree = self.0.open_tree("send_sessions")?;
        let mut session_ids = Vec::new();
        for item in send_tree.iter() {
            let (key, value) = item?;
            let wrapper: SessionWrapper<SenderSessionEvent> =
                serde_json::from_slice(&value).map_err(Error::Deserialize)?;
            if wrapper.completed_at.is_some() {
                continue;
            }
            session_ids.push(SessionId::new(u64::from_be_bytes(
                key.as_ref().try_into().map_err(Error::TryFromSlice)?,
            )));
        }
        Ok(session_ids)
    }
}

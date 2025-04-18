use std::sync::Arc;
use std::time::SystemTime;

use bitcoincore_rpc::jsonrpc::serde_json;
use payjoin::persist::PersistedSession;
use payjoin::receive::v2::ReceiverSessionEvent;
use payjoin::send::v2::SenderSessionEvent;
use serde::{Deserialize, Serialize};
use sled::Tree;

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
}

impl PersistedSession for SenderPersister {
    type SessionEvent = SenderSessionEvent;
    type Error = crate::db::error::Error;
    fn save(&self, event: SenderSessionEvent) -> std::result::Result<(), Self::Error> {
        // Append to list of session updates
        let send_tree = self.db.0.open_tree("send_sessions")?;
        let key = self.session_id.as_ref();
        // Check if key exists
        let session = send_tree.get(key)?.expect("key should exist");
        // Deserialize existing events
        let mut session_wrapper: SessionWrapper<SenderSessionEvent> =
            serde_json::from_slice(&session).map_err(Error::Deserialize)?;
        // Append new event
        session_wrapper.events.push(event);
        // Serialize and save updated events
        let value = serde_json::to_vec(&session_wrapper).map_err(Error::Serialize)?;
        send_tree.insert(key, value.as_slice())?;

        send_tree.flush()?;
        Ok(())
    }

    fn load(&self) -> std::result::Result<impl Iterator<Item = SenderSessionEvent>, Self::Error> {
        let send_tree = self.db.0.open_tree("send_sessions")?;
        let session_wrapper = send_tree.get(self.session_id.as_ref())?;
        let value = session_wrapper.expect("key should exist");
        let wrapper: SessionWrapper<SenderSessionEvent> =
            serde_json::from_slice(&value).map_err(Error::Deserialize)?;
        Ok(wrapper.events.into_iter())
    }

    fn close(&self) -> std::result::Result<(), Self::Error> {
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
        let id = SessionId::new(db.0.generate_id().unwrap());
        let recv_tree = db.0.open_tree("recv_sessions")?;
        let empty_session: SessionWrapper<ReceiverSessionEvent> =
            SessionWrapper { completed_at: None, events: vec![] };
        let value = serde_json::to_vec(&empty_session).map_err(Error::Serialize)?;
        recv_tree.insert(id.as_ref(), value.as_slice())?;
        recv_tree.flush()?;

        Ok(Self { db: db.clone(), session_id: id })
    }
}

impl PersistedSession for ReceiverPersister {
    type SessionEvent = ReceiverSessionEvent;
    type Error = crate::db::error::Error;

    fn save(&self, event: ReceiverSessionEvent) -> std::result::Result<(), Self::Error> {
        let recv_tree = self.db.0.open_tree("recv_sessions")?;
        let key = self.session_id.as_ref();
        // Check if key exists
        let session = recv_tree.get(key)?.expect("key should exist");
        // Deserialize existing events
        let mut session_wrapper: SessionWrapper<ReceiverSessionEvent> =
            serde_json::from_slice(&session).map_err(Error::Deserialize)?;
        // Append new event
        session_wrapper.events.push(event);
        // Serialize and save updated events
        let value = serde_json::to_vec(&session_wrapper).map_err(Error::Serialize)?;
        recv_tree.insert(key, value.as_slice())?;
        recv_tree.flush()?;
        Ok(())
    }

    fn load(&self) -> std::result::Result<impl Iterator<Item = ReceiverSessionEvent>, Self::Error> {
        let recv_tree = self.db.0.open_tree("recv_sessions")?;
        let session_wrapper = recv_tree.get(self.session_id.as_ref())?;
        let value = session_wrapper.expect("key should exist");
        let wrapper: SessionWrapper<ReceiverSessionEvent> =
            serde_json::from_slice(&value).map_err(Error::Deserialize)?;
        Ok(wrapper.events.into_iter())
    }

    fn close(&self) -> std::result::Result<(), Self::Error> {
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
    pub(crate) fn get_recv_sessions(&self) -> Result<Vec<SessionWrapper<ReceiverSessionEvent>>> {
        let recv_tree = self.0.open_tree("recv_sessions")?;
        let mut sessions = Vec::new();
        for item in recv_tree.iter() {
            let (_, value) = item?;
            let wrapper: SessionWrapper<ReceiverSessionEvent> =
                serde_json::from_slice(&value).map_err(Error::Deserialize)?;
            if wrapper.completed_at.is_none() {
                sessions.push(wrapper);
            }
        }
        Ok(sessions)
    }

    // pub(crate) fn close_recv_session(&self, storage_token: ReceiverToken) -> Result<()> {
    //     let recv_tree: Tree = self.0.open_tree("recv_sessions")?;
    //     let session_wrapper = recv_tree.get(storage_token.as_ref())?;
    //     if let Some(val) = session_wrapper {
    //         let mut wrapper: SessionWrapper<ReceiverSessionEvent> =
    //             serde_json::from_slice(&val).map_err(Error::Deserialize)?;
    //         wrapper.completed_at = Some(SystemTime::now());
    //         let value = serde_json::to_vec(&wrapper).map_err(Error::Serialize)?;
    //         recv_tree.insert(storage_token.as_ref(), value.as_slice())?;
    //     }
    //     Ok(())
    // }

    pub(crate) fn get_send_sessions(&self) -> Result<Vec<SessionWrapper<SenderSessionEvent>>> {
        let send_tree: Tree = self.0.open_tree("send_sessions")?;
        let mut sessions = Vec::new();
        for item in send_tree.iter() {
            let (_, value) = item?;
            let wrapper: SessionWrapper<SenderSessionEvent> =
                serde_json::from_slice(&value).map_err(Error::Deserialize)?;
            if wrapper.completed_at.is_none() {
                sessions.push(wrapper);
            }
        }
        Ok(sessions)
    }

    // pub(crate) fn get_send_session(
    //     &self,
    //     pj_url: &Url,
    // ) -> Result<Option<SessionWrapper<SenderSessionEvent>>> {
    //     let send_tree = self.0.open_tree("send_sessions")?;
    //     if let Some(val) = send_tree.get(pj_url.as_str())? {
    //         let wrapper: SessionWrapper<SenderSessionEvent> =
    //             serde_json::from_slice(&val).map_err(Error::Deserialize)?;
    //         if wrapper.completed_at.is_none() {
    //             return Ok(Some(wrapper));
    //         } else {
    //             return Ok(None);
    //         }
    //     }
    //     Ok(None)
    // }

    // pub(crate) fn close_send_session(&self, pj_url: &Url) -> Result<()> {
    //     let send_tree: Tree = self.0.open_tree("send_sessions")?;
    //     let wrapper = send_tree.get(pj_url.as_str())?;
    //     if let Some(val) = wrapper {
    //         let mut wrapper: SessionWrapper<SenderSessionEvent> =
    //             serde_json::from_slice(&val).map_err(Error::Deserialize)?;
    //         wrapper.completed_at = Some(SystemTime::now());
    //         let value = serde_json::to_vec(&wrapper).map_err(Error::Serialize)?;
    //         send_tree.insert(pj_url.as_str(), value.as_slice())?;
    //     }
    //     send_tree.flush()?;
    //     Ok(())
    // }

    pub(crate) fn get_closed_send_sessions(
        &self,
    ) -> Result<Vec<SessionWrapper<SenderSessionEvent>>> {
        let send_tree: Tree = self.0.open_tree("send_sessions")?;
        let mut sessions = Vec::new();
        for item in send_tree.iter() {
            let (_, value) = item?;
            let wrapper: SessionWrapper<SenderSessionEvent> =
                serde_json::from_slice(&value).map_err(Error::Deserialize)?;
            if wrapper.completed_at.is_some() {
                sessions.push(wrapper);
            }
        }
        Ok(sessions)
    }

    pub(crate) fn get_closed_recv_sessions(
        &self,
    ) -> Result<Vec<SessionWrapper<ReceiverSessionEvent>>> {
        let recv_tree: Tree = self.0.open_tree("recv_sessions")?;
        let mut sessions = Vec::new();
        for item in recv_tree.iter() {
            let (_, value) = item?;
            let wrapper: SessionWrapper<ReceiverSessionEvent> =
                serde_json::from_slice(&value).map_err(Error::Deserialize)?;
            if wrapper.completed_at.is_some() {
                sessions.push(wrapper);
            }
        }
        Ok(sessions)
    }
}

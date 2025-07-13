use std::sync::Arc;
use std::time::SystemTime;

use bitcoincore_rpc::jsonrpc::serde_json;
use payjoin::persist::SessionPersister;
use payjoin::receive::v2::SessionEvent as ReceiverSessionEvent;
use payjoin::send::v2::SessionEvent as SenderSessionEvent;
use rusqlite::params;
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

    pub fn generate() -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        std::time::SystemTime::now().hash(&mut hasher);
        std::thread::current().id().hash(&mut hasher);

        Self::new(hasher.finish())
    }
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
        let id = SessionId::generate();
        let conn = db.get_connection()?;

        // Create a new session
        conn.execute(
            "INSERT INTO sessions (session_id, session_type, completed_at) VALUES (?1, ?2, ?3)",
            params![id.as_ref(), "sender", Option::<i64>::None],
        )?;

        Ok(Self { db, session_id: id })
    }

    pub fn from_id(db: Arc<Database>, id: SessionId) -> crate::db::Result<Self> {
        Ok(Self { db, session_id: id })
    }
}

impl SessionPersister for SenderPersister {
    type SessionEvent = SenderSessionEvent;
    type InternalStorageError = crate::db::error::Error;

    fn save_event(
        &self,
        event: &SenderSessionEvent,
    ) -> std::result::Result<(), Self::InternalStorageError> {
        let conn = self.db.get_connection()?;
        let event_data = serde_json::to_string(event).map_err(Error::Serialize)?;
        let timestamp =
            SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;

        conn.execute(
            "INSERT INTO session_events (session_id, event_data, created_at) VALUES (?1, ?2, ?3)",
            params![self.session_id.as_ref(), event_data, timestamp],
        )?;

        Ok(())
    }

    fn load(
        &self,
    ) -> std::result::Result<Box<dyn Iterator<Item = SenderSessionEvent>>, Self::InternalStorageError>
    {
        let conn = self.db.get_connection()?;
        let mut stmt = conn.prepare(
            "SELECT event_data FROM session_events WHERE session_id = ?1 ORDER BY created_at ASC",
        )?;

        let event_rows = stmt.query_map(params![self.session_id.as_ref()], |row| {
            let event_data: String = row.get(0)?;
            Ok(event_data)
        })?;

        let mut events = Vec::new();
        for event_row in event_rows {
            let event_data = event_row?;
            let event: SenderSessionEvent =
                serde_json::from_str(&event_data).map_err(Error::Deserialize)?;
            events.push(event);
        }

        Ok(Box::new(events.into_iter()))
    }

    fn close(&self) -> std::result::Result<(), Self::InternalStorageError> {
        let conn = self.db.get_connection()?;
        let timestamp =
            SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;

        conn.execute(
            "UPDATE sessions SET completed_at = ?1 WHERE session_id = ?2",
            params![timestamp, self.session_id.as_ref()],
        )?;

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
        let id = SessionId::generate();
        let conn = db.get_connection()?;

        conn.execute(
            "INSERT INTO sessions (session_id, session_type, completed_at) VALUES (?1, ?2, ?3)",
            params![id.as_ref(), "receiver", Option::<i64>::None],
        )?;

        Ok(Self { db, session_id: id })
    }

    pub fn from_id(db: Arc<Database>, id: SessionId) -> crate::db::Result<Self> {
        Ok(Self { db, session_id: id })
    }
}

impl SessionPersister for ReceiverPersister {
    type SessionEvent = ReceiverSessionEvent;
    type InternalStorageError = crate::db::error::Error;

    fn save_event(
        &self,
        event: &ReceiverSessionEvent,
    ) -> std::result::Result<(), Self::InternalStorageError> {
        let conn = self.db.get_connection()?;
        let event_data = serde_json::to_string(event).map_err(Error::Serialize)?;
        let timestamp =
            SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;

        conn.execute(
            "INSERT INTO session_events (session_id, event_data, created_at) VALUES (?1, ?2, ?3)",
            params![self.session_id.as_ref(), event_data, timestamp],
        )?;

        Ok(())
    }

    fn load(
        &self,
    ) -> std::result::Result<
        Box<dyn Iterator<Item = ReceiverSessionEvent>>,
        Self::InternalStorageError,
    > {
        let conn = self.db.get_connection()?;
        let mut stmt = conn.prepare(
            "SELECT event_data FROM session_events WHERE session_id = ?1 ORDER BY created_at ASC",
        )?;

        let event_rows = stmt.query_map(params![self.session_id.as_ref()], |row| {
            let event_data: String = row.get(0)?;
            Ok(event_data)
        })?;

        let mut events = Vec::new();
        for event_row in event_rows {
            let event_data = event_row?;
            let event: ReceiverSessionEvent =
                serde_json::from_str(&event_data).map_err(Error::Deserialize)?;
            events.push(event);
        }

        Ok(Box::new(events.into_iter()))
    }

    fn close(&self) -> std::result::Result<(), Self::InternalStorageError> {
        let conn = self.db.get_connection()?;
        let timestamp =
            SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;

        conn.execute(
            "UPDATE sessions SET completed_at = ?1 WHERE session_id = ?2",
            params![timestamp, self.session_id.as_ref()],
        )?;

        Ok(())
    }
}

impl Database {
    pub(crate) fn get_recv_session_ids(&self) -> Result<Vec<SessionId>> {
        let conn = self.get_connection()?;
        let mut stmt = conn.prepare(
            "SELECT session_id FROM sessions WHERE session_type = ?1 AND completed_at IS NULL",
        )?;

        let session_rows = stmt.query_map(params!["receiver"], |row| {
            let session_id: Vec<u8> = row.get(0)?;
            Ok(session_id)
        })?;

        let mut session_ids = Vec::new();
        for session_row in session_rows {
            let session_id_bytes = session_row?;
            if session_id_bytes.len() == 8 {
                let mut id_array = [0u8; 8];
                id_array.copy_from_slice(&session_id_bytes);
                session_ids.push(SessionId(id_array));
            }
        }

        Ok(session_ids)
    }

    pub(crate) fn get_send_session_ids(&self) -> Result<Vec<SessionId>> {
        let conn = self.get_connection()?;
        let mut stmt = conn.prepare(
            "SELECT session_id FROM sessions WHERE session_type = ?1 AND completed_at IS NULL",
        )?;

        let session_rows = stmt.query_map(params!["sender"], |row| {
            let session_id: Vec<u8> = row.get(0)?;
            Ok(session_id)
        })?;

        let mut session_ids = Vec::new();
        for session_row in session_rows {
            let session_id_bytes = session_row?;
            if session_id_bytes.len() == 8 {
                let mut id_array = [0u8; 8];
                id_array.copy_from_slice(&session_id_bytes);
                session_ids.push(SessionId(id_array));
            }
        }

        Ok(session_ids)
    }
}

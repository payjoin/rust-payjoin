use std::sync::Arc;
use std::time::SystemTime;

use bitcoincore_rpc::jsonrpc::serde_json;
use payjoin::persist::SessionPersister;
use payjoin::receive::v2::SessionEvent as ReceiverSessionEvent;
use payjoin::send::v2::SessionEvent as SenderSessionEvent;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use super::*;

macro_rules! now {
    () => {
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SessionWrapper<V> {
    pub(crate) completed_at: Option<SystemTime>,
    pub(crate) events: Vec<V>,
}

#[derive(Debug, Clone)]
pub enum SessionId {
    Send(i64),
    Receive(i64),
}

impl SessionId {
    pub fn as_integer(&self) -> i64 {
        match self {
            SessionId::Send(id) => *id,
            SessionId::Receive(id) => *id,
        }
    }

    pub fn session_type(&self) -> &'static str {
        match self {
            SessionId::Send(_) => "send",
            SessionId::Receive(_) => "receive",
        }
    }
}

#[derive(Clone)]
pub(crate) struct SenderPersister {
    db: Arc<Database>,
    session_id: SessionId,
}

impl SenderPersister {
    pub fn new(db: Arc<Database>) -> crate::db::Result<Self> {
        let conn = db.get_connection()?;

        // Create a new session in send_sessions table
        conn.execute(
            "INSERT INTO send_sessions (completed_at) VALUES (?1)",
            params![Option::<i64>::None],
        )?;

        // Get the generated session ID
        let session_id = conn.last_insert_rowid();

        Ok(Self { db, session_id: SessionId::Send(session_id) })
    }

    pub fn from_id(db: Arc<Database>, id: SessionId) -> crate::db::Result<Self> {
        match id {
            SessionId::Send(_) => Ok(Self { db, session_id: id }),
            SessionId::Receive(_) =>
                panic!("Attempted to create SenderPersister with Receive session ID"),
        }
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
        let timestamp = now!();

        conn.execute(
            "INSERT INTO session_events (session_id, session_type, event_data, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![self.session_id.as_integer(), self.session_id.session_type(), event_data, timestamp],
        )?;

        Ok(())
    }

    fn load(
        &self,
    ) -> std::result::Result<Box<dyn Iterator<Item = SenderSessionEvent>>, Self::InternalStorageError>
    {
        let conn = self.db.get_connection()?;
        let mut stmt = conn.prepare(
            "SELECT event_data FROM session_events WHERE session_id = ?1 AND session_type = ?2 ORDER BY created_at ASC",
        )?;

        let event_rows = stmt.query_map(
            params![self.session_id.as_integer(), self.session_id.session_type()],
            |row| {
                let event_data: String = row.get(0)?;
                Ok(event_data)
            },
        )?;

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
        let timestamp = now!();

        conn.execute(
            "UPDATE send_sessions SET completed_at = ?1 WHERE session_id = ?2",
            params![timestamp, self.session_id.as_integer()],
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
        let conn = db.get_connection()?;

        conn.execute(
            "INSERT INTO receive_sessions (completed_at) VALUES (?1)",
            params![Option::<i64>::None],
        )?;

        let session_id = conn.last_insert_rowid();

        Ok(Self { db, session_id: SessionId::Receive(session_id) })
    }

    pub fn from_id(db: Arc<Database>, id: SessionId) -> crate::db::Result<Self> {
        match id {
            SessionId::Receive(_) => Ok(Self { db, session_id: id }),
            SessionId::Send(_) =>
                panic!("Attempted to create ReceiverPersister with Send session ID"),
        }
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
        let timestamp = now!();

        conn.execute(
            "INSERT INTO session_events (session_id, session_type, event_data, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![self.session_id.as_integer(), self.session_id.session_type(), event_data, timestamp],
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
            "SELECT event_data FROM session_events WHERE session_id = ?1 AND session_type = ?2 ORDER BY created_at ASC",
        )?;

        let event_rows = stmt.query_map(
            params![self.session_id.as_integer(), self.session_id.session_type()],
            |row| {
                let event_data: String = row.get(0)?;
                Ok(event_data)
            },
        )?;

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
        let timestamp = now!();

        conn.execute(
            "UPDATE receive_sessions SET completed_at = ?1 WHERE session_id = ?2",
            params![timestamp, self.session_id.as_integer()],
        )?;

        Ok(())
    }
}

impl Database {
    pub(crate) fn get_recv_session_ids(&self) -> Result<Vec<SessionId>> {
        let conn = self.get_connection()?;
        let mut stmt =
            conn.prepare("SELECT session_id FROM receive_sessions WHERE completed_at IS NULL")?;

        let session_rows = stmt.query_map([], |row| {
            let session_id: i64 = row.get(0)?;
            Ok(SessionId::Receive(session_id))
        })?;

        let mut session_ids = Vec::new();
        for session_row in session_rows {
            let session_id = session_row?;
            session_ids.push(session_id);
        }

        Ok(session_ids)
    }

    pub(crate) fn get_send_session_ids(&self) -> Result<Vec<SessionId>> {
        let conn = self.get_connection()?;
        let mut stmt =
            conn.prepare("SELECT session_id FROM send_sessions WHERE completed_at IS NULL")?;

        let session_rows = stmt.query_map([], |row| {
            let session_id: i64 = row.get(0)?;
            Ok(SessionId::Send(session_id))
        })?;

        let mut session_ids = Vec::new();
        for session_row in session_rows {
            let session_id = session_row?;
            session_ids.push(session_id);
        }

        Ok(session_ids)
    }
}

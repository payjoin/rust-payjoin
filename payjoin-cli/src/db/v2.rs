use std::sync::Arc;

use payjoin::persist::SessionPersister;
use payjoin::receive::v2::SessionEvent as ReceiverSessionEvent;
use payjoin::send::v2::SessionEvent as SenderSessionEvent;
use payjoin::HpkePublicKey;
use rusqlite::{params, OptionalExtension};

use super::*;

#[derive(Debug, Clone)]
pub(crate) struct SessionId(i64);

impl core::ops::Deref for SessionId {
    type Target = i64;
    fn deref(&self) -> &Self::Target { &self.0 }
}

#[derive(Clone)]
pub(crate) struct SenderPersister {
    db: Arc<Database>,
    session_id: SessionId,
}

impl SenderPersister {
    pub fn new(db: Arc<Database>, receiver_pubkey: HpkePublicKey) -> crate::db::Result<Self> {
        let conn = db.get_connection()?;

        // Create a new session in send_sessions and get its ID
        let session_id: i64 = conn.query_row(
            "INSERT INTO send_sessions (session_id, receiver_pubkey) VALUES (NULL, ?1) RETURNING session_id",
            params![receiver_pubkey.to_compressed_bytes()],
            |row| row.get(0),
        )?;

        Ok(Self { db, session_id: SessionId(session_id) })
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
        event: SenderSessionEvent,
    ) -> std::result::Result<(), Self::InternalStorageError> {
        let conn = self.db.get_connection()?;
        let event_data = serde_json::to_string(&event).map_err(Error::Serialize)?;

        conn.execute(
            "INSERT INTO send_session_events (session_id, event_data, created_at) VALUES (?1, ?2, ?3)",
            params![*self.session_id, event_data, now()],
        )?;

        Ok(())
    }

    fn load(
        &self,
    ) -> std::result::Result<Box<dyn Iterator<Item = SenderSessionEvent>>, Self::InternalStorageError>
    {
        let conn = self.db.get_connection()?;
        let mut stmt = conn.prepare(
            "SELECT event_data FROM send_session_events WHERE session_id = ?1 ORDER BY created_at ASC",
        )?;

        let event_rows = stmt.query_map(params![*self.session_id], |row| {
            let event_data: String = row.get(0)?;
            Ok(event_data)
        })?;

        let events: Vec<SenderSessionEvent> = event_rows
            .map(|row| {
                let event_data = row.expect("Failed to read event data from database");
                serde_json::from_str::<SenderSessionEvent>(&event_data)
                    .expect("Database corruption: failed to deserialize session event")
            })
            .collect();

        Ok(Box::new(events.into_iter()))
    }

    fn close(&self) -> std::result::Result<(), Self::InternalStorageError> {
        let conn = self.db.get_connection()?;

        conn.execute(
            "UPDATE send_sessions SET completed_at = ?1 WHERE session_id = ?2",
            params![now(), *self.session_id],
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

        // Create a new session in receive_sessions and get its ID
        let session_id: i64 = conn.query_row(
            "INSERT INTO receive_sessions (session_id) VALUES (NULL) RETURNING session_id",
            [],
            |row| row.get(0),
        )?;

        Ok(Self { db, session_id: SessionId(session_id) })
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
        event: ReceiverSessionEvent,
    ) -> std::result::Result<(), Self::InternalStorageError> {
        let conn = self.db.get_connection()?;
        let event_data = serde_json::to_string(&event).map_err(Error::Serialize)?;

        conn.execute(
            "INSERT INTO receive_session_events (session_id, event_data, created_at) VALUES (?1, ?2, ?3)",
            params![*self.session_id, event_data, now()],
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
            "SELECT event_data FROM receive_session_events WHERE session_id = ?1 ORDER BY created_at ASC",
        )?;

        let event_rows = stmt.query_map(params![*self.session_id], |row| {
            let event_data: String = row.get(0)?;
            Ok(event_data)
        })?;

        let events: Vec<ReceiverSessionEvent> = event_rows
            .map(|row| {
                let event_data = row.expect("Failed to read event data from database");
                serde_json::from_str::<ReceiverSessionEvent>(&event_data)
                    .expect("Database corruption: failed to deserialize session event")
            })
            .collect();

        Ok(Box::new(events.into_iter()))
    }

    fn close(&self) -> std::result::Result<(), Self::InternalStorageError> {
        let conn = self.db.get_connection()?;

        conn.execute(
            "UPDATE receive_sessions SET completed_at = ?1 WHERE session_id = ?2",
            params![now(), *self.session_id],
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
            Ok(SessionId(session_id))
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
            Ok(SessionId(session_id))
        })?;

        let mut session_ids = Vec::new();
        for session_row in session_rows {
            let session_id = session_row?;
            session_ids.push(session_id);
        }

        Ok(session_ids)
    }

    pub(crate) fn get_send_session_id_with_receiver_pk(
        &self,
        receiver_pk: &HpkePublicKey,
    ) -> Result<Option<SessionId>> {
        let conn = self.get_connection()?;
        let mut stmt =
            conn.prepare("SELECT session_id FROM send_sessions WHERE receiver_pubkey = ?1")?;
        let session_id = stmt
            .query_row(params![receiver_pk.to_compressed_bytes()], |row| row.get(0))
            .optional()?;
        Ok(session_id.map(SessionId))
    }
}

use std::sync::Arc;

use payjoin::persist::SessionPersister;
use payjoin::receive::v2::SessionEvent as ReceiverSessionEvent;
use payjoin::send::v2::SessionEvent as SenderSessionEvent;
use payjoin::HpkePublicKey;
use rusqlite::params;

use super::*;

#[derive(Debug, Clone)]
pub(crate) struct SessionId(i64);

impl core::ops::Deref for SessionId {
    type Target = i64;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}

#[derive(Clone)]
pub(crate) struct SenderPersister {
    db: Arc<Database>,
    session_id: SessionId,
}

impl SenderPersister {
    pub fn new(
        db: Arc<Database>,
        receiver_pubkey: HpkePublicKey,
        original_uri: &str,
        bitcoin_address: &str,
    ) -> crate::db::Result<Self> {
        let conn = db.get_connection()?;

        // Perform duplicate checks only if the new columns exist
        // If they don't exist yet, we'll skip the enhanced safety checks

        // Try to check for duplicates with new columns, but handle gracefully if columns don't exist
        let has_new_columns =
            conn.prepare("SELECT original_uri, bitcoin_address FROM send_sessions LIMIT 1").is_ok();

        if has_new_columns {
            // Check for same URI with different receiver key (modified URI being retried)
            let modified_uri: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM send_sessions WHERE original_uri = ?1 AND receiver_pubkey != ?2 AND completed_at IS NULL)",
                params![original_uri, receiver_pubkey.to_compressed_bytes()],
                |row| row.get(0),
            ).unwrap_or(false);
            if modified_uri {
                return Err(crate::db::error::Error::DuplicateUri(original_uri.to_string()));
            }

            // Check for same receiver key with different URI (receiver key reuse)
            let reused_rk: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM send_sessions WHERE receiver_pubkey = ?1 AND original_uri != ?2 AND completed_at IS NULL)",
                params![receiver_pubkey.to_compressed_bytes(), original_uri],
                |row| row.get(0),
            ).unwrap_or(false);
            if reused_rk {
                return Err(crate::db::error::Error::DuplicateReceiverKey);
            }

            // Check for same bitcoin address with different receiver key (privacy issue)
            let addr_reuse: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM send_sessions WHERE bitcoin_address = ?1 AND receiver_pubkey != ?2 AND completed_at IS NULL)",
                params![bitcoin_address, receiver_pubkey.to_compressed_bytes()],
                |row| row.get(0),
            ).unwrap_or(false);
            if addr_reuse {
                return Err(crate::db::error::Error::DuplicateBitcoinAddress(
                    bitcoin_address.to_string(),
                ));
            }
        }

        // Create a new session - use new or old schema depending on what's available
        let session_id: i64 = if has_new_columns {
            conn.execute(
                "INSERT INTO send_sessions (receiver_pubkey, original_uri, bitcoin_address) VALUES (?1, ?2, ?3)",
                params![receiver_pubkey.to_compressed_bytes(), original_uri, bitcoin_address],
            )?;
            conn.last_insert_rowid()
        } else {
            // Fallback to original schema if new columns don't exist
            conn.execute(
                "INSERT INTO send_sessions (receiver_pubkey) VALUES (?1)",
                params![receiver_pubkey.to_compressed_bytes()],
            )?;
            conn.last_insert_rowid()
        };

        Ok(Self { db, session_id: SessionId(session_id) })
    }

    pub fn from_id(db: Arc<Database>, id: SessionId) -> Self { Self { db, session_id: id } }
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
        conn.execute("INSERT INTO receive_sessions DEFAULT VALUES", [])?;
        let session_id: i64 = conn.last_insert_rowid();

        Ok(Self { db, session_id: SessionId(session_id) })
    }

    pub fn from_id(db: Arc<Database>, id: SessionId) -> Self { Self { db, session_id: id } }
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

    pub(crate) fn get_send_session_receiver_pk(
        &self,
        session_id: &SessionId,
    ) -> Result<HpkePublicKey> {
        let conn = self.get_connection()?;
        let mut stmt =
            conn.prepare("SELECT receiver_pubkey FROM send_sessions WHERE session_id = ?1")?;
        let receiver_pubkey: Vec<u8> = stmt.query_row(params![session_id.0], |row| row.get(0))?;
        Ok(HpkePublicKey::from_compressed_bytes(&receiver_pubkey).expect("Valid receiver pubkey"))
    }

    pub(crate) fn get_inactive_send_session_ids(&self) -> Result<Vec<(SessionId, u64)>> {
        let conn = self.get_connection()?;
        let mut stmt = conn.prepare(
            "SELECT session_id, completed_at FROM send_sessions WHERE completed_at IS NOT NULL",
        )?;
        let session_rows = stmt.query_map([], |row| {
            let session_id: i64 = row.get(0)?;
            let completed_at: u64 = row.get(1)?;
            Ok((SessionId(session_id), completed_at))
        })?;

        let mut session_ids = Vec::new();
        for session_row in session_rows {
            let (session_id, completed_at) = session_row?;
            session_ids.push((session_id, completed_at));
        }
        Ok(session_ids)
    }

    pub(crate) fn get_inactive_recv_session_ids(&self) -> Result<Vec<(SessionId, u64)>> {
        let conn = self.get_connection()?;
        let mut stmt = conn.prepare(
            "SELECT session_id, completed_at FROM receive_sessions WHERE completed_at IS NOT NULL",
        )?;
        let session_rows = stmt.query_map([], |row| {
            let session_id: i64 = row.get(0)?;
            let completed_at: u64 = row.get(1)?;
            Ok((SessionId(session_id), completed_at))
        })?;

        let mut session_ids = Vec::new();
        for session_row in session_rows {
            let (session_id, completed_at) = session_row?;
            session_ids.push((session_id, completed_at));
        }
        Ok(session_ids)
    }
}

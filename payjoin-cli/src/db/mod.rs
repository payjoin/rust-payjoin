use std::path::Path;

use payjoin::bitcoin::consensus::encode::serialize;
use payjoin::bitcoin::OutPoint;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection};

pub(crate) mod error;
use error::*;

#[inline]
pub(crate) fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

pub(crate) const DB_PATH: &str = "payjoin.sqlite";

pub(crate) struct Database(Pool<SqliteConnectionManager>);

impl Database {
    pub(crate) fn create(path: impl AsRef<Path>) -> Result<Self> {
        let manager = SqliteConnectionManager::file(path.as_ref());
        let pool = Pool::new(manager)?;

        // Initialize database schema
        let conn = pool.get()?;
        Self::init_schema(&conn)?;

        Ok(Self(pool))
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        // Enable foreign keys
        conn.execute("PRAGMA foreign_keys = ON", [])?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS send_sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                receiver_pubkey BLOB NOT NULL,
                completed_event_id INTEGER,
                FOREIGN KEY(completed_event_id) REFERENCES send_session_events(id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS receive_sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                completed_event_id INTEGER,
                FOREIGN KEY(completed_event_id) REFERENCES receive_session_events(id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS send_session_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                event_data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(session_id) REFERENCES send_sessions(session_id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS receive_session_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                event_data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(session_id) REFERENCES receive_sessions(session_id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS inputs_seen (
                outpoint BLOB PRIMARY KEY,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;

        Ok(())
    }

    pub(crate) fn get_connection(&self) -> Result<r2d2::PooledConnection<SqliteConnectionManager>> {
        Ok(self.0.get()?)
    }
    /// Inserts the input and returns true if the input was seen before, false otherwise.
    pub(crate) fn insert_input_seen_before(&self, input: OutPoint) -> Result<bool> {
        let conn = self.get_connection()?;
        let key = serialize(&input);

        let was_seen_before = conn.execute(
            "INSERT OR IGNORE INTO inputs_seen (outpoint, created_at) VALUES (?1, ?2)",
            params![key, now()],
        )? == 0;

        Ok(was_seen_before)
    }
}

#[cfg(feature = "v2")]
pub(crate) mod v2;

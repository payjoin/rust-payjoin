use std::path::Path;

use payjoin::bitcoin::consensus::encode::serialize;
use payjoin::bitcoin::OutPoint;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection};

pub(crate) mod error;
use error::*;

pub(crate) const DB_PATH: &str = "payjoin.sqlite";

pub(crate) struct Database {
    pool: Pool<SqliteConnectionManager>,
}

impl Database {
    pub(crate) fn create(path: impl AsRef<Path>) -> Result<Self> {
        let manager = SqliteConnectionManager::file(path.as_ref());
        let pool = Pool::new(manager)?;

        // Initialize database schema
        let conn = pool.get()?;
        Self::init_schema(&conn)?;

        Ok(Self { pool })
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        // Create sessions table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions (
                session_id BLOB PRIMARY KEY,
                session_type TEXT NOT NULL,
                completed_at INTEGER
            )",
            [],
        )?;

        // Create session_events table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS session_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id BLOB NOT NULL,
                event_data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )",
            [],
        )?;

        // Create inputs_seen table for tracking inputs
        conn.execute(
            "CREATE TABLE IF NOT EXISTS inputs_seen (
                input_hash BLOB PRIMARY KEY,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;

        Ok(())
    }

    pub(crate) fn get_connection(&self) -> Result<r2d2::PooledConnection<SqliteConnectionManager>> {
        Ok(self.pool.get()?)
    }

    /// Inserts the input and returns true if the input was seen before, false otherwise.
    pub(crate) fn insert_input_seen_before(&self, input: OutPoint) -> Result<bool> {
        let conn = self.get_connection()?;
        let key = serialize(&input);
        let timestamp =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                as i64;

        let was_seen_before = conn.execute(
            "INSERT OR IGNORE INTO inputs_seen (input_hash, created_at) VALUES (?1, ?2)",
            params![key, timestamp],
        )? == 0;

        Ok(was_seen_before)
    }
}

#[cfg(feature = "v2")]
pub(crate) mod v2;

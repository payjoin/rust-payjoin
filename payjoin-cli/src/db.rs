use std::path::Path;

use anyhow::Result;
use payjoin::bitcoin::consensus::encode::serialize;
use payjoin::bitcoin::OutPoint;
use sled::IVec;

pub(crate) const DB_PATH: &str = "payjoin.sled";

pub(crate) struct Database(sled::Db);

impl Database {
    pub(crate) fn create(path: impl AsRef<Path>) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Self(db))
    }

    /// Inserts the input and returns true if the input was seen before, false otherwise.
    pub(crate) fn insert_input_seen_before(&self, input: OutPoint) -> Result<bool> {
        let key = serialize(&input);
        let was_seen_before = self.0.insert(key.as_slice(), IVec::from(vec![]))?.is_some();
        self.0.flush()?;
        Ok(was_seen_before)
    }
}

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub trait PersistableValue: Serialize + DeserializeOwned + Sized + Clone {
    /// Unique identifier for this persisted value
    fn key(&self) -> String;
}
/// Implemented types that should be persisted by the application.
pub trait Persister<V: PersistableValue> {
    type Error: std::error::Error + Send + Sync + 'static;

    fn save(&mut self, value: V) -> Result<String, Self::Error>;
    fn load(&self, key: &str) -> Result<V, Self::Error>;
}

/// Noop implementation
#[derive(Debug, Clone)]
pub struct NoopPersister;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoopToken<T>(T);

impl<V: PersistableValue> Persister<V> for NoopPersister {
    type Error = serde_json::Error;

    fn save(&mut self, value: V) -> Result<String, Self::Error> { serde_json::to_string(&value) }

    fn load(&self, key: &str) -> Result<V, Self::Error> { serde_json::from_str(key) }
}

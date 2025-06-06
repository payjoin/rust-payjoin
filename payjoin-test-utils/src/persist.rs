use std::sync::{Arc, RwLock};

use payjoin::persist::SessionPersister;

#[derive(Clone)]
pub struct InMemoryTestPersister<T> {
    pub inner: Arc<RwLock<InnerStorage<T>>>,
}

impl<T> Default for InMemoryTestPersister<T> {
    fn default() -> Self { Self { inner: Arc::new(RwLock::new(InnerStorage::default())) } }
}

#[derive(Clone)]
pub struct InnerStorage<T> {
    pub events: Vec<T>,
    pub is_closed: bool,
}

impl<T> Default for InnerStorage<T> {
    fn default() -> Self { Self { events: vec![], is_closed: false } }
}

#[derive(Debug, Clone, PartialEq)]
/// Dummy error type for testing
pub struct InMemoryTestError {}

impl std::error::Error for InMemoryTestError {}

impl std::fmt::Display for InMemoryTestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InMemoryTestError")
    }
}

/// Receiver InMemory Persister
impl SessionPersister for InMemoryTestPersister<payjoin::receive::v2::ReceiverSessionEvent> {
    type InternalStorageError = std::convert::Infallible;
    type SessionEvent = payjoin::receive::v2::ReceiverSessionEvent;

    fn save_event(&self, event: &Self::SessionEvent) -> Result<(), Self::InternalStorageError> {
        let mut inner = self.inner.write().expect("Lock should not be poisoned");
        inner.events.push(event.clone());
        Ok(())
    }

    fn load(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::InternalStorageError> {
        let inner = self.inner.read().expect("Lock should not be poisoned");
        let events = inner.events.clone();
        Ok(Box::new(events.into_iter()))
    }

    fn close(&self) -> Result<(), Self::InternalStorageError> {
        let mut inner = self.inner.write().expect("Lock should not be poisoned");
        inner.is_closed = true;
        Ok(())
    }
}

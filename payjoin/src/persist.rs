use crate::receive::v2::ReceiverSessionEvent;
use crate::send::v2::SenderSessionEvent;

impl Event for ReceiverSessionEvent {
    fn session_invalid(error: &impl PersistableError) -> Self {
        ReceiverSessionEvent::SessionInvalid(error.to_string())
    }
}
impl Event for SenderSessionEvent {
    fn session_invalid(error: &impl PersistableError) -> Self {
        SenderSessionEvent::SessionInvalid(error.to_string())
    }
}

/// Types that can be persisted in a session
pub trait Event: serde::Serialize + serde::de::DeserializeOwned + Sized + Clone {
    fn session_invalid(error: &impl PersistableError) -> Self;
}

/// Serializable error types that can be persisted in a session
/// TODO: see if this can be a ext. trait with a blanket impl for all error types
pub trait PersistableError: std::error::Error + ToString {}

/// A session that can be persisted and loaded from a store
///
/// This is a generic trait that can be implemented for any type that implements `Event`.
///
///
pub trait PersistedSession {
    type Error: std::error::Error + Send + Sync + 'static;
    type SessionEvent: Event;

    fn save(&self, event: Self::SessionEvent) -> Result<(), Self::Error>; // Appends to list of session updates, Receives generic events
    fn record_error(&self, error: &impl PersistableError) -> Result<(), Self::Error> {
        self.save(Self::SessionEvent::session_invalid(error))?;
        self.close()
    }
    fn load(&self) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::Error>; // Loads the latest session given all updates
                                                                                         // TODO: this should consume self
    fn close(&self) -> Result<(), Self::Error>; // Marks the session as closed, no more updates will be appended
}

/// A persister that does nothing
/// This persister cannot be used to replay a session
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NoopPersisterEvent;

impl Event for NoopPersisterEvent {
    fn session_invalid(_error: &impl PersistableError) -> Self { NoopPersisterEvent }
}

impl From<ReceiverSessionEvent> for NoopPersisterEvent {
    fn from(_event: ReceiverSessionEvent) -> Self { NoopPersisterEvent }
}

impl From<SenderSessionEvent> for NoopPersisterEvent {
    fn from(_event: SenderSessionEvent) -> Self { NoopPersisterEvent }
}

#[derive(Debug, Clone)]
pub struct NoopPersister;

impl PersistedSession for NoopPersister {
    type Error = std::io::Error;
    type SessionEvent = NoopPersisterEvent;

    fn save(&self, _event: Self::SessionEvent) -> Result<(), Self::Error> { Ok(()) }

    fn load(&self) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::Error> {
        Ok(Box::new(std::iter::empty()))
    }

    fn close(&self) -> Result<(), Self::Error> { Ok(()) }
}

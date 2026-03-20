use std::fmt::Debug;
use std::{error, fmt};

#[derive(Debug)]
pub struct ImplementationError(Box<dyn error::Error + Send + Sync>);

impl ImplementationError {
    pub fn new(e: impl error::Error + Send + Sync + 'static) -> Self {
        ImplementationError(Box::new(e))
    }
}

impl fmt::Display for ImplementationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { std::fmt::Display::fmt(&self.0, f) }
}

impl error::Error for ImplementationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> { Some(self.0.as_ref()) }
}

impl PartialEq for ImplementationError {
    fn eq(&self, _: &Self) -> bool { false }
}

impl Eq for ImplementationError {}

impl From<Box<dyn error::Error + Send + Sync>> for ImplementationError {
    fn from(e: Box<dyn error::Error + Send + Sync>) -> Self { ImplementationError(e) }
}

impl From<&str> for ImplementationError {
    fn from(e: &str) -> Self {
        let error = Box::<dyn error::Error + Send + Sync>::from(e);
        ImplementationError::from(error)
    }
}
/// Errors that can occur when replaying a session event log
#[cfg(feature = "v2")]
#[derive(Debug)]
pub struct ReplayError<SessionState, SessionEvent>(InternalReplayError<SessionState, SessionEvent>);

/// High-level replay error classification for recovered session event logs.
#[cfg(feature = "v2")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayErrorKind {
    NoEvents,
    InvalidEvent,
    Expired,
    PersistenceFailure,
}

/// Stable public decomposition of replay failures that does not expose session internals.
#[cfg(feature = "v2")]
#[derive(Debug)]
pub enum ReplayErrorVariant {
    NoEvents,
    InvalidFirstEvent,
    InvalidEventForState,
    Expired { expired_at_unix_seconds: u32 },
    PersistenceFailure(ImplementationError),
}

#[cfg(feature = "v2")]
impl<SessionState: Debug, SessionEvent: Debug> std::fmt::Display
    for ReplayError<SessionState, SessionEvent>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use InternalReplayError::*;
        match &self.0 {
            NoEvents => write!(f, "No events found in session"),
            InvalidEvent(event, session) => match session {
                Some(session) => write!(f, "Invalid event ({event:?}) for session ({session:?})",),
                None => write!(f, "Invalid first event ({event:?}) for session",),
            },
            Expired(time) => write!(f, "Session expired at {time:?}"),
            PersistenceFailure(e) => write!(f, "Persistence failure: {e}"),
        }
    }
}
#[cfg(feature = "v2")]
impl<SessionState: Debug, SessionEvent: Debug> std::error::Error
    for ReplayError<SessionState, SessionEvent>
{
}

#[cfg(feature = "v2")]
impl<SessionState: Debug, SessionEvent: Debug> From<InternalReplayError<SessionState, SessionEvent>>
    for ReplayError<SessionState, SessionEvent>
{
    fn from(e: InternalReplayError<SessionState, SessionEvent>) -> Self { ReplayError(e) }
}

#[cfg(feature = "v2")]
impl<SessionState: Debug, SessionEvent: Debug> ReplayError<SessionState, SessionEvent> {
    pub fn kind(&self) -> ReplayErrorKind {
        match &self.0 {
            InternalReplayError::NoEvents => ReplayErrorKind::NoEvents,
            InternalReplayError::InvalidEvent(_, _) => ReplayErrorKind::InvalidEvent,
            InternalReplayError::Expired(_) => ReplayErrorKind::Expired,
            InternalReplayError::PersistenceFailure(_) => ReplayErrorKind::PersistenceFailure,
        }
    }

    pub fn into_variant(self) -> ReplayErrorVariant {
        match self.0 {
            InternalReplayError::NoEvents => ReplayErrorVariant::NoEvents,
            InternalReplayError::InvalidEvent(_, None) => ReplayErrorVariant::InvalidFirstEvent,
            InternalReplayError::InvalidEvent(_, Some(_)) =>
                ReplayErrorVariant::InvalidEventForState,
            InternalReplayError::Expired(time) =>
                ReplayErrorVariant::Expired { expired_at_unix_seconds: time.to_unix_seconds() },
            InternalReplayError::PersistenceFailure(error) =>
                ReplayErrorVariant::PersistenceFailure(error),
        }
    }
}

#[cfg(feature = "v2")]
#[derive(Debug)]
pub(crate) enum InternalReplayError<SessionState, SessionEvent> {
    /// No events in the event log
    NoEvents,
    /// Invalid initial event
    InvalidEvent(Box<SessionEvent>, Option<Box<SessionState>>),
    /// Session is expired
    Expired(crate::time::Time),
    /// Application storage error
    PersistenceFailure(ImplementationError),
}

#[cfg(all(test, feature = "v2"))]
mod tests {
    use super::{
        ImplementationError, InternalReplayError, ReplayError, ReplayErrorKind, ReplayErrorVariant,
    };
    use crate::time::Time;

    #[derive(Debug)]
    struct DummyState;

    #[derive(Debug)]
    struct DummyEvent;

    #[test]
    fn test_replay_error_kind_and_variant() {
        let no_events = ReplayError::<DummyState, DummyEvent>::from(InternalReplayError::NoEvents);
        assert_eq!(no_events.kind(), ReplayErrorKind::NoEvents);
        assert!(matches!(no_events.into_variant(), ReplayErrorVariant::NoEvents));

        let invalid_first_event = ReplayError::<DummyState, DummyEvent>::from(
            InternalReplayError::InvalidEvent(Box::new(DummyEvent), None),
        );
        assert_eq!(invalid_first_event.kind(), ReplayErrorKind::InvalidEvent);
        assert!(matches!(
            invalid_first_event.into_variant(),
            ReplayErrorVariant::InvalidFirstEvent
        ));

        let invalid_event_for_state = ReplayError::<DummyState, DummyEvent>::from(
            InternalReplayError::InvalidEvent(Box::new(DummyEvent), Some(Box::new(DummyState))),
        );
        assert_eq!(invalid_event_for_state.kind(), ReplayErrorKind::InvalidEvent);
        assert!(matches!(
            invalid_event_for_state.into_variant(),
            ReplayErrorVariant::InvalidEventForState
        ));

        let expired_time = Time::from_unix_seconds(1_700_000_000).expect("valid time");
        let expired =
            ReplayError::<DummyState, DummyEvent>::from(InternalReplayError::Expired(expired_time));
        assert_eq!(expired.kind(), ReplayErrorKind::Expired);
        assert!(matches!(
            expired.into_variant(),
            ReplayErrorVariant::Expired { expired_at_unix_seconds: 1_700_000_000 }
        ));

        let persistence_failure = ReplayError::<DummyState, DummyEvent>::from(
            InternalReplayError::PersistenceFailure(ImplementationError::from("storage failed")),
        );
        assert_eq!(persistence_failure.kind(), ReplayErrorKind::PersistenceFailure);
        assert!(matches!(
            persistence_failure.into_variant(),
            ReplayErrorVariant::PersistenceFailure(_)
        ));
    }
}

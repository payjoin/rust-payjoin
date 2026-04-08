#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use core::error;
use core::fmt::{self, Debug};
#[cfg(feature = "std")]
use std::error;

#[derive(Debug)]
pub struct StdRequiredError;

impl fmt::Display for StdRequiredError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "std is required for this operation")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for StdRequiredError {}

#[cfg(not(feature = "std"))]
impl core::error::Error for StdRequiredError {}

impl ImplementationError {
    pub fn std_required() -> Self { ImplementationError(Box::new(StdRequiredError)) }
}
#[derive(Debug)]
pub struct ImplementationError(Box<dyn error::Error + Send + Sync>);

impl ImplementationError {
    pub fn new(e: impl error::Error + Send + Sync + 'static) -> Self {
        ImplementationError(Box::new(e))
    }
}

impl fmt::Display for ImplementationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
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

#[cfg(feature = "v2")]
impl<SessionState: Debug, SessionEvent: Debug> fmt::Display
    for ReplayError<SessionState, SessionEvent>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
impl<SessionState: Debug, SessionEvent: Debug> error::Error
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
#[derive(Debug)]
#[allow(dead_code)]
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

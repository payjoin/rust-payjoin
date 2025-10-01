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
pub struct ReplayError<SessionState, SessionEvent, SessionHistory>(
    pub(crate) InternalReplayError<SessionState, SessionEvent, SessionHistory>,
);

#[cfg(feature = "v2")]
impl<SessionState: Debug, SessionEvent: Debug, SessionHistory: Debug>
    ReplayError<SessionState, SessionEvent, SessionHistory>
{
    pub fn session_history(&self) -> Option<&SessionHistory> {
        match &self.0 {
            InternalReplayError::TerminalFailure(history)
            | InternalReplayError::Expired(_, history) => Some(history),
            _ => None,
        }
    }
}

#[cfg(feature = "v2")]
impl<SessionState: Debug, SessionEvent: Debug, SessionHistory: Debug> std::fmt::Display
    for ReplayError<SessionState, SessionEvent, SessionHistory>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use InternalReplayError::*;
        match &self.0 {
            NoEvents => write!(f, "No events found in session"),
            InvalidEvent(event, session) => match session {
                Some(session) => write!(f, "Invalid event ({event:?}) for session ({session:?})",),
                None => write!(f, "Invalid first event ({event:?}) for session",),
            },
            Expired(time, _) => write!(f, "Session expired at {time:?}"),
            PersistenceFailure(e) => write!(f, "Persistence failure: {e}"),
            ProtocolError() => write!(f, "Protocol error"),
            TerminalFailure(_) => write!(f, "Terminal failure"),
        }
    }
}
#[cfg(feature = "v2")]
impl<SessionState: Debug, SessionEvent: Debug, SessionHistory: Debug> std::error::Error
    for ReplayError<SessionState, SessionEvent, SessionHistory>
{
}

#[cfg(feature = "v2")]
impl<SessionState: Debug, SessionEvent: Debug, SessionHistory: Debug>
    From<InternalReplayError<SessionState, SessionEvent, SessionHistory>>
    for ReplayError<SessionState, SessionEvent, SessionHistory>
{
    fn from(e: InternalReplayError<SessionState, SessionEvent, SessionHistory>) -> Self {
        ReplayError(e)
    }
}

#[cfg(feature = "v2")]
#[derive(Debug)]
pub(crate) enum InternalReplayError<SessionState, SessionEvent, SessionHistory> {
    /// No events in the event log
    NoEvents,
    /// Invalid initial event
    InvalidEvent(Box<SessionEvent>, Option<Box<SessionState>>),
    /// Session is expired
    Expired(crate::time::Time, SessionHistory),
    /// Application storage error
    PersistenceFailure(ImplementationError),
    /// Protocol error
    // TODO: should this include a deserialize / string representation of the error?
    ProtocolError(),
    /// Terminal failure with session history
    TerminalFailure(SessionHistory),
}

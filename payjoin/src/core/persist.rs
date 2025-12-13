use std::fmt;
/// Handles cases where the transition either succeeds with a final result that ends the session, or hits a static condition and stays in the same state.
/// State transition may also be a fatal error or transient error.
pub struct MaybeSuccessTransitionWithNoResults<Event, SuccessValue, CurrentState, Err>(
    Result<AcceptOptionalTransition<Event, SuccessValue, CurrentState>, Rejection<Event, Err>>,
);

impl<Event, SuccessValue, CurrentState, Err>
    MaybeSuccessTransitionWithNoResults<Event, SuccessValue, CurrentState, Err>
{
    pub(crate) fn fatal(event: Event, error: Err) -> Self {
        MaybeSuccessTransitionWithNoResults(Err(Rejection::fatal(event, error)))
    }

    pub(crate) fn transient(error: Err) -> Self {
        MaybeSuccessTransitionWithNoResults(Err(Rejection::transient(error)))
    }

    pub(crate) fn no_results(current_state: CurrentState) -> Self {
        MaybeSuccessTransitionWithNoResults(Ok(AcceptOptionalTransition::NoResults(current_state)))
    }

    pub(crate) fn success(success_value: SuccessValue, event: Event) -> Self {
        MaybeSuccessTransitionWithNoResults(Ok(AcceptOptionalTransition::Success(AcceptNextState(
            event,
            success_value,
        ))))
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<
        OptionalTransitionOutcome<SuccessValue, CurrentState>,
        PersistedError<Err, P::InternalStorageError>,
    >
    where
        P: SessionPersister<SessionEvent = Event>,
        Err: std::error::Error,
    {
        persister.save_maybe_no_results_success_transition(self)
    }
}
/// A transition that can result in a state transition, fatal error, or successfully have no results.
pub struct MaybeFatalTransitionWithNoResults<Event, NextState, CurrentState, Err>(
    Result<AcceptOptionalTransition<Event, NextState, CurrentState>, Rejection<Event, Err>>,
);

impl<Event, NextState, CurrentState, Err>
    MaybeFatalTransitionWithNoResults<Event, NextState, CurrentState, Err>
{
    pub(crate) fn fatal(event: Event, error: Err) -> Self {
        MaybeFatalTransitionWithNoResults(Err(Rejection::fatal(event, error)))
    }

    pub(crate) fn no_results(current_state: CurrentState) -> Self {
        MaybeFatalTransitionWithNoResults(Ok(AcceptOptionalTransition::NoResults(current_state)))
    }

    pub(crate) fn transient(error: Err) -> Self {
        MaybeFatalTransitionWithNoResults(Err(Rejection::transient(error)))
    }

    pub(crate) fn success(event: Event, next_state: NextState) -> Self {
        MaybeFatalTransitionWithNoResults(Ok(AcceptOptionalTransition::Success(AcceptNextState(
            event, next_state,
        ))))
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<
        OptionalTransitionOutcome<NextState, CurrentState>,
        PersistedError<Err, P::InternalStorageError>,
    >
    where
        P: SessionPersister<SessionEvent = Event>,
        Err: std::error::Error,
    {
        persister.save_maybe_no_results_transition(self)
    }
}

/// A transition that can be either fatal, transient, or a state transition.
pub struct MaybeFatalTransition<Event, NextState, Err, ErrorState = ()>(
    pub(crate) Result<AcceptNextState<Event, NextState>, Rejection<Event, Err, ErrorState>>,
);

impl<Event, NextState, Err, ErrorState> MaybeFatalTransition<Event, NextState, Err, ErrorState>
where
    ErrorState: fmt::Debug,
{
    pub(crate) fn fatal(event: Event, error: Err) -> Self {
        MaybeFatalTransition(Err(Rejection::fatal(event, error)))
    }

    pub(crate) fn transient(error: Err) -> Self {
        MaybeFatalTransition(Err(Rejection::transient(error)))
    }

    pub(crate) fn success(event: Event, next_state: NextState) -> Self {
        MaybeFatalTransition(Ok(AcceptNextState(event, next_state)))
    }

    pub(crate) fn replyable_error(event: Event, error_state: ErrorState, error: Err) -> Self {
        MaybeFatalTransition(Err(Rejection::replyable_error(event, error_state, error)))
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<NextState, PersistedError<Err, P::InternalStorageError, ErrorState>>
    where
        P: SessionPersister<SessionEvent = Event>,
        Err: std::error::Error,
    {
        persister.save_maybe_fatal_error_transition(self)
    }
}

/// A transition that can result in a state transition or a transient error.
/// Fatal errors cannot occur in this transition.
pub struct MaybeTransientTransition<Event, NextState, Err>(
    Result<AcceptNextState<Event, NextState>, RejectTransient<Err>>,
);

impl<Event, NextState, Err> MaybeTransientTransition<Event, NextState, Err> {
    pub(crate) fn success(event: Event, next_state: NextState) -> Self {
        MaybeTransientTransition(Ok(AcceptNextState(event, next_state)))
    }

    pub(crate) fn transient(error: Err) -> Self {
        MaybeTransientTransition(Err(RejectTransient(error)))
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<NextState, PersistedError<Err, P::InternalStorageError>>
    where
        P: SessionPersister<SessionEvent = Event>,
        Err: std::error::Error,
    {
        persister.save_maybe_transient_error_transition(self)
    }
}

/// A transition that can result in the completion of a state machine or a transient error
/// Fatal errors cannot occur in this transition.
pub struct MaybeSuccessTransition<Event, SuccessValue, Err>(
    Result<AcceptNextState<Event, SuccessValue>, Rejection<Event, Err>>,
);

impl<Event, SuccessValue, Err> MaybeSuccessTransition<Event, SuccessValue, Err>
where
    Err: std::error::Error,
{
    pub(crate) fn success(event: Event, success_value: SuccessValue) -> Self {
        MaybeSuccessTransition(Ok(AcceptNextState(event, success_value)))
    }

    pub(crate) fn transient(error: Err) -> Self {
        MaybeSuccessTransition(Err(Rejection::transient(error)))
    }

    pub(crate) fn fatal(event: Event, error: Err) -> Self {
        MaybeSuccessTransition(Err(Rejection::fatal(event, error)))
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<SuccessValue, PersistedError<Err, P::InternalStorageError>>
    where
        P: SessionPersister<SessionEvent = Event>,
    {
        persister.save_maybe_success_transition(self)
    }
}

/// A transition that always results in a state transition.
pub struct NextStateTransition<Event, NextState>(AcceptNextState<Event, NextState>);

impl<Event, NextState> NextStateTransition<Event, NextState> {
    pub(crate) fn success(event: Event, next_state: NextState) -> Self {
        NextStateTransition(AcceptNextState(event, next_state))
    }

    pub fn save<P>(self, persister: &P) -> Result<NextState, P::InternalStorageError>
    where
        P: SessionPersister<SessionEvent = Event>,
    {
        persister.save_progression_transition(self)
    }
}

/// A transition that can result in a succession completion, fatal error, or transient error.
/// The transition can also result in no state change.
pub enum MaybeFatalOrSuccessTransition<Event, CurrentState, Err> {
    Success(Event),
    NoResults(CurrentState),
    Transient(RejectTransient<Err>),
    Fatal(RejectFatal<Event, Err>),
}

impl<Event, CurrentState, Err> MaybeFatalOrSuccessTransition<Event, CurrentState, Err>
where
    Err: std::error::Error,
{
    pub(crate) fn success(event: Event) -> Self { MaybeFatalOrSuccessTransition::Success(event) }

    #[cfg(test)]
    pub(crate) fn fatal(event: Event, error: Err) -> Self {
        MaybeFatalOrSuccessTransition::Fatal(RejectFatal(event, error))
    }

    pub(crate) fn transient(error: Err) -> Self {
        MaybeFatalOrSuccessTransition::Transient(RejectTransient(error))
    }

    pub(crate) fn no_results(current_state: CurrentState) -> Self {
        MaybeFatalOrSuccessTransition::NoResults(current_state)
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<
        OptionalTransitionOutcome<(), CurrentState>,
        PersistedError<Err, P::InternalStorageError>,
    >
    where
        P: SessionPersister<SessionEvent = Event>,
        Err: std::error::Error,
    {
        persister.save_maybe_fatal_or_success_transition(self)
    }
}

/// Wrapper that marks the progression of a state machine
pub struct AcceptNextState<Event, NextState>(Event, NextState);

/// Wrapper that represents either a successful state transition or indicates no state change occurred
pub enum AcceptOptionalTransition<Event, NextState, CurrentState> {
    /// A state transition that was successful and returned session event to be persisted
    Success(AcceptNextState<Event, NextState>),
    /// A state transition returned no value. Caller should resume from the current state
    NoResults(CurrentState),
}

/// Wrapper representing a fatal or transient rejection of a state transition.
pub enum Rejection<Event, Err, ErrorState = ()> {
    Fatal(RejectFatal<Event, Err>),
    Transient(RejectTransient<Err>),
    ReplyableError(RejectReplyableError<Event, ErrorState, Err>),
}

impl<Event, Err, ErrorState> Rejection<Event, Err, ErrorState> {
    pub fn fatal(event: Event, error: Err) -> Self { Rejection::Fatal(RejectFatal(event, error)) }
    pub fn transient(error: Err) -> Self { Rejection::Transient(RejectTransient(error)) }
    pub fn replyable_error(event: Event, error_state: ErrorState, error: Err) -> Self {
        Rejection::ReplyableError(RejectReplyableError(event, error_state, error))
    }
}

/// Represents a fatal rejection of a state transition.
/// When this error occurs, the session must be closed and cannot be resumed.
pub struct RejectFatal<Event, Err>(pub(crate) Event, pub(crate) Err);
/// Represents a transient rejection of a state transition.
/// When this error occurs, the session should resume from its current state.
pub struct RejectTransient<Err>(pub(crate) Err);
/// Represents a replyable error that transitions to an error state but keeps the session open.
/// When this error occurs, the session transitions to the ErrorState.
pub struct RejectReplyableError<Event, ErrorState, Err>(
    pub(crate) Event,
    pub(crate) ErrorState,
    pub(crate) Err,
);
/// Represents a bad initial inputs to the state machine.
/// When this error occurs, the session cannot be created.
/// The wrapper contains the error and should be returned to the caller.
pub struct RejectBadInitInputs<Err>(Err);

impl<Err: std::error::Error> fmt::Display for RejectTransient<Err> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let RejectTransient(err) = self;
        write!(f, "{err}")
    }
}

/// Error type that represents all possible errors that can be returned when processing a state transition
#[derive(Debug)]
pub struct PersistedError<
    ApiError: std::error::Error,
    StorageError: std::error::Error,
    ErrorState: fmt::Debug = (),
>(InternalPersistedError<ApiError, StorageError, ErrorState>);

impl<ApiErr, StorageErr, ErrorState> PersistedError<ApiErr, StorageErr, ErrorState>
where
    StorageErr: std::error::Error,
    ApiErr: std::error::Error,
    ErrorState: fmt::Debug,
{
    #[allow(dead_code)]
    pub fn storage_error(self) -> Option<StorageErr> {
        match self.0 {
            InternalPersistedError::Storage(e) => Some(e),
            _ => None,
        }
    }

    pub fn api_error(self) -> Option<ApiErr> {
        match self.0 {
            InternalPersistedError::Fatal(e)
            | InternalPersistedError::Transient(e)
            | InternalPersistedError::FatalWithState(e, _) => Some(e),
            _ => None,
        }
    }

    pub fn storage_error_ref(&self) -> Option<&StorageErr> {
        match &self.0 {
            InternalPersistedError::Storage(e) => Some(e),
            _ => None,
        }
    }

    pub fn api_error_ref(&self) -> Option<&ApiErr> {
        match &self.0 {
            InternalPersistedError::Fatal(e)
            | InternalPersistedError::Transient(e)
            | InternalPersistedError::FatalWithState(e, _) => Some(e),
            _ => None,
        }
    }

    pub fn error_state(self) -> Option<ErrorState> {
        match self.0 {
            InternalPersistedError::FatalWithState(_, state) => Some(state),
            _ => None,
        }
    }
}

impl<ApiError: std::error::Error, StorageError: std::error::Error, ErrorState: fmt::Debug>
    From<InternalPersistedError<ApiError, StorageError, ErrorState>>
    for PersistedError<ApiError, StorageError, ErrorState>
{
    fn from(value: InternalPersistedError<ApiError, StorageError, ErrorState>) -> Self {
        PersistedError(value)
    }
}

impl<ApiError: std::error::Error, StorageError: std::error::Error, ErrorState: fmt::Debug>
    std::error::Error for PersistedError<ApiError, StorageError, ErrorState>
{
}

impl<ApiError: std::error::Error, StorageError: std::error::Error, ErrorState: fmt::Debug>
    fmt::Display for PersistedError<ApiError, StorageError, ErrorState>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            InternalPersistedError::Transient(err) => write!(f, "Transient error: {err}"),
            InternalPersistedError::Fatal(err) | InternalPersistedError::FatalWithState(err, _) =>
                write!(f, "Fatal error: {err}"),
            InternalPersistedError::Storage(err) => write!(f, "Storage error: {err}"),
        }
    }
}

#[derive(Debug)]
pub(crate) enum InternalPersistedError<InternalApiError, StorageErr, ErrorState = ()>
where
    InternalApiError: std::error::Error,
    StorageErr: std::error::Error,
    ErrorState: fmt::Debug,
{
    /// Error indicating that the session should be retried from the same state
    Transient(InternalApiError),
    /// Error indicating that the session is terminally closed
    Fatal(InternalApiError),
    /// Fatal error that results in a state transition to ErrorState
    FatalWithState(InternalApiError, ErrorState),
    /// Error indicating that application failed to save the session event. This should be treated as a transient error
    /// but is represented as a separate error because this error is propagated from the application's storage layer
    Storage(StorageErr),
}

/// Represents a state transition that either progresses to a new state or maintains the current state
#[derive(Debug, PartialEq)]
pub enum OptionalTransitionOutcome<NextState, CurrentState> {
    /// A successful state transition that returned a next state
    Progress(NextState),
    /// A state transition returned no value. Caller should resume from the current state
    Stasis(CurrentState),
}

/// A session that can persist events to an append-only log.
/// A session represents a sequence of events generated by the BIP78 state machine.
/// The events can be replayed from the log to reconstruct the state machine's state.
pub trait SessionPersister {
    /// Errors that may arise from implementers storage layer
    type InternalStorageError: std::error::Error + Send + Sync + 'static;
    /// Session events types that we are persisting
    type SessionEvent;

    /// Appends to list of session updates, Receives generic events
    fn save_event(&self, event: Self::SessionEvent) -> Result<(), Self::InternalStorageError>;

    /// Loads all the events from the session in the same order they were saved
    fn load(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::InternalStorageError>;

    /// Marks the session as closed, no more events will be appended.
    /// This is invoked when the session is terminated due to a fatal error
    /// or when the session is closed due to a success state
    fn close(&self) -> Result<(), Self::InternalStorageError>;
}

/// Internal logic for processing specific state transitions. Each method is strongly typed to the state transition type.
/// Methods are not meant to be called directly, but are invoked through a state transition object's `save` method.
trait InternalSessionPersister: SessionPersister {
    fn save_maybe_fatal_or_success_transition<CurrentState, Err>(
        &self,
        state_transition: MaybeFatalOrSuccessTransition<Self::SessionEvent, CurrentState, Err>,
    ) -> Result<
        OptionalTransitionOutcome<(), CurrentState>,
        PersistedError<Err, Self::InternalStorageError>,
    >
    where
        Err: std::error::Error,
    {
        match state_transition {
            MaybeFatalOrSuccessTransition::Success(event) => {
                // Success value here would be the something to save
                self.save_event(event).map_err(InternalPersistedError::Storage)?;
                self.close().map_err(InternalPersistedError::Storage)?;
                Ok(OptionalTransitionOutcome::Progress(()))
            }
            MaybeFatalOrSuccessTransition::NoResults(current_state) =>
                Ok(OptionalTransitionOutcome::Stasis(current_state)),
            MaybeFatalOrSuccessTransition::Fatal(reject_fatal) =>
                Err(self.handle_fatal_reject(reject_fatal).into()),
            MaybeFatalOrSuccessTransition::Transient(RejectTransient(err)) =>
                Err(InternalPersistedError::Transient(err).into()),
        }
    }

    /// Save state transition where state transition does not return an error
    /// Only returns an error if the storage fails
    fn save_progression_transition<NextState>(
        &self,
        state_transition: NextStateTransition<Self::SessionEvent, NextState>,
    ) -> Result<NextState, Self::InternalStorageError> {
        self.save_event(state_transition.0 .0)?;
        Ok(state_transition.0 .1)
    }

    /// Save a transition that can be a state transition or a transient error
    fn save_maybe_success_transition<SuccessValue, Err>(
        &self,
        state_transition: MaybeSuccessTransition<Self::SessionEvent, SuccessValue, Err>,
    ) -> Result<SuccessValue, PersistedError<Err, Self::InternalStorageError>>
    where
        Err: std::error::Error,
    {
        match state_transition.0 {
            Ok(AcceptNextState(event, success_value)) => {
                self.save_event(event).map_err(InternalPersistedError::Storage)?;
                self.close().map_err(InternalPersistedError::Storage)?;
                Ok(success_value)
            }
            Err(Rejection::Transient(RejectTransient(err))) =>
                Err(InternalPersistedError::Transient(err).into()),
            Err(Rejection::Fatal(reject_fatal)) =>
                Err(self.handle_fatal_reject(reject_fatal).into()),
            Err(Rejection::ReplyableError(reject_replyable_error)) =>
                Err(self.handle_replyable_error_reject(reject_replyable_error).into()),
        }
    }

    /// Persists the outcome of a state transition that may result in one of the following:
    /// - A successful state transition, in which case the success value is returned and the session is closed.
    /// - No state change (stasis), where the current state is retained and nothing is persisted.
    /// - A transient error, which does not affect persistent storage and is returned to the caller.
    /// - A fatal error, which is persisted and returned to the caller.
    fn save_maybe_no_results_success_transition<SuccessValue, CurrentState, Err>(
        &self,
        state_transition: MaybeSuccessTransitionWithNoResults<
            Self::SessionEvent,
            SuccessValue,
            CurrentState,
            Err,
        >,
    ) -> Result<
        OptionalTransitionOutcome<SuccessValue, CurrentState>,
        PersistedError<Err, Self::InternalStorageError>,
    >
    where
        Err: std::error::Error,
    {
        match state_transition.0 {
            Ok(AcceptOptionalTransition::Success(AcceptNextState(event, success_value))) => {
                self.save_event(event).map_err(InternalPersistedError::Storage)?;
                self.close().map_err(InternalPersistedError::Storage)?;
                Ok(OptionalTransitionOutcome::Progress(success_value))
            }
            Ok(AcceptOptionalTransition::NoResults(current_state)) =>
                Ok(OptionalTransitionOutcome::Stasis(current_state)),
            Err(Rejection::Fatal(reject_fatal)) =>
                Err(self.handle_fatal_reject(reject_fatal).into()),
            Err(Rejection::Transient(RejectTransient(err))) =>
                Err(InternalPersistedError::Transient(err).into()),
            Err(Rejection::ReplyableError(reject_replyable_error)) =>
                Err(self.handle_replyable_error_reject(reject_replyable_error).into()),
        }
    }
    /// Save a transition that can result in:
    /// - A successful state transition
    /// - No state change (no results)
    /// - A transient error
    /// - A fatal error
    fn save_maybe_no_results_transition<NextState, CurrentState, Err>(
        &self,
        state_transition: MaybeFatalTransitionWithNoResults<
            Self::SessionEvent,
            NextState,
            CurrentState,
            Err,
        >,
    ) -> Result<
        OptionalTransitionOutcome<NextState, CurrentState>,
        PersistedError<Err, Self::InternalStorageError>,
    >
    where
        Err: std::error::Error,
    {
        match state_transition.0 {
            Ok(AcceptOptionalTransition::Success(AcceptNextState(event, next_state))) => {
                self.save_event(event).map_err(InternalPersistedError::Storage)?;
                Ok(OptionalTransitionOutcome::Progress(next_state))
            }
            Ok(AcceptOptionalTransition::NoResults(current_state)) =>
                Ok(OptionalTransitionOutcome::Stasis(current_state)),
            Err(Rejection::Fatal(reject_fatal)) =>
                Err(self.handle_fatal_reject(reject_fatal).into()),
            Err(Rejection::Transient(RejectTransient(err))) =>
                Err(InternalPersistedError::Transient(err).into()),
            Err(Rejection::ReplyableError(reject_replyable_error)) =>
                Err(self.handle_replyable_error_reject(reject_replyable_error).into()),
        }
    }

    /// Save a transition that can be a transient error or a state transition
    fn save_maybe_transient_error_transition<NextState, Err>(
        &self,
        state_transition: MaybeTransientTransition<Self::SessionEvent, NextState, Err>,
    ) -> Result<NextState, PersistedError<Err, Self::InternalStorageError>>
    where
        Err: std::error::Error,
    {
        match state_transition.0 {
            Ok(AcceptNextState(event, next_state)) => {
                self.save_event(event).map_err(InternalPersistedError::Storage)?;
                Ok(next_state)
            }
            Err(RejectTransient(err)) => Err(InternalPersistedError::Transient(err).into()),
        }
    }

    /// Save a transition that can be a fatal error, transient error or a state transition
    fn save_maybe_fatal_error_transition<NextState, Err, ErrorState>(
        &self,
        state_transition: MaybeFatalTransition<Self::SessionEvent, NextState, Err, ErrorState>,
    ) -> Result<NextState, PersistedError<Err, Self::InternalStorageError, ErrorState>>
    where
        Err: std::error::Error,
        ErrorState: fmt::Debug,
    {
        match state_transition.0 {
            Ok(AcceptNextState(event, next_state)) => {
                self.save_event(event).map_err(InternalPersistedError::Storage)?;
                Ok(next_state)
            }
            Err(e) => {
                match e {
                    Rejection::Fatal(reject_fatal) =>
                        Err(self.handle_fatal_reject(reject_fatal).into()),
                    Rejection::Transient(RejectTransient(err)) => {
                        // No event to store for transient errors
                        Err(InternalPersistedError::Transient(err).into())
                    }
                    Rejection::ReplyableError(reject_replyable_error) =>
                        Err(self.handle_replyable_error_reject(reject_replyable_error).into()),
                }
            }
        }
    }

    fn handle_fatal_reject<Err, ErrorState>(
        &self,
        reject_fatal: RejectFatal<Self::SessionEvent, Err>,
    ) -> InternalPersistedError<Err, Self::InternalStorageError, ErrorState>
    where
        Err: std::error::Error,
        ErrorState: fmt::Debug,
    {
        let RejectFatal(event, error) = reject_fatal;
        if let Err(e) = self.save_event(event) {
            return InternalPersistedError::Storage(e);
        }
        // Session is in a terminal state, close it
        if let Err(e) = self.close() {
            return InternalPersistedError::Storage(e);
        }

        InternalPersistedError::Fatal(error)
    }

    fn handle_replyable_error_reject<Err, ErrorState>(
        &self,
        reject_replyable_error: RejectReplyableError<Self::SessionEvent, ErrorState, Err>,
    ) -> InternalPersistedError<Err, Self::InternalStorageError, ErrorState>
    where
        Err: std::error::Error,
        ErrorState: fmt::Debug,
    {
        let RejectReplyableError(event, error_state, error) = reject_replyable_error;
        if let Err(e) = self.save_event(event) {
            return InternalPersistedError::Storage(e);
        }
        // For replyable errors, don't close the session - keep it open for error response
        InternalPersistedError::FatalWithState(error, error_state)
    }
}

impl<T: SessionPersister> InternalSessionPersister for T {}

/// A persister that does nothing
/// This persister cannot be used to replay a session
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NoopPersisterEvent;

#[derive(Debug, Clone)]
pub struct NoopSessionPersister<E = NoopPersisterEvent>(std::marker::PhantomData<E>);

impl<E> Default for NoopSessionPersister<E> {
    fn default() -> Self { Self(std::marker::PhantomData) }
}

impl<E: 'static> SessionPersister for NoopSessionPersister<E> {
    type InternalStorageError = std::convert::Infallible;
    type SessionEvent = E;

    fn save_event(&self, _event: Self::SessionEvent) -> Result<(), Self::InternalStorageError> {
        Ok(())
    }

    fn load(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::InternalStorageError> {
        Ok(Box::new(std::iter::empty()))
    }

    fn close(&self) -> Result<(), Self::InternalStorageError> { Ok(()) }
}

#[cfg(feature = "_test-utils")]
pub mod test_utils {
    use std::sync::{Arc, RwLock};

    use crate::persist::SessionPersister;

    #[derive(Clone)]
    /// In-memory session persister for testing session replays and introspecting session events
    pub struct InMemoryTestPersister<V> {
        pub(crate) inner: Arc<RwLock<InnerStorage<V>>>,
    }

    impl<V> Default for InMemoryTestPersister<V> {
        fn default() -> Self { Self { inner: Arc::new(RwLock::new(InnerStorage::default())) } }
    }

    #[derive(Clone)]
    pub(crate) struct InnerStorage<V> {
        pub(crate) events: std::sync::Arc<Vec<V>>,
        pub(crate) is_closed: bool,
    }

    impl<V> Default for InnerStorage<V> {
        fn default() -> Self { Self { events: std::sync::Arc::new(vec![]), is_closed: false } }
    }

    impl<V> SessionPersister for InMemoryTestPersister<V>
    where
        V: Clone + 'static,
    {
        type InternalStorageError = std::convert::Infallible;
        type SessionEvent = V;

        fn save_event(&self, event: Self::SessionEvent) -> Result<(), Self::InternalStorageError> {
            let mut inner = self.inner.write().expect("Lock should not be poisoned");
            std::sync::Arc::make_mut(&mut inner.events).push(event);
            Ok(())
        }

        fn load(
            &self,
        ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::InternalStorageError>
        {
            let inner = self.inner.read().expect("Lock should not be poisoned");
            let events = std::sync::Arc::clone(&inner.events);
            Ok(Box::new(
                std::sync::Arc::try_unwrap(events).unwrap_or_else(|arc| (*arc).clone()).into_iter(),
            ))
        }

        fn close(&self) -> Result<(), Self::InternalStorageError> {
            let mut inner = self.inner.write().expect("Lock should not be poisoned");
            inner.is_closed = true;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::persist::test_utils::InMemoryTestPersister;

    type InMemoryTestState = String;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct InMemoryTestEvent(String);

    #[derive(Debug, Clone, PartialEq)]
    /// Dummy error type for testing
    struct InMemoryTestError {}

    impl std::error::Error for InMemoryTestError {}

    impl fmt::Display for InMemoryTestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "InMemoryTestError")
        }
    }

    struct TestCase<SuccessState, ErrorState> {
        // Allow type complexity for the test closure
        #[allow(clippy::type_complexity)]
        test: Box<
            dyn Fn(&InMemoryTestPersister<InMemoryTestEvent>) -> Result<SuccessState, ErrorState>,
        >,
        expected_result: ExpectedResult<SuccessState, ErrorState>,
    }

    struct ExpectedResult<SuccessState, ErrorState> {
        /// Events that should be saved
        events: Vec<InMemoryTestEvent>,
        /// Whether the session should be closed
        is_closed: bool,
        /// Error that should be returned
        error: Option<ErrorState>,
        /// Success state if one exists for this test case
        success: Option<SuccessState>,
    }

    fn do_test<SuccessState: std::fmt::Debug + PartialEq, ErrorState: std::error::Error>(
        persister: &InMemoryTestPersister<InMemoryTestEvent>,
        test_case: &TestCase<SuccessState, ErrorState>,
    ) {
        let expected_result = &test_case.expected_result;
        let res = (test_case.test)(persister);
        let events = persister.load().expect("Persister should not fail").collect::<Vec<_>>();
        assert_eq!(events.len(), expected_result.events.len());
        for (event, expected_event) in events.iter().zip(expected_result.events.iter()) {
            assert_eq!(event.0, expected_event.0);
        }

        assert_eq!(
            persister.inner.read().expect("Lock should not be poisoned").is_closed,
            expected_result.is_closed
        );

        match (&res, &expected_result.error) {
            (Ok(actual), None) => {
                assert_eq!(Some(actual), expected_result.success.as_ref());
            }
            (Err(actual), Some(expected)) => {
                // TODO: replace .to_string() with .eq(). This would introduce a trait bound on the internal API error type
                // And not all internal API errors implement PartialEq
                assert_eq!(actual.to_string(), expected.to_string());
            }
            _ => panic!("Unexpected result state"),
        }
    }

    #[test]
    fn test_initial_transition() {
        let event = InMemoryTestEvent("foo".to_string());
        let next_state = "Next state".to_string();
        let test_cases: Vec<TestCase<InMemoryTestState, std::convert::Infallible>> = vec![
            // Success
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![event.clone()],
                    is_closed: false,
                    error: None,
                    success: Some(next_state.clone()),
                },
                test: Box::new(move |persister| {
                    NextStateTransition::success(event.clone(), next_state.clone()).save(persister)
                }),
            },
        ];

        for test in test_cases {
            let persister = InMemoryTestPersister::default();
            do_test(&persister, &test);
        }
    }

    #[test]
    fn test_maybe_transient_transition() {
        let event = InMemoryTestEvent("foo".to_string());
        let next_state = "Next state".to_string();
        let test_cases: Vec<
            TestCase<
                InMemoryTestState,
                PersistedError<InMemoryTestError, std::convert::Infallible>,
            >,
        > = vec![
            // Success
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![event.clone()],
                    is_closed: false,
                    error: None,
                    success: Some(next_state.clone()),
                },
                test: Box::new(move |persister| {
                    MaybeTransientTransition::success(event.clone(), next_state.clone())
                        .save(persister)
                }),
            },
            // Transient error
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: Some(InternalPersistedError::Transient(InMemoryTestError {}).into()),
                    success: None,
                },
                test: Box::new(move |persister| {
                    MaybeTransientTransition::transient(InMemoryTestError {}).save(persister)
                }),
            },
        ];

        for test in test_cases {
            let persister = InMemoryTestPersister::default();
            do_test(&persister, &test);
        }
    }

    #[test]
    fn test_next_state_transition() {
        let event = InMemoryTestEvent("foo".to_string());
        let next_state = "Next state".to_string();
        let test_cases: Vec<TestCase<InMemoryTestState, std::convert::Infallible>> = vec![
            // Success
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![event.clone()],
                    is_closed: false,
                    error: None,
                    success: Some(next_state.clone()),
                },
                test: Box::new(move |persister| {
                    NextStateTransition::success(event.clone(), next_state.clone()).save(persister)
                }),
            },
        ];

        for test in test_cases {
            let persister = InMemoryTestPersister::default();
            do_test(&persister, &test);
        }
    }

    #[test]
    fn test_maybe_success_transition() {
        let event = InMemoryTestEvent("foo".to_string());
        let test_cases: Vec<
            TestCase<(), PersistedError<InMemoryTestError, std::convert::Infallible>>,
        > = vec![
            // Success
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![event.clone()],
                    is_closed: true,
                    error: None,
                    success: Some(()),
                },
                test: Box::new(move |persister| {
                    MaybeSuccessTransition::success(event.clone(), ()).save(persister)
                }),
            },
            // Transient error
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: Some(InternalPersistedError::Transient(InMemoryTestError {}).into()),
                    success: None,
                },
                test: Box::new(move |persister| {
                    MaybeSuccessTransition::transient(InMemoryTestError {}).save(persister)
                }),
            },
            // Fatal error
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![InMemoryTestEvent("error event".to_string())],
                    is_closed: true,
                    error: Some(InternalPersistedError::Fatal(InMemoryTestError {}).into()),
                    success: None,
                },
                test: Box::new(move |persister| {
                    MaybeSuccessTransition::fatal(
                        InMemoryTestEvent("error event".to_string()),
                        InMemoryTestError {},
                    )
                    .save(persister)
                }),
            },
        ];

        for test in test_cases {
            let persister = InMemoryTestPersister::default();
            do_test(&persister, &test);
        }
    }

    #[test]
    fn test_maybe_fatal_transition() {
        let event = InMemoryTestEvent("foo".to_string());
        let error_event = InMemoryTestEvent("error event".to_string());
        let next_state = "Next state".to_string();

        let test_cases: Vec<
            TestCase<
                InMemoryTestState,
                PersistedError<InMemoryTestError, std::convert::Infallible>,
            >,
        > = vec![
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![event.clone()],
                    is_closed: false,
                    error: None,
                    success: Some(next_state.clone()),
                },
                test: Box::new(move |persister| {
                    MaybeFatalTransition::success(event.clone(), next_state.clone()).save(persister)
                }),
            },
            // Transient error
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: Some(InternalPersistedError::Transient(InMemoryTestError {}).into()),
                    success: None,
                },
                test: Box::new(move |persister| {
                    MaybeFatalTransition::transient(InMemoryTestError {}).save(persister)
                }),
            },
            // Fatal error
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![error_event.clone()],
                    is_closed: true,
                    error: Some(InternalPersistedError::Fatal(InMemoryTestError {}).into()),
                    success: None,
                },
                test: Box::new(move |persister| {
                    MaybeFatalTransition::fatal(error_event.clone(), InMemoryTestError {})
                        .save(persister)
                }),
            },
        ];

        for test in test_cases {
            let persister = InMemoryTestPersister::default();
            do_test(&persister, &test);
        }
    }

    #[test]
    fn test_maybe_success_transition_with_no_results() {
        let event = InMemoryTestEvent("foo".to_string());
        let error_event = InMemoryTestEvent("error event".to_string());
        let current_state = "Current state".to_string();
        let success_value = "Success value".to_string();
        let test_cases: Vec<
            TestCase<
                OptionalTransitionOutcome<InMemoryTestState, InMemoryTestState>,
                PersistedError<InMemoryTestError, std::convert::Infallible>,
            >,
        > = vec![
            // Success
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![event.clone()],
                    is_closed: true,
                    error: None,
                    success: Some(OptionalTransitionOutcome::Progress(success_value.clone())),
                },
                test: Box::new(move |persister| {
                    MaybeSuccessTransitionWithNoResults::success(
                        success_value.clone(),
                        event.clone(),
                    )
                    .save(persister)
                }),
            },
            // No results
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: None,
                    success: Some(OptionalTransitionOutcome::Stasis(current_state.clone())),
                },
                test: Box::new(move |persister| {
                    MaybeSuccessTransitionWithNoResults::no_results(current_state.clone())
                        .save(persister)
                }),
            },
            // Transient error
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: Some(InternalPersistedError::Transient(InMemoryTestError {}).into()),
                    success: None,
                },
                test: Box::new(move |persister| {
                    MaybeSuccessTransitionWithNoResults::transient(InMemoryTestError {})
                        .save(persister)
                }),
            },
            // Fatal error
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![error_event.clone()],
                    is_closed: true,
                    error: Some(InternalPersistedError::Fatal(InMemoryTestError {}).into()),
                    success: None,
                },
                test: Box::new(move |persister| {
                    MaybeSuccessTransitionWithNoResults::fatal(
                        error_event.clone(),
                        InMemoryTestError {},
                    )
                    .save(persister)
                }),
            },
        ];

        for test in test_cases {
            let persister = InMemoryTestPersister::default();
            do_test(&persister, &test);
        }
    }

    #[test]
    fn test_maybe_fatal_transition_with_no_results() {
        let event = InMemoryTestEvent("foo".to_string());
        let error_event = InMemoryTestEvent("error event".to_string());
        let current_state = "Current state".to_string();
        let next_state = "Next state".to_string();
        let test_cases: Vec<
            TestCase<
                OptionalTransitionOutcome<InMemoryTestState, InMemoryTestState>,
                PersistedError<InMemoryTestError, std::convert::Infallible>,
            >,
        > = vec![
            // Success
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![event.clone()],
                    is_closed: false,
                    error: None,
                    success: Some(OptionalTransitionOutcome::Progress(next_state.clone())),
                },
                test: Box::new(move |persister| {
                    MaybeFatalTransitionWithNoResults::success(event.clone(), next_state.clone())
                        .save(persister)
                }),
            },
            // No results
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: None,
                    success: Some(OptionalTransitionOutcome::Stasis(current_state.clone())),
                },
                test: Box::new(move |persister| {
                    MaybeFatalTransitionWithNoResults::no_results(current_state.clone())
                        .save(persister)
                }),
            },
            // Fatal error
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![error_event.clone()],
                    is_closed: true,
                    error: Some(InternalPersistedError::Fatal(InMemoryTestError {}).into()),
                    success: None,
                },
                test: Box::new(move |persister| {
                    MaybeFatalTransitionWithNoResults::fatal(
                        error_event.clone(),
                        InMemoryTestError {},
                    )
                    .save(persister)
                }),
            },
        ];

        for test in test_cases {
            let persister = InMemoryTestPersister::default();
            do_test(&persister, &test);
        }
    }

    #[test]
    fn test_maybe_fatal_or_success_transition() {
        let event = InMemoryTestEvent("foo".to_string());
        let error_event = InMemoryTestEvent("error event".to_string());
        let current_state = "Current state".to_string();
        let test_cases: Vec<
            TestCase<
                OptionalTransitionOutcome<(), InMemoryTestState>,
                PersistedError<InMemoryTestError, std::convert::Infallible>,
            >,
        > = vec![
            // Success
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![event.clone()],
                    is_closed: true,
                    error: None,
                    success: Some(OptionalTransitionOutcome::Progress(())),
                },
                test: Box::new(move |persister| {
                    MaybeFatalOrSuccessTransition::Success(event.clone()).save(persister)
                }),
            },
            // No results
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: None,
                    success: Some(OptionalTransitionOutcome::Stasis(current_state.clone())),
                },
                test: Box::new(move |persister| {
                    MaybeFatalOrSuccessTransition::NoResults(current_state.clone()).save(persister)
                }),
            },
            // Fatal error
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![error_event.clone()],
                    is_closed: true,
                    error: Some(InternalPersistedError::Fatal(InMemoryTestError {}).into()),
                    success: None,
                },
                test: Box::new(move |persister| {
                    MaybeFatalOrSuccessTransition::fatal(error_event.clone(), InMemoryTestError {})
                        .save(persister)
                }),
            },
            // Transient error
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: Some(InternalPersistedError::Transient(InMemoryTestError {}).into()),
                    success: None,
                },
                test: Box::new(move |persister| {
                    MaybeFatalOrSuccessTransition::transient(InMemoryTestError {}).save(persister)
                }),
            },
        ];

        for test in test_cases {
            let persister = InMemoryTestPersister::default();
            do_test(&persister, &test);
        }
    }

    #[test]
    fn test_persisted_error_helpers() {
        let api_err = InMemoryTestError {};

        // Test Storage error case
        let storage_error = PersistedError::<InMemoryTestError, InMemoryTestError>(
            InternalPersistedError::Storage(InMemoryTestError {}),
        );
        assert!(storage_error.storage_error_ref().is_some());
        assert!(storage_error.api_error_ref().is_none());

        // Test Internal API error cases
        let fatal_error = PersistedError::<InMemoryTestError, InMemoryTestError>(
            InternalPersistedError::Fatal(api_err.clone()),
        );
        assert!(fatal_error.storage_error_ref().is_none());
        assert!(fatal_error.api_error_ref().is_some());

        let transient_error = PersistedError::<InMemoryTestError, InMemoryTestError>(
            InternalPersistedError::Transient(api_err.clone()),
        );
        assert!(transient_error.storage_error_ref().is_none());
        assert!(transient_error.api_error_ref().is_some());
    }
}

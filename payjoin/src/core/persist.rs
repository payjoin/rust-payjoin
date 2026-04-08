//! State machine persistence for payjoin sessions.
//!
//! The receiver and senders' v1 and v2 state machines are driven by events. An
//! event contains all the information to transition into the next state, which
//! means that the session's full state can be computed by "replaying" the events.
//! Session history is therefore a recorded as an append only log of events.
//!
//! # Backwards and forwards compatibility
//!
//! If any new fields are added to events, backwards compatibility must be
//! maintained, which means that new fields are necessarily `Option<T>`
//! defaulting to `None`, allowing old event data to be still be processed.
//! Forward compatibility in general is not appropriate since old state machines
//! will not know the meaning of the new fields, and ignoring them may lead to a
//! transition to an invalid state, inconsistent with the state machine of any
//! later version of the code that persisted this event data.
//!
//! If any new event types are added, presumably extending the state machine
//! with additional transitions and states, the same logic applies: old sessions
//! will simply not contain this new type of event and therefore only explore
//! the subgraph of the state machine diagram which corresponds to the older
//! version of the state machine. New sessions which do contain this event will
//! not be interpretable by the old code.

use alloc::boxed::Box;
use alloc::fmt;
use core::{convert, iter, marker};

/// Representation of the actions that the persister should take, if any.
pub(crate) enum PersistActions<Event> {
    /// Do nothing.
    NoOp,
    /// Save an event.
    Save(Event),
    /// Save an event and close the session.
    SaveAndClose(Event),
}

impl<Event> PersistActions<Event> {
    pub fn execute<P>(self, persister: &P) -> Result<(), P::InternalStorageError>
    where
        P: SessionPersister<SessionEvent = Event>,
    {
        match self {
            Self::NoOp => {}
            Self::Save(event) => persister.save_event(event)?,
            Self::SaveAndClose(event) => {
                persister.save_event(event)?;
                persister.close()?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "std")]
    pub async fn execute_async<P>(self, persister: &P) -> Result<(), P::InternalStorageError>
    where
        P: AsyncSessionPersister<SessionEvent = Event>,
        Event: Send,
    {
        match self {
            Self::NoOp => {}
            Self::Save(event) => persister.save_event(event).await?,
            Self::SaveAndClose(event) => {
                persister.save_event(event).await?;
                persister.close().await?;
            }
        }
        Ok(())
    }
}

/// Handles cases where the transition either succeeds with a final result that ends the session, or hits a static condition and stays in the same state.
/// State transition may also be a fatal error or transient error.
pub struct MaybeSuccessTransitionWithNoResults<Event, SuccessValue, CurrentState, Err>(
    Result<AcceptOptionalTransition<Event, SuccessValue, CurrentState>, Rejection<Event, Err>>,
);

impl<Event, SuccessValue, CurrentState, Err>
    MaybeSuccessTransitionWithNoResults<Event, SuccessValue, CurrentState, Err>
where
    Err: core::error::Error,
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

    #[allow(clippy::type_complexity)]
    #[allow(dead_code)]
    pub(crate) fn deconstruct(
        self,
    ) -> (
        PersistActions<Event>,
        Result<OptionalTransitionOutcome<SuccessValue, CurrentState>, ApiError<Err>>,
    ) {
        match self.0 {
            Ok(AcceptOptionalTransition::Success(AcceptNextState(event, success_value))) => (
                PersistActions::SaveAndClose(event),
                Ok(OptionalTransitionOutcome::Progress(success_value)),
            ),
            Ok(AcceptOptionalTransition::NoResults(current_state)) =>
                (PersistActions::NoOp, Ok(OptionalTransitionOutcome::Stasis(current_state))),
            Err(Rejection::Fatal(RejectFatal(event, error))) =>
                (PersistActions::SaveAndClose(event), Err(ApiError::Fatal(error))),
            Err(Rejection::Transient(RejectTransient(error))) =>
                (PersistActions::NoOp, Err(ApiError::Transient(error))),
            Err(Rejection::ReplyableError(RejectReplyableError(event, _, error))) =>
                (PersistActions::Save(event), Err(ApiError::Fatal(error))),
        }
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
        Err: core::error::Error,
    {
        persister.save_maybe_no_results_success_transition(self)
    }

    #[cfg(feature = "std")]
    pub async fn save_async<P>(
        self,
        persister: &P,
    ) -> Result<
        OptionalTransitionOutcome<SuccessValue, CurrentState>,
        PersistedError<Err, P::InternalStorageError>,
    >
    where
        P: AsyncSessionPersister<SessionEvent = Event>,
        Err: core::error::Error + Send,
        SuccessValue: Send,
        CurrentState: Send,
        Event: Send,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute_async(persister).await.map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
    }
}

/// A transition that can result in a state transition, fatal error, or successfully have no results.
pub struct MaybeFatalTransitionWithNoResults<Event, NextState, CurrentState, Err>(
    Result<AcceptOptionalTransition<Event, NextState, CurrentState>, Rejection<Event, Err>>,
);

impl<Event, NextState, CurrentState, Err>
    MaybeFatalTransitionWithNoResults<Event, NextState, CurrentState, Err>
where
    Err: core::error::Error,
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

    #[allow(clippy::type_complexity)]
    #[allow(dead_code)]
    pub(crate) fn deconstruct(
        self,
    ) -> (
        PersistActions<Event>,
        Result<OptionalTransitionOutcome<NextState, CurrentState>, ApiError<Err>>,
    ) {
        match self.0 {
            Ok(AcceptOptionalTransition::Success(AcceptNextState(event, next_state))) =>
                (PersistActions::Save(event), Ok(OptionalTransitionOutcome::Progress(next_state))),
            Ok(AcceptOptionalTransition::NoResults(current_state)) =>
                (PersistActions::NoOp, Ok(OptionalTransitionOutcome::Stasis(current_state))),
            Err(Rejection::Fatal(RejectFatal(event, error))) =>
                (PersistActions::SaveAndClose(event), Err(ApiError::Fatal(error))),
            Err(Rejection::Transient(RejectTransient(error))) =>
                (PersistActions::NoOp, Err(ApiError::Transient(error))),
            Err(Rejection::ReplyableError(RejectReplyableError(event, _, error))) =>
                (PersistActions::Save(event), Err(ApiError::Fatal(error))),
        }
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
        Err: core::error::Error,
    {
        persister.save_maybe_no_results_transition(self)
    }

    #[cfg(feature = "std")]
    pub async fn save_async<P>(
        self,
        persister: &P,
    ) -> Result<
        OptionalTransitionOutcome<NextState, CurrentState>,
        PersistedError<Err, P::InternalStorageError>,
    >
    where
        P: AsyncSessionPersister<SessionEvent = Event>,
        Err: core::error::Error + Send,
        NextState: Send,
        CurrentState: Send,
        Event: Send,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute_async(persister).await.map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
    }
}

/// A transition that can be either fatal, transient, or a state transition.
pub struct MaybeFatalTransition<Event, NextState, Err, ErrorState = ()>(
    pub(crate) Result<AcceptNextState<Event, NextState>, Rejection<Event, Err, ErrorState>>,
);

impl<Event, NextState, Err, ErrorState> MaybeFatalTransition<Event, NextState, Err, ErrorState>
where
    Err: core::error::Error,
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

    #[allow(dead_code)]
    pub(crate) fn deconstruct(
        self,
    ) -> (PersistActions<Event>, Result<NextState, ApiError<Err, ErrorState>>) {
        match self.0 {
            Ok(AcceptNextState(event, next_state)) => (PersistActions::Save(event), Ok(next_state)),
            Err(Rejection::Fatal(RejectFatal(event, error))) =>
                (PersistActions::SaveAndClose(event), Err(ApiError::Fatal(error))),
            Err(Rejection::Transient(RejectTransient(error))) =>
                (PersistActions::NoOp, Err(ApiError::Transient(error))),
            Err(Rejection::ReplyableError(RejectReplyableError(event, error_state, error))) =>
                (PersistActions::Save(event), Err(ApiError::FatalWithState(error, error_state))),
        }
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<NextState, PersistedError<Err, P::InternalStorageError, ErrorState>>
    where
        P: SessionPersister<SessionEvent = Event>,
        Err: core::error::Error,
    {
        persister.save_maybe_fatal_error_transition(self)
    }

    #[cfg(feature = "std")]
    pub async fn save_async<P>(
        self,
        persister: &P,
    ) -> Result<NextState, PersistedError<Err, P::InternalStorageError, ErrorState>>
    where
        P: AsyncSessionPersister<SessionEvent = Event>,
        Err: core::error::Error + Send,
        NextState: Send,
        ErrorState: Send,
        Event: Send,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute_async(persister).await.map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
    }
}

/// A transition that can result in a state transition or a transient error.
/// Fatal errors cannot occur in this transition.
pub struct MaybeTransientTransition<Event, NextState, Err>(
    Result<AcceptNextState<Event, NextState>, RejectTransient<Err>>,
);

impl<Event, NextState, Err> MaybeTransientTransition<Event, NextState, Err>
where
    Err: core::error::Error,
{
    pub(crate) fn success(event: Event, next_state: NextState) -> Self {
        MaybeTransientTransition(Ok(AcceptNextState(event, next_state)))
    }

    pub(crate) fn transient(error: Err) -> Self {
        MaybeTransientTransition(Err(RejectTransient(error)))
    }

    #[allow(dead_code)]
    pub(crate) fn deconstruct(self) -> (PersistActions<Event>, Result<NextState, ApiError<Err>>) {
        match self.0 {
            Ok(AcceptNextState(event, next_state)) => (PersistActions::Save(event), Ok(next_state)),
            Err(RejectTransient(error)) => (PersistActions::NoOp, Err(ApiError::Transient(error))),
        }
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<NextState, PersistedError<Err, P::InternalStorageError>>
    where
        P: SessionPersister<SessionEvent = Event>,
        Err: core::error::Error,
    {
        persister.save_maybe_transient_error_transition(self)
    }

    #[cfg(feature = "std")]
    pub async fn save_async<P>(
        self,
        persister: &P,
    ) -> Result<NextState, PersistedError<Err, P::InternalStorageError>>
    where
        P: AsyncSessionPersister<SessionEvent = Event>,
        Err: core::error::Error + Send,
        NextState: Send,
        Event: Send,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute_async(persister).await.map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
    }
}

/// A transition that can result in the completion of a state machine or a transient error
/// Fatal errors cannot occur in this transition.
pub struct MaybeSuccessTransition<Event, SuccessValue, Err>(
    Result<AcceptNextState<Event, SuccessValue>, Rejection<Event, Err>>,
);

#[allow(dead_code)]
impl<Event, SuccessValue, Err> MaybeSuccessTransition<Event, SuccessValue, Err>
where
    Err: core::error::Error,
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

    #[allow(dead_code)]
    pub(crate) fn deconstruct(
        self,
    ) -> (PersistActions<Event>, Result<SuccessValue, ApiError<Err>>) {
        match self.0 {
            Ok(AcceptNextState(event, success_value)) =>
                (PersistActions::SaveAndClose(event), Ok(success_value)),
            Err(Rejection::Transient(RejectTransient(error))) =>
                (PersistActions::NoOp, Err(ApiError::Transient(error))),
            Err(Rejection::Fatal(RejectFatal(event, error))) =>
                (PersistActions::SaveAndClose(event), Err(ApiError::Fatal(error))),
            Err(Rejection::ReplyableError(RejectReplyableError(event, _, error))) =>
                (PersistActions::Save(event), Err(ApiError::Fatal(error))),
        }
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<SuccessValue, PersistedError<Err, P::InternalStorageError>>
    where
        P: SessionPersister<SessionEvent = Event>,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute(persister).map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
    }

    #[cfg(feature = "std")]
    pub async fn save_async<P>(
        self,
        persister: &P,
    ) -> Result<SuccessValue, PersistedError<Err, P::InternalStorageError>>
    where
        P: AsyncSessionPersister<SessionEvent = Event>,
        Err: Send,
        SuccessValue: Send,
        Event: Send,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute_async(persister).await.map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
    }
}

/// A transition that always results in a state transition.
pub struct NextStateTransition<Event, NextState>(AcceptNextState<Event, NextState>);

impl<Event, NextState> NextStateTransition<Event, NextState> {
    pub(crate) fn success(event: Event, next_state: NextState) -> Self {
        NextStateTransition(AcceptNextState(event, next_state))
    }

    #[allow(dead_code)]
    pub(crate) fn deconstruct(self) -> (PersistActions<Event>, NextState) {
        let AcceptNextState(event, next_state) = self.0;
        (PersistActions::Save(event), next_state)
    }

    pub fn save<P>(self, persister: &P) -> Result<NextState, P::InternalStorageError>
    where
        P: SessionPersister<SessionEvent = Event>,
    {
        let (actions, next_state) = self.deconstruct();
        actions.execute(persister)?;
        Ok(next_state)
    }

    #[cfg(feature = "std")]
    pub async fn save_async<P>(self, persister: &P) -> Result<NextState, P::InternalStorageError>
    where
        P: AsyncSessionPersister<SessionEvent = Event>,
        NextState: Send,
        Event: Send,
    {
        let (actions, next_state) = self.deconstruct();
        actions.execute_async(persister).await?;
        Ok(next_state)
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
    Err: core::error::Error,
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

    #[allow(clippy::type_complexity)]
    #[allow(dead_code)]
    pub(crate) fn deconstruct(
        self,
    ) -> (PersistActions<Event>, Result<OptionalTransitionOutcome<(), CurrentState>, ApiError<Err>>)
    {
        match self {
            MaybeFatalOrSuccessTransition::Success(event) =>
                (PersistActions::SaveAndClose(event), Ok(OptionalTransitionOutcome::Progress(()))),
            MaybeFatalOrSuccessTransition::NoResults(current_state) =>
                (PersistActions::NoOp, Ok(OptionalTransitionOutcome::Stasis(current_state))),
            MaybeFatalOrSuccessTransition::Transient(RejectTransient(error)) =>
                (PersistActions::NoOp, Err(ApiError::Transient(error))),
            MaybeFatalOrSuccessTransition::Fatal(RejectFatal(event, error)) =>
                (PersistActions::SaveAndClose(event), Err(ApiError::Fatal(error))),
        }
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
        Err: core::error::Error,
    {
        persister.save_maybe_fatal_or_success_transition(self)
    }

    #[cfg(feature = "std")]
    pub async fn save_async<P>(
        self,
        persister: &P,
    ) -> Result<
        OptionalTransitionOutcome<(), CurrentState>,
        PersistedError<Err, P::InternalStorageError>,
    >
    where
        P: AsyncSessionPersister<SessionEvent = Event>,
        Err: core::error::Error + Send,
        CurrentState: Send,
        Event: Send,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute_async(persister).await.map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
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

impl<Err: core::error::Error> fmt::Display for RejectTransient<Err> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let RejectTransient(err) = self;
        write!(f, "{err}")
    }
}

/// Error type that represents all possible errors that can be returned when processing a state transition
#[derive(Debug)]
pub struct PersistedError<
    ApiError: core::error::Error,
    StorageError: core::error::Error,
    ErrorState: fmt::Debug = (),
>(InternalPersistedError<ApiError, StorageError, ErrorState>);

impl<ApiErr, StorageErr, ErrorState> PersistedError<ApiErr, StorageErr, ErrorState>
where
    StorageErr: core::error::Error,
    ApiErr: core::error::Error,
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
            InternalPersistedError::Api(
                ApiError::Fatal(e) | ApiError::Transient(e) | ApiError::FatalWithState(e, _),
            ) => Some(e),
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
            InternalPersistedError::Api(
                ApiError::Fatal(e) | ApiError::Transient(e) | ApiError::FatalWithState(e, _),
            ) => Some(e),
            _ => None,
        }
    }

    pub fn error_state(self) -> Option<ErrorState> {
        match self.0 {
            InternalPersistedError::Api(ApiError::FatalWithState(_, state)) => Some(state),
            _ => None,
        }
    }
}

impl<ApiError: core::error::Error, StorageError: core::error::Error, ErrorState: fmt::Debug>
    From<InternalPersistedError<ApiError, StorageError, ErrorState>>
    for PersistedError<ApiError, StorageError, ErrorState>
{
    fn from(value: InternalPersistedError<ApiError, StorageError, ErrorState>) -> Self {
        PersistedError(value)
    }
}

impl<ApiError: core::error::Error, StorageError: core::error::Error, ErrorState: fmt::Debug>
    core::error::Error for PersistedError<ApiError, StorageError, ErrorState>
{
}

impl<AErr: core::error::Error, StorageError: core::error::Error, ErrorState: fmt::Debug>
    fmt::Display for PersistedError<AErr, StorageError, ErrorState>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            InternalPersistedError::Api(api_err) => match api_err {
                ApiError::Transient(err) => write!(f, "Transient error: {err}"),
                ApiError::Fatal(err) | ApiError::FatalWithState(err, _) =>
                    write!(f, "Fatal error: {err}"),
            },
            InternalPersistedError::Storage(err) => write!(f, "Storage error: {err}"),
        }
    }
}

#[derive(Debug)]
pub(crate) enum ApiError<Err, ErrorState = ()> {
    /// Error indicating that the session should be retried from the same state
    Transient(Err),
    /// Error indicating that the session is terminally closed
    Fatal(Err),
    /// Fatal error that results in a state transition to ErrorState
    FatalWithState(Err, ErrorState),
}

#[derive(Debug)]
pub(crate) enum InternalPersistedError<ApiErr, StorageErr, ErrorState = ()>
where
    ApiErr: core::error::Error,
    StorageErr: core::error::Error,
    ErrorState: fmt::Debug,
{
    /// Error indicating that the session failed to progress to the next success state.
    Api(ApiError<ApiErr, ErrorState>),
    /// Error indicating that application failed to save the session event.
    Storage(StorageErr),
}

impl<Err, StorageErr, ErrorState> From<ApiError<Err, ErrorState>>
    for InternalPersistedError<Err, StorageErr, ErrorState>
where
    Err: core::error::Error,
    StorageErr: core::error::Error,
    ErrorState: fmt::Debug,
{
    fn from(api: ApiError<Err, ErrorState>) -> Self { InternalPersistedError::Api(api) }
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
    type InternalStorageError: core::error::Error + Send + Sync + 'static;
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

/// Async version of [SessionPersister] for use with async runtimes.
/// Only available with the `std` feature.
#[cfg(feature = "std")]
pub trait AsyncSessionPersister {
    type InternalStorageError: core::error::Error + Send + Sync + 'static;
    type SessionEvent;

    fn save_event(
        &self,
        event: Self::SessionEvent,
    ) -> impl std::future::Future<Output = Result<(), Self::InternalStorageError>> + Send;

    fn load(
        &self,
    ) -> impl std::future::Future<
        Output = Result<
            Box<dyn Iterator<Item = Self::SessionEvent> + Send>,
            Self::InternalStorageError,
        >,
    > + Send;

    fn close(
        &self,
    ) -> impl std::future::Future<Output = Result<(), Self::InternalStorageError>> + Send;
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
        Err: core::error::Error,
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
                Err(PersistedError(InternalPersistedError::Api(ApiError::Transient(err)))),
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
        Err: core::error::Error,
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
                Err(PersistedError(InternalPersistedError::Api(ApiError::Transient(err)))),
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
        Err: core::error::Error,
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
                Err(PersistedError(InternalPersistedError::Api(ApiError::Transient(err)))),
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
        Err: core::error::Error,
    {
        match state_transition.0 {
            Ok(AcceptNextState(event, next_state)) => {
                self.save_event(event).map_err(InternalPersistedError::Storage)?;
                Ok(next_state)
            }
            Err(RejectTransient(err)) =>
                Err(PersistedError(InternalPersistedError::Api(ApiError::Transient(err)))),
        }
    }

    /// Save a transition that can be a fatal error, transient error or a state transition
    fn save_maybe_fatal_error_transition<NextState, Err, ErrorState>(
        &self,
        state_transition: MaybeFatalTransition<Self::SessionEvent, NextState, Err, ErrorState>,
    ) -> Result<NextState, PersistedError<Err, Self::InternalStorageError, ErrorState>>
    where
        Err: core::error::Error,
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
                        Err(PersistedError(InternalPersistedError::Api(ApiError::Transient(err))))
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
        Err: core::error::Error,
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

        InternalPersistedError::Api(ApiError::Fatal(error))
    }

    fn handle_replyable_error_reject<Err, ErrorState>(
        &self,
        reject_replyable_error: RejectReplyableError<Self::SessionEvent, ErrorState, Err>,
    ) -> InternalPersistedError<Err, Self::InternalStorageError, ErrorState>
    where
        Err: core::error::Error,
        ErrorState: fmt::Debug,
    {
        let RejectReplyableError(event, error_state, error) = reject_replyable_error;
        if let Err(e) = self.save_event(event) {
            return InternalPersistedError::Storage(e);
        }
        // For replyable errors, don't close the session - keep it open for error response
        InternalPersistedError::Api(ApiError::FatalWithState(error, error_state))
    }
}

impl<T: SessionPersister> InternalSessionPersister for T {}

/// A persister that does nothing
/// This persister cannot be used to replay a session
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NoopPersisterEvent;

#[derive(Debug, Clone)]
pub struct NoopSessionPersister<E = NoopPersisterEvent>(marker::PhantomData<E>);

impl<E> Default for NoopSessionPersister<E> {
    fn default() -> Self { Self(marker::PhantomData) }
}

impl<E: 'static> SessionPersister for NoopSessionPersister<E> {
    type InternalStorageError = convert::Infallible;
    type SessionEvent = E;

    fn save_event(&self, _event: Self::SessionEvent) -> Result<(), Self::InternalStorageError> {
        Ok(())
    }

    fn load(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::InternalStorageError> {
        Ok(Box::new(iter::empty()))
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
        type InternalStorageError = core::convert::Infallible;
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
            Ok(Box::new(Arc::try_unwrap(events).unwrap_or_else(|arc| (*arc).clone()).into_iter()))
        }

        fn close(&self) -> Result<(), Self::InternalStorageError> {
            let mut inner = self.inner.write().expect("Lock should not be poisoned");
            inner.is_closed = true;
            Ok(())
        }
    }

    #[cfg(test)]
    #[derive(Clone)]
    /// Async in-memory session persister for testing async session replays and introspecting session events
    pub struct InMemoryAsyncTestPersister<V> {
        pub(crate) inner: Arc<tokio::sync::RwLock<InnerStorage<V>>>,
    }

    #[cfg(test)]
    impl<V> Default for InMemoryAsyncTestPersister<V> {
        fn default() -> Self {
            Self { inner: Arc::new(tokio::sync::RwLock::new(InnerStorage::default())) }
        }
    }

    #[cfg(all(test, feature = "std"))]
    impl<V> crate::persist::AsyncSessionPersister for InMemoryAsyncTestPersister<V>
    where
        V: Clone + Send + Sync + 'static,
    {
        type InternalStorageError = std::convert::Infallible;
        type SessionEvent = V;

        async fn save_event(
            &self,
            event: Self::SessionEvent,
        ) -> Result<(), Self::InternalStorageError> {
            let mut inner = self.inner.write().await;
            Arc::make_mut(&mut inner.events).push(event);
            Ok(())
        }

        async fn load(
            &self,
        ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent> + Send>, Self::InternalStorageError>
        {
            let inner = self.inner.read().await;
            let events = Arc::clone(&inner.events);
            Ok(Box::new(Arc::try_unwrap(events).unwrap_or_else(|arc| (*arc).clone()).into_iter()))
        }

        async fn close(&self) -> Result<(), Self::InternalStorageError> {
            let mut inner = self.inner.write().await;
            inner.is_closed = true;
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::type_complexity)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::persist::test_utils::InMemoryAsyncTestPersister;

    type InMemoryTestState = String;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct InMemoryTestEvent(String);

    #[derive(Debug, Clone, PartialEq)]
    /// Dummy error type for testing
    struct InMemoryTestError {}

    impl std::error::Error for InMemoryTestError {}

    impl fmt::Display for InMemoryTestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "InMemoryTestError") }
    }

    struct TestCase<Transition, SuccessState, ErrorState> {
        make_transition: Box<dyn Fn() -> Transition>,
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

    async fn verify_async<
        SuccessState: std::fmt::Debug + PartialEq + Send,
        ErrorState: std::error::Error + Send,
    >(
        persister: &InMemoryAsyncTestPersister<InMemoryTestEvent>,
        result: Result<SuccessState, ErrorState>,
        expected_result: &ExpectedResult<SuccessState, ErrorState>,
    ) {
        let events = persister.load().await.expect("Persister should not fail").collect::<Vec<_>>();
        assert_eq!(events.len(), expected_result.events.len());
        for (event, expected_event) in events.iter().zip(expected_result.events.iter()) {
            assert_eq!(event.0, expected_event.0);
        }

        assert_eq!(persister.inner.read().await.is_closed, expected_result.is_closed);

        match (&result, &expected_result.error) {
            (Ok(actual), None) => {
                assert_eq!(Some(actual), expected_result.success.as_ref());
            }
            (Err(actual), Some(exp)) => {
                assert_eq!(actual.to_string(), exp.to_string());
            }
            _ => panic!("Unexpected result state"),
        }
    }

    macro_rules! run_test_cases {
        ($test_cases:expr) => {
            for test in &$test_cases {
                let persister = InMemoryAsyncTestPersister::default();
                let result = (test.make_transition)().save_async(&persister).await;
                verify_async(&persister, result, &test.expected_result).await;
            }
        };
    }

    #[tokio::test]
    async fn test_initial_transition() {
        let event = InMemoryTestEvent("foo".to_string());
        let next_state = "Next state".to_string();
        let test_cases: Vec<
            TestCase<
                NextStateTransition<InMemoryTestEvent, InMemoryTestState>,
                InMemoryTestState,
                std::convert::Infallible,
            >,
        > = vec![TestCase {
            make_transition: Box::new({
                let event = event.clone();
                let next_state = next_state.clone();
                move || NextStateTransition::success(event.clone(), next_state.clone())
            }),
            expected_result: ExpectedResult {
                events: vec![event.clone()],
                is_closed: false,
                error: None,
                success: Some(next_state.clone()),
            },
        }];

        run_test_cases!(test_cases);
    }

    #[tokio::test]
    async fn test_maybe_transient_transition() {
        let event = InMemoryTestEvent("foo".to_string());
        let next_state = "Next state".to_string();
        let test_cases: Vec<
            TestCase<
                MaybeTransientTransition<InMemoryTestEvent, InMemoryTestState, InMemoryTestError>,
                InMemoryTestState,
                PersistedError<InMemoryTestError, std::convert::Infallible>,
            >,
        > = vec![
            TestCase {
                make_transition: Box::new({
                    let event = event.clone();
                    let next_state = next_state.clone();
                    move || MaybeTransientTransition::success(event.clone(), next_state.clone())
                }),
                expected_result: ExpectedResult {
                    events: vec![event.clone()],
                    is_closed: false,
                    error: None,
                    success: Some(next_state.clone()),
                },
            },
            TestCase {
                make_transition: Box::new(|| {
                    MaybeTransientTransition::transient(InMemoryTestError {})
                }),
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Transient(InMemoryTestError {}))
                            .into(),
                    ),
                    success: None,
                },
            },
        ];

        run_test_cases!(test_cases);
    }

    #[tokio::test]
    async fn test_next_state_transition() {
        let event = InMemoryTestEvent("foo".to_string());
        let next_state = "Next state".to_string();
        let test_cases: Vec<
            TestCase<
                NextStateTransition<InMemoryTestEvent, InMemoryTestState>,
                InMemoryTestState,
                std::convert::Infallible,
            >,
        > = vec![TestCase {
            make_transition: Box::new({
                let event = event.clone();
                let next_state = next_state.clone();
                move || NextStateTransition::success(event.clone(), next_state.clone())
            }),
            expected_result: ExpectedResult {
                events: vec![event.clone()],
                is_closed: false,
                error: None,
                success: Some(next_state.clone()),
            },
        }];

        run_test_cases!(test_cases);
    }

    #[tokio::test]
    async fn test_maybe_success_transition() {
        let event = InMemoryTestEvent("foo".to_string());
        let error_event = InMemoryTestEvent("error event".to_string());
        let test_cases: Vec<
            TestCase<
                MaybeSuccessTransition<InMemoryTestEvent, (), InMemoryTestError>,
                (),
                PersistedError<InMemoryTestError, std::convert::Infallible>,
            >,
        > = vec![
            TestCase {
                make_transition: Box::new({
                    let event = event.clone();
                    move || MaybeSuccessTransition::success(event.clone(), ())
                }),
                expected_result: ExpectedResult {
                    events: vec![event.clone()],
                    is_closed: true,
                    error: None,
                    success: Some(()),
                },
            },
            TestCase {
                make_transition: Box::new(|| {
                    MaybeSuccessTransition::transient(InMemoryTestError {})
                }),
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Transient(InMemoryTestError {}))
                            .into(),
                    ),
                    success: None,
                },
            },
            TestCase {
                make_transition: Box::new({
                    let error_event = error_event.clone();
                    move || MaybeSuccessTransition::fatal(error_event.clone(), InMemoryTestError {})
                }),
                expected_result: ExpectedResult {
                    events: vec![error_event.clone()],
                    is_closed: true,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Fatal(InMemoryTestError {})).into(),
                    ),
                    success: None,
                },
            },
        ];

        run_test_cases!(test_cases);
    }

    #[tokio::test]
    async fn test_maybe_fatal_transition() {
        let event = InMemoryTestEvent("foo".to_string());
        let error_event = InMemoryTestEvent("error event".to_string());
        let next_state = "Next state".to_string();

        let test_cases: Vec<
            TestCase<
                MaybeFatalTransition<
                    InMemoryTestEvent,
                    InMemoryTestState,
                    InMemoryTestError,
                    std::convert::Infallible,
                >,
                InMemoryTestState,
                PersistedError<
                    InMemoryTestError,
                    std::convert::Infallible,
                    std::convert::Infallible,
                >,
            >,
        > = vec![
            TestCase {
                make_transition: Box::new({
                    let event = event.clone();
                    let next_state = next_state.clone();
                    move || MaybeFatalTransition::success(event.clone(), next_state.clone())
                }),
                expected_result: ExpectedResult {
                    events: vec![event.clone()],
                    is_closed: false,
                    error: None,
                    success: Some(next_state.clone()),
                },
            },
            TestCase {
                make_transition: Box::new(|| MaybeFatalTransition::transient(InMemoryTestError {})),
                expected_result: ExpectedResult::<
                    InMemoryTestState,
                    PersistedError<
                        InMemoryTestError,
                        std::convert::Infallible,
                        std::convert::Infallible,
                    >,
                > {
                    events: vec![],
                    is_closed: false,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Transient(InMemoryTestError {}))
                            .into(),
                    ),
                    success: None,
                },
            },
            TestCase {
                make_transition: Box::new({
                    let error_event = error_event.clone();
                    move || MaybeFatalTransition::fatal(error_event.clone(), InMemoryTestError {})
                }),
                expected_result: ExpectedResult {
                    events: vec![error_event.clone()],
                    is_closed: true,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Fatal(InMemoryTestError {})).into(),
                    ),
                    success: None,
                },
            },
        ];

        run_test_cases!(test_cases);
    }

    #[tokio::test]
    async fn test_maybe_success_transition_with_no_results() {
        let event = InMemoryTestEvent("foo".to_string());
        let error_event = InMemoryTestEvent("error event".to_string());
        let current_state = "Current state".to_string();
        let success_value = "Success value".to_string();
        let test_cases: Vec<
            TestCase<
                MaybeSuccessTransitionWithNoResults<
                    InMemoryTestEvent,
                    InMemoryTestState,
                    InMemoryTestState,
                    InMemoryTestError,
                >,
                OptionalTransitionOutcome<InMemoryTestState, InMemoryTestState>,
                PersistedError<InMemoryTestError, std::convert::Infallible>,
            >,
        > = vec![
            TestCase {
                make_transition: Box::new({
                    let event = event.clone();
                    let success_value = success_value.clone();
                    move || {
                        MaybeSuccessTransitionWithNoResults::success(
                            success_value.clone(),
                            event.clone(),
                        )
                    }
                }),
                expected_result: ExpectedResult {
                    events: vec![event.clone()],
                    is_closed: true,
                    error: None,
                    success: Some(OptionalTransitionOutcome::Progress(success_value.clone())),
                },
            },
            TestCase {
                make_transition: Box::new({
                    let current_state = current_state.clone();
                    move || MaybeSuccessTransitionWithNoResults::no_results(current_state.clone())
                }),
                expected_result: ExpectedResult::<
                    OptionalTransitionOutcome<InMemoryTestState, InMemoryTestState>,
                    PersistedError<InMemoryTestError, std::convert::Infallible>,
                > {
                    events: vec![],
                    is_closed: false,
                    error: None,
                    success: Some(OptionalTransitionOutcome::Stasis(current_state.clone())),
                },
            },
            TestCase {
                make_transition: Box::new(|| {
                    MaybeSuccessTransitionWithNoResults::transient(InMemoryTestError {})
                }),
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Transient(InMemoryTestError {}))
                            .into(),
                    ),
                    success: None,
                },
            },
            TestCase {
                make_transition: Box::new({
                    let error_event = error_event.clone();
                    move || {
                        MaybeSuccessTransitionWithNoResults::fatal(
                            error_event.clone(),
                            InMemoryTestError {},
                        )
                    }
                }),
                expected_result: ExpectedResult {
                    events: vec![error_event.clone()],
                    is_closed: true,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Fatal(InMemoryTestError {})).into(),
                    ),
                    success: None,
                },
            },
        ];

        run_test_cases!(test_cases);
    }

    #[tokio::test]
    async fn test_maybe_fatal_transition_with_no_results() {
        let event = InMemoryTestEvent("foo".to_string());
        let error_event = InMemoryTestEvent("error event".to_string());
        let current_state = "Current state".to_string();
        let next_state = "Next state".to_string();
        let test_cases: Vec<
            TestCase<
                MaybeFatalTransitionWithNoResults<
                    InMemoryTestEvent,
                    InMemoryTestState,
                    InMemoryTestState,
                    InMemoryTestError,
                >,
                OptionalTransitionOutcome<InMemoryTestState, InMemoryTestState>,
                PersistedError<InMemoryTestError, std::convert::Infallible>,
            >,
        > = vec![
            TestCase {
                make_transition: Box::new({
                    let event = event.clone();
                    let next_state = next_state.clone();
                    move || {
                        MaybeFatalTransitionWithNoResults::success(
                            event.clone(),
                            next_state.clone(),
                        )
                    }
                }),
                expected_result: ExpectedResult {
                    events: vec![event.clone()],
                    is_closed: false,
                    error: None,
                    success: Some(OptionalTransitionOutcome::Progress(next_state.clone())),
                },
            },
            TestCase {
                make_transition: Box::new({
                    let current_state = current_state.clone();
                    move || MaybeFatalTransitionWithNoResults::no_results(current_state.clone())
                }),
                expected_result: ExpectedResult::<
                    OptionalTransitionOutcome<InMemoryTestState, InMemoryTestState>,
                    PersistedError<InMemoryTestError, std::convert::Infallible>,
                > {
                    events: vec![],
                    is_closed: false,
                    error: None,
                    success: Some(OptionalTransitionOutcome::Stasis(current_state.clone())),
                },
            },
            TestCase {
                make_transition: Box::new({
                    let error_event = error_event.clone();
                    move || {
                        MaybeFatalTransitionWithNoResults::fatal(
                            error_event.clone(),
                            InMemoryTestError {},
                        )
                    }
                }),
                expected_result: ExpectedResult {
                    events: vec![error_event.clone()],
                    is_closed: true,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Fatal(InMemoryTestError {})).into(),
                    ),
                    success: None,
                },
            },
        ];

        run_test_cases!(test_cases);
    }

    #[tokio::test]
    async fn test_maybe_fatal_or_success_transition() {
        let event = InMemoryTestEvent("foo".to_string());
        let error_event = InMemoryTestEvent("error event".to_string());
        let current_state = "Current state".to_string();
        let test_cases: Vec<
            TestCase<
                MaybeFatalOrSuccessTransition<
                    InMemoryTestEvent,
                    InMemoryTestState,
                    InMemoryTestError,
                >,
                OptionalTransitionOutcome<(), InMemoryTestState>,
                PersistedError<InMemoryTestError, std::convert::Infallible>,
            >,
        > = vec![
            TestCase {
                make_transition: Box::new({
                    let event = event.clone();
                    move || MaybeFatalOrSuccessTransition::Success(event.clone())
                }),
                expected_result: ExpectedResult {
                    events: vec![event.clone()],
                    is_closed: true,
                    error: None,
                    success: Some(OptionalTransitionOutcome::Progress(())),
                },
            },
            TestCase {
                make_transition: Box::new({
                    let current_state = current_state.clone();
                    move || MaybeFatalOrSuccessTransition::NoResults(current_state.clone())
                }),
                expected_result: ExpectedResult::<
                    OptionalTransitionOutcome<(), InMemoryTestState>,
                    PersistedError<InMemoryTestError, std::convert::Infallible>,
                > {
                    events: vec![],
                    is_closed: false,
                    error: None,
                    success: Some(OptionalTransitionOutcome::Stasis(current_state.clone())),
                },
            },
            TestCase {
                make_transition: Box::new({
                    let error_event = error_event.clone();
                    move || {
                        MaybeFatalOrSuccessTransition::fatal(
                            error_event.clone(),
                            InMemoryTestError {},
                        )
                    }
                }),
                expected_result: ExpectedResult {
                    events: vec![error_event.clone()],
                    is_closed: true,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Fatal(InMemoryTestError {})).into(),
                    ),
                    success: None,
                },
            },
            TestCase {
                make_transition: Box::new(|| {
                    MaybeFatalOrSuccessTransition::transient(InMemoryTestError {})
                }),
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Transient(InMemoryTestError {}))
                            .into(),
                    ),
                    success: None,
                },
            },
        ];

        run_test_cases!(test_cases);
    }

    #[test]
    fn test_persisted_error_helpers() {
        let api_err = InMemoryTestError {};

        let storage_error = PersistedError::<InMemoryTestError, InMemoryTestError>(
            InternalPersistedError::Storage(InMemoryTestError {}),
        );
        assert!(storage_error.storage_error_ref().is_some());
        assert!(storage_error.api_error_ref().is_none());

        let fatal_error = PersistedError::<InMemoryTestError, InMemoryTestError>(
            InternalPersistedError::Api(ApiError::Fatal(api_err.clone())),
        );
        assert!(fatal_error.storage_error_ref().is_none());
        assert!(fatal_error.api_error_ref().is_some());

        let transient_error = PersistedError::<InMemoryTestError, InMemoryTestError>(
            InternalPersistedError::Api(ApiError::Transient(api_err.clone())),
        );
        assert!(transient_error.storage_error_ref().is_none());
        assert!(transient_error.api_error_ref().is_some());
    }
}

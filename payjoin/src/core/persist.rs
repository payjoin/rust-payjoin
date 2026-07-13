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
//!
//! # Transient errors and typestate linearity
//!
//! State transitions consume the current typestate, and exactly one live
//! handle exists at any point: a successful transition returns the next
//! state, a transient rejection returns ownership of the current state
//! inside the error so the caller can retry in place, and a fatal rejection
//! closes the session. Transient rejections persist nothing, so replaying
//! the event log always reconstructs the same current state that the error
//! carries.

use std::fmt;

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
#[must_use = "a transition must be persisted with .save() to advance the session"]
#[allow(clippy::type_complexity)]
pub struct MaybeSuccessTransitionWithNoResults<Event, SuccessValue, CurrentState, Err>(
    Result<
        AcceptOptionalTransition<Event, SuccessValue, CurrentState>,
        Rejection<Event, Err, (), CurrentState>,
    >,
);

impl<Event, SuccessValue, CurrentState, Err>
    MaybeSuccessTransitionWithNoResults<Event, SuccessValue, CurrentState, Err>
where
    Err: std::error::Error,
    CurrentState: fmt::Debug,
{
    pub(crate) fn fatal(event: Event, error: Err) -> Self {
        MaybeSuccessTransitionWithNoResults(Err(Rejection::fatal(event, error)))
    }

    pub(crate) fn transient(error: Err, current_state: CurrentState) -> Self {
        MaybeSuccessTransitionWithNoResults(Err(Rejection::transient(error, current_state)))
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
    pub(crate) fn deconstruct(
        self,
    ) -> (
        PersistActions<Event>,
        Result<
            OptionalTransitionOutcome<SuccessValue, CurrentState>,
            ApiError<Err, (), CurrentState>,
        >,
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
            Err(Rejection::Transient(RejectTransient(error, current_state))) =>
                (PersistActions::NoOp, Err(ApiError::Transient(error, current_state))),
            Err(Rejection::ReplyableError(RejectReplyableError(event, _, error))) =>
                (PersistActions::Save(event), Err(ApiError::Fatal(error))),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<
        OptionalTransitionOutcome<SuccessValue, CurrentState>,
        PersistedError<Err, P::InternalStorageError, (), CurrentState>,
    >
    where
        P: SessionPersister<SessionEvent = Event>,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute(persister).map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
    }

    #[allow(clippy::type_complexity)]
    pub async fn save_async<P>(
        self,
        persister: &P,
    ) -> Result<
        OptionalTransitionOutcome<SuccessValue, CurrentState>,
        PersistedError<Err, P::InternalStorageError, (), CurrentState>,
    >
    where
        P: AsyncSessionPersister<SessionEvent = Event>,
        Err: Send,
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
#[must_use = "a transition must be persisted with .save() to advance the session"]
#[allow(clippy::type_complexity)]
pub struct MaybeFatalTransitionWithNoResults<Event, NextState, CurrentState, Err>(
    Result<
        AcceptOptionalTransition<Event, NextState, CurrentState>,
        Rejection<Event, Err, (), CurrentState>,
    >,
);

impl<Event, NextState, CurrentState, Err>
    MaybeFatalTransitionWithNoResults<Event, NextState, CurrentState, Err>
where
    Err: std::error::Error,
    CurrentState: fmt::Debug,
{
    pub(crate) fn fatal(event: Event, error: Err) -> Self {
        MaybeFatalTransitionWithNoResults(Err(Rejection::fatal(event, error)))
    }

    pub(crate) fn no_results(current_state: CurrentState) -> Self {
        MaybeFatalTransitionWithNoResults(Ok(AcceptOptionalTransition::NoResults(current_state)))
    }

    pub(crate) fn transient(error: Err, current_state: CurrentState) -> Self {
        MaybeFatalTransitionWithNoResults(Err(Rejection::transient(error, current_state)))
    }

    pub(crate) fn success(event: Event, next_state: NextState) -> Self {
        MaybeFatalTransitionWithNoResults(Ok(AcceptOptionalTransition::Success(AcceptNextState(
            event, next_state,
        ))))
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn deconstruct(
        self,
    ) -> (
        PersistActions<Event>,
        Result<OptionalTransitionOutcome<NextState, CurrentState>, ApiError<Err, (), CurrentState>>,
    ) {
        match self.0 {
            Ok(AcceptOptionalTransition::Success(AcceptNextState(event, next_state))) =>
                (PersistActions::Save(event), Ok(OptionalTransitionOutcome::Progress(next_state))),
            Ok(AcceptOptionalTransition::NoResults(current_state)) =>
                (PersistActions::NoOp, Ok(OptionalTransitionOutcome::Stasis(current_state))),
            Err(Rejection::Fatal(RejectFatal(event, error))) =>
                (PersistActions::SaveAndClose(event), Err(ApiError::Fatal(error))),
            Err(Rejection::Transient(RejectTransient(error, current_state))) =>
                (PersistActions::NoOp, Err(ApiError::Transient(error, current_state))),
            Err(Rejection::ReplyableError(RejectReplyableError(event, _, error))) =>
                (PersistActions::Save(event), Err(ApiError::Fatal(error))),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<
        OptionalTransitionOutcome<NextState, CurrentState>,
        PersistedError<Err, P::InternalStorageError, (), CurrentState>,
    >
    where
        P: SessionPersister<SessionEvent = Event>,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute(persister).map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
    }

    #[allow(clippy::type_complexity)]
    pub async fn save_async<P>(
        self,
        persister: &P,
    ) -> Result<
        OptionalTransitionOutcome<NextState, CurrentState>,
        PersistedError<Err, P::InternalStorageError, (), CurrentState>,
    >
    where
        P: AsyncSessionPersister<SessionEvent = Event>,
        Err: Send,
        NextState: Send,
        CurrentState: Send,
        Event: Send,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute_async(persister).await.map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
    }
}

pub(crate) type FatalTransitionResult<Event, NextState, Err, ErrorState, CurrentState> =
    Result<AcceptNextState<Event, NextState>, Rejection<Event, Err, ErrorState, CurrentState>>;

/// A transition that can be either fatal, transient, or a state transition.
#[must_use = "a transition must be persisted with .save() to advance the session"]
pub struct MaybeFatalTransition<Event, NextState, Err, ErrorState = (), CurrentState = ()>(
    pub(crate) FatalTransitionResult<Event, NextState, Err, ErrorState, CurrentState>,
);

impl<Event, NextState, Err, ErrorState, CurrentState>
    MaybeFatalTransition<Event, NextState, Err, ErrorState, CurrentState>
where
    Err: std::error::Error,
    ErrorState: fmt::Debug,
    CurrentState: fmt::Debug,
{
    pub(crate) fn fatal(event: Event, error: Err) -> Self {
        MaybeFatalTransition(Err(Rejection::fatal(event, error)))
    }

    pub(crate) fn transient(error: Err, current_state: CurrentState) -> Self {
        MaybeFatalTransition(Err(Rejection::transient(error, current_state)))
    }

    pub(crate) fn success(event: Event, next_state: NextState) -> Self {
        MaybeFatalTransition(Ok(AcceptNextState(event, next_state)))
    }

    pub(crate) fn replyable_error(event: Event, error_state: ErrorState, error: Err) -> Self {
        MaybeFatalTransition(Err(Rejection::replyable_error(event, error_state, error)))
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn deconstruct(
        self,
    ) -> (PersistActions<Event>, Result<NextState, ApiError<Err, ErrorState, CurrentState>>) {
        match self.0 {
            Ok(AcceptNextState(event, next_state)) => (PersistActions::Save(event), Ok(next_state)),
            Err(Rejection::Fatal(RejectFatal(event, error))) =>
                (PersistActions::SaveAndClose(event), Err(ApiError::Fatal(error))),
            Err(Rejection::Transient(RejectTransient(error, current_state))) =>
                (PersistActions::NoOp, Err(ApiError::Transient(error, current_state))),
            Err(Rejection::ReplyableError(RejectReplyableError(event, error_state, error))) =>
                (PersistActions::Save(event), Err(ApiError::FatalWithState(error, error_state))),
        }
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<NextState, PersistedError<Err, P::InternalStorageError, ErrorState, CurrentState>>
    where
        P: SessionPersister<SessionEvent = Event>,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute(persister).map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
    }

    pub async fn save_async<P>(
        self,
        persister: &P,
    ) -> Result<NextState, PersistedError<Err, P::InternalStorageError, ErrorState, CurrentState>>
    where
        P: AsyncSessionPersister<SessionEvent = Event>,
        Err: Send,
        ErrorState: Send,
        CurrentState: Send,
        NextState: Send,
        Event: Send,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute_async(persister).await.map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
    }
}

/// A transition that can result in a state transition or a transient error.
/// Fatal errors cannot occur in this transition.
#[must_use = "a transition must be persisted with .save() to advance the session"]
pub struct MaybeTransientTransition<Event, NextState, Err, CurrentState = ()>(
    Result<AcceptNextState<Event, NextState>, RejectTransient<Err, CurrentState>>,
);

impl<Event, NextState, Err, CurrentState>
    MaybeTransientTransition<Event, NextState, Err, CurrentState>
where
    Err: std::error::Error,
    CurrentState: fmt::Debug,
{
    pub(crate) fn success(event: Event, next_state: NextState) -> Self {
        MaybeTransientTransition(Ok(AcceptNextState(event, next_state)))
    }

    pub(crate) fn transient(error: Err, current_state: CurrentState) -> Self {
        MaybeTransientTransition(Err(RejectTransient(error, current_state)))
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn deconstruct(
        self,
    ) -> (PersistActions<Event>, Result<NextState, ApiError<Err, (), CurrentState>>) {
        match self.0 {
            Ok(AcceptNextState(event, next_state)) => (PersistActions::Save(event), Ok(next_state)),
            Err(RejectTransient(error, current_state)) =>
                (PersistActions::NoOp, Err(ApiError::Transient(error, current_state))),
        }
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<NextState, PersistedError<Err, P::InternalStorageError, (), CurrentState>>
    where
        P: SessionPersister<SessionEvent = Event>,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute(persister).map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
    }

    pub async fn save_async<P>(
        self,
        persister: &P,
    ) -> Result<NextState, PersistedError<Err, P::InternalStorageError, (), CurrentState>>
    where
        P: AsyncSessionPersister<SessionEvent = Event>,
        Err: Send,
        CurrentState: Send,
        NextState: Send,
        Event: Send,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute_async(persister).await.map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
    }
}

/// A transition that always results in a state transition.
#[must_use = "a transition must be persisted with .save() to advance the session"]
pub struct NextStateTransition<Event, NextState>(AcceptNextState<Event, NextState>);

impl<Event, NextState> NextStateTransition<Event, NextState> {
    pub(crate) fn success(event: Event, next_state: NextState) -> Self {
        NextStateTransition(AcceptNextState(event, next_state))
    }

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

/// A transition that either advances to a live state or terminates the session.
///
/// No error path exists. Both outcomes are successful from the protocol's point
/// of view. The choice is determined by the source typestate's internal data,
/// not by the caller.
#[must_use = "a transition must be persisted with .save() to advance the session"]
pub struct MaybeTerminalTransition<Event, NextState>(MaybeTerminalOutcome<Event, NextState>);

impl<Event, NextState> MaybeTerminalTransition<Event, NextState> {
    pub(crate) fn advance(event: Event, next_state: NextState) -> Self {
        Self(MaybeTerminalOutcome::Advance(AcceptNextState(event, next_state)))
    }

    pub(crate) fn terminate(event: Event) -> Self { Self(MaybeTerminalOutcome::Terminate(event)) }

    pub(crate) fn deconstruct(self) -> (PersistActions<Event>, Option<NextState>) {
        match self.0 {
            MaybeTerminalOutcome::Advance(AcceptNextState(event, next_state)) =>
                (PersistActions::Save(event), Some(next_state)),
            MaybeTerminalOutcome::Terminate(event) => (PersistActions::SaveAndClose(event), None),
        }
    }

    pub fn save<P>(self, persister: &P) -> Result<Option<NextState>, P::InternalStorageError>
    where
        P: SessionPersister<SessionEvent = Event>,
    {
        let (actions, next_state) = self.deconstruct();
        actions.execute(persister)?;
        Ok(next_state)
    }

    pub async fn save_async<P>(
        self,
        persister: &P,
    ) -> Result<Option<NextState>, P::InternalStorageError>
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

/// A transition that can either advance, terminate, or fail transiently.
///
/// Fatal outcomes still persist an event. When the fatal outcome advances, the
/// saved event keeps the session live for replay while the caller receives the
/// fatal protocol error.
#[must_use = "a transition must be persisted with .save() to advance the session"]
pub struct MaybeTerminalSuccessTransition<Event, NextState, Err, CurrentState = ()>(
    MaybeTerminalSuccessOutcome<Event, NextState, Err, CurrentState>,
);

impl<Event, NextState, Err, CurrentState>
    MaybeTerminalSuccessTransition<Event, NextState, Err, CurrentState>
where
    Err: std::error::Error,
    NextState: fmt::Debug,
    CurrentState: fmt::Debug,
{
    pub(crate) fn advance(event: Event, next_state: NextState) -> Self {
        Self(MaybeTerminalSuccessOutcome::Advance(AcceptNextState(event, next_state)))
    }

    pub(crate) fn terminate(event: Event) -> Self {
        Self(MaybeTerminalSuccessOutcome::Terminate(event))
    }

    pub(crate) fn fatal_advance(event: Event, next_state: NextState, error: Err) -> Self {
        Self(MaybeTerminalSuccessOutcome::FatalAdvance(event, next_state, error))
    }

    pub(crate) fn fatal_terminate(event: Event, error: Err) -> Self {
        Self(MaybeTerminalSuccessOutcome::FatalTerminate(event, error))
    }

    pub(crate) fn transient(error: Err, current_state: CurrentState) -> Self {
        Self(MaybeTerminalSuccessOutcome::Transient(error, current_state))
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn deconstruct(
        self,
    ) -> (PersistActions<Event>, Result<Option<NextState>, ApiError<Err, NextState, CurrentState>>)
    {
        match self.0 {
            MaybeTerminalSuccessOutcome::Advance(AcceptNextState(event, next_state)) =>
                (PersistActions::Save(event), Ok(Some(next_state))),
            MaybeTerminalSuccessOutcome::Terminate(event) =>
                (PersistActions::SaveAndClose(event), Ok(None)),
            MaybeTerminalSuccessOutcome::FatalAdvance(event, next_state, error) =>
                (PersistActions::Save(event), Err(ApiError::FatalWithState(error, next_state))),
            MaybeTerminalSuccessOutcome::FatalTerminate(event, error) =>
                (PersistActions::SaveAndClose(event), Err(ApiError::Fatal(error))),
            MaybeTerminalSuccessOutcome::Transient(error, current_state) =>
                (PersistActions::NoOp, Err(ApiError::Transient(error, current_state))),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<
        Option<NextState>,
        PersistedError<Err, P::InternalStorageError, NextState, CurrentState>,
    >
    where
        P: SessionPersister<SessionEvent = Event>,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute(persister).map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
    }

    #[allow(clippy::type_complexity)]
    pub async fn save_async<P>(
        self,
        persister: &P,
    ) -> Result<
        Option<NextState>,
        PersistedError<Err, P::InternalStorageError, NextState, CurrentState>,
    >
    where
        P: AsyncSessionPersister<SessionEvent = Event>,
        Err: Send,
        NextState: Send,
        CurrentState: Send,
        Event: Send,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute_async(persister).await.map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
    }
}

/// A transition that unconditionally terminates the session.
///
/// Unlike other transition types, this always succeeds at the protocol level
/// (the only possible error is from the persister's storage layer).
/// After saving, the session is closed and no further events can be appended.
///
/// The `T` parameter carries a value that is returned after saving without
/// being persisted. This lets callers receive derived data (e.g. a fallback
/// transaction) through the same `.save()` call pattern used by every other
/// transition type.
#[must_use = "a transition must be persisted with .save() to advance the session"]
pub struct TerminalTransition<Event, T>(Event, T);

impl<Event, T> TerminalTransition<Event, T> {
    pub(crate) fn new(event: Event, value: T) -> Self { Self(event, value) }

    pub fn save<P>(self, persister: &P) -> Result<T, P::InternalStorageError>
    where
        P: SessionPersister<SessionEvent = Event>,
    {
        PersistActions::SaveAndClose(self.0).execute(persister)?;
        Ok(self.1)
    }

    pub async fn save_async<P>(self, persister: &P) -> Result<T, P::InternalStorageError>
    where
        P: AsyncSessionPersister<SessionEvent = Event>,
        Event: Send,
        T: Send,
    {
        PersistActions::SaveAndClose(self.0).execute_async(persister).await?;
        Ok(self.1)
    }
}

/// A transition that can result in a succession completion, fatal error, or transient error.
/// The transition can also result in no state change.
#[must_use = "a transition must be persisted with .save() to advance the session"]
pub enum MaybeFatalOrSuccessTransition<Event, CurrentState, Err> {
    Success(Event),
    NoResults(CurrentState),
    Transient(RejectTransient<Err, CurrentState>),
    Fatal(RejectFatal<Event, Err>),
}

impl<Event, CurrentState, Err> MaybeFatalOrSuccessTransition<Event, CurrentState, Err>
where
    Err: std::error::Error,
    CurrentState: fmt::Debug,
{
    pub(crate) fn success(event: Event) -> Self { MaybeFatalOrSuccessTransition::Success(event) }

    #[cfg(test)]
    pub(crate) fn fatal(event: Event, error: Err) -> Self {
        MaybeFatalOrSuccessTransition::Fatal(RejectFatal(event, error))
    }

    pub(crate) fn transient(error: Err, current_state: CurrentState) -> Self {
        MaybeFatalOrSuccessTransition::Transient(RejectTransient(error, current_state))
    }

    pub(crate) fn no_results(current_state: CurrentState) -> Self {
        MaybeFatalOrSuccessTransition::NoResults(current_state)
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn deconstruct(
        self,
    ) -> (
        PersistActions<Event>,
        Result<OptionalTransitionOutcome<(), CurrentState>, ApiError<Err, (), CurrentState>>,
    ) {
        match self {
            MaybeFatalOrSuccessTransition::Success(event) =>
                (PersistActions::SaveAndClose(event), Ok(OptionalTransitionOutcome::Progress(()))),
            MaybeFatalOrSuccessTransition::NoResults(current_state) =>
                (PersistActions::NoOp, Ok(OptionalTransitionOutcome::Stasis(current_state))),
            MaybeFatalOrSuccessTransition::Transient(RejectTransient(error, current_state)) =>
                (PersistActions::NoOp, Err(ApiError::Transient(error, current_state))),
            MaybeFatalOrSuccessTransition::Fatal(RejectFatal(event, error)) =>
                (PersistActions::SaveAndClose(event), Err(ApiError::Fatal(error))),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<
        OptionalTransitionOutcome<(), CurrentState>,
        PersistedError<Err, P::InternalStorageError, (), CurrentState>,
    >
    where
        P: SessionPersister<SessionEvent = Event>,
    {
        let (actions, outcome) = self.deconstruct();
        actions.execute(persister).map_err(InternalPersistedError::Storage)?;
        Ok(outcome.map_err(InternalPersistedError::Api)?)
    }

    #[allow(clippy::type_complexity)]
    pub async fn save_async<P>(
        self,
        persister: &P,
    ) -> Result<
        OptionalTransitionOutcome<(), CurrentState>,
        PersistedError<Err, P::InternalStorageError, (), CurrentState>,
    >
    where
        P: AsyncSessionPersister<SessionEvent = Event>,
        Err: Send,
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

enum MaybeTerminalOutcome<Event, NextState> {
    Advance(AcceptNextState<Event, NextState>),
    Terminate(Event),
}

enum MaybeTerminalSuccessOutcome<Event, NextState, Err, CurrentState> {
    Advance(AcceptNextState<Event, NextState>),
    Terminate(Event),
    FatalAdvance(Event, NextState, Err),
    FatalTerminate(Event, Err),
    Transient(Err, CurrentState),
}

/// Wrapper that represents either a successful state transition or indicates no state change occurred
pub enum AcceptOptionalTransition<Event, NextState, CurrentState> {
    /// A state transition that was successful and returned session event to be persisted
    Success(AcceptNextState<Event, NextState>),
    /// A state transition returned no value. Caller should resume from the current state
    NoResults(CurrentState),
}

/// Wrapper representing a fatal or transient rejection of a state transition.
pub enum Rejection<Event, Err, ErrorState = (), CurrentState = ()> {
    Fatal(RejectFatal<Event, Err>),
    Transient(RejectTransient<Err, CurrentState>),
    ReplyableError(RejectReplyableError<Event, ErrorState, Err>),
}

impl<Event, Err, ErrorState, CurrentState> Rejection<Event, Err, ErrorState, CurrentState> {
    pub fn fatal(event: Event, error: Err) -> Self { Rejection::Fatal(RejectFatal(event, error)) }
    pub fn transient(error: Err, current_state: CurrentState) -> Self {
        Rejection::Transient(RejectTransient(error, current_state))
    }
    pub fn replyable_error(event: Event, error_state: ErrorState, error: Err) -> Self {
        Rejection::ReplyableError(RejectReplyableError(event, error_state, error))
    }
}

/// Represents a fatal rejection of a state transition.
/// When this error occurs, the session must be closed and cannot be resumed.
pub struct RejectFatal<Event, Err>(pub(crate) Event, pub(crate) Err);
/// Represents a transient rejection of a state transition.
/// When this error occurs, nothing is persisted and the session should resume
/// from the current state, which is carried alongside the error so the caller
/// can retry in place.
pub struct RejectTransient<Err, CurrentState = ()>(pub(crate) Err, pub(crate) CurrentState);
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

impl<Err: std::error::Error, CurrentState> fmt::Display for RejectTransient<Err, CurrentState> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let RejectTransient(err, _) = self;
        write!(f, "{err}")
    }
}

/// Error type that represents all possible errors that can be returned when processing a state transition
#[derive(Debug)]
pub struct PersistedError<
    ApiError: std::error::Error,
    StorageError: std::error::Error,
    ErrorState: fmt::Debug = (),
    CurrentState: fmt::Debug = (),
>(InternalPersistedError<ApiError, StorageError, ErrorState, CurrentState>);

impl<ApiErr, StorageErr, ErrorState, CurrentState>
    PersistedError<ApiErr, StorageErr, ErrorState, CurrentState>
where
    StorageErr: std::error::Error,
    ApiErr: std::error::Error,
    ErrorState: fmt::Debug,
    CurrentState: fmt::Debug,
{
    #[allow(dead_code)]
    pub fn storage_error(self) -> Option<StorageErr> {
        match self.0 {
            InternalPersistedError::Storage(e) => Some(e),
            _ => None,
        }
    }

    /// The protocol error that rejected the transition, regardless of whether
    /// it was transient or fatal.
    ///
    /// On a transient error this drops the current state carried by the
    /// error; use [`Self::transient_state`] to recover it instead.
    pub fn api_error(self) -> Option<ApiErr> {
        match self.0 {
            InternalPersistedError::Api(
                ApiError::Fatal(e) | ApiError::Transient(e, _) | ApiError::FatalWithState(e, _),
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
                ApiError::Fatal(e) | ApiError::Transient(e, _) | ApiError::FatalWithState(e, _),
            ) => Some(e),
            _ => None,
        }
    }

    pub fn fatal_state(self) -> Option<ErrorState> {
        match self.0 {
            InternalPersistedError::Api(ApiError::FatalWithState(_, state)) => Some(state),
            _ => None,
        }
    }

    /// The typestate to retry from after a transient rejection.
    ///
    /// Transient rejections persist nothing, so the returned state is exactly
    /// the state the failed transition was called on: retry by calling the
    /// same transition on it again. Returns `None` for fatal and storage
    /// errors. A storage error means the transition outcome is unknown, and
    /// recovery is replaying the event log rather than retrying in memory.
    pub fn transient_state(self) -> Option<CurrentState> {
        match self.0 {
            InternalPersistedError::Api(ApiError::Transient(_, state)) => Some(state),
            _ => None,
        }
    }

    /// True if the transition was rejected transiently: nothing was
    /// persisted, and the session can be retried in place from the state
    /// returned by [`Self::transient_state`].
    pub fn is_transient(&self) -> bool {
        matches!(self.0, InternalPersistedError::Api(ApiError::Transient(..)))
    }

    /// True if the transition failed fatally: an event was persisted, and
    /// the session is closed or has moved to an error state (see
    /// [`Self::fatal_state`]).
    ///
    /// Storage errors are neither transient nor fatal. They mean the
    /// transition outcome is unknown, and recovery is replaying the event
    /// log; detect them with [`Self::storage_error_ref`].
    pub fn is_fatal(&self) -> bool {
        matches!(
            self.0,
            InternalPersistedError::Api(ApiError::Fatal(_) | ApiError::FatalWithState(..))
        )
    }
}

impl<
        ApiError: std::error::Error,
        StorageError: std::error::Error,
        ErrorState: fmt::Debug,
        CurrentState: fmt::Debug,
    > From<InternalPersistedError<ApiError, StorageError, ErrorState, CurrentState>>
    for PersistedError<ApiError, StorageError, ErrorState, CurrentState>
{
    fn from(
        value: InternalPersistedError<ApiError, StorageError, ErrorState, CurrentState>,
    ) -> Self {
        PersistedError(value)
    }
}

impl<
        ApiError: std::error::Error,
        StorageError: std::error::Error,
        ErrorState: fmt::Debug,
        CurrentState: fmt::Debug,
    > std::error::Error for PersistedError<ApiError, StorageError, ErrorState, CurrentState>
{
}

impl<
        ApiErr: std::error::Error,
        StorageError: std::error::Error,
        ErrorState: fmt::Debug,
        CurrentState: fmt::Debug,
    > fmt::Display for PersistedError<ApiErr, StorageError, ErrorState, CurrentState>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            InternalPersistedError::Api(ApiError::Transient(err, _)) =>
                write!(f, "Transient error: {err}"),
            InternalPersistedError::Api(
                ApiError::Fatal(err) | ApiError::FatalWithState(err, _),
            ) => write!(f, "Fatal error: {err}"),
            InternalPersistedError::Storage(err) => write!(f, "Storage error: {err}"),
        }
    }
}

#[derive(Debug)]
pub(crate) enum ApiError<Err, ErrorState = (), CurrentState = ()> {
    /// Error indicating that the session should be retried from the same state,
    /// which is returned alongside the error
    Transient(Err, CurrentState),
    /// Error indicating that the session is terminally closed
    Fatal(Err),
    /// Fatal error that results in a state transition to ErrorState
    FatalWithState(Err, ErrorState),
}

#[derive(Debug)]
pub(crate) enum InternalPersistedError<ApiErr, StorageErr, ErrorState = (), CurrentState = ()>
where
    ApiErr: std::error::Error,
    StorageErr: std::error::Error,
    ErrorState: fmt::Debug,
    CurrentState: fmt::Debug,
{
    /// Error indicating that the session failed to progress to the next success state.
    Api(ApiError<ApiErr, ErrorState, CurrentState>),
    /// Error indicating that application failed to save the session event.
    Storage(StorageErr),
}

impl<Err, StorageErr, ErrorState, CurrentState> From<ApiError<Err, ErrorState, CurrentState>>
    for InternalPersistedError<Err, StorageErr, ErrorState, CurrentState>
where
    Err: std::error::Error,
    StorageErr: std::error::Error,
    ErrorState: fmt::Debug,
    CurrentState: fmt::Debug,
{
    fn from(api: ApiError<Err, ErrorState, CurrentState>) -> Self {
        InternalPersistedError::Api(api)
    }
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

/// Async version of [`SessionPersister`] for use in async contexts.
//
// Methods use `impl Future<...> + Send` instead of `async fn` because `async fn` in traits
// doesn't guarantee the returned future is `Send`. This triggers the `async_fn_in_trait` lint.
// https://doc.rust-lang.org/stable/nightly-rustc/rustc_lint/async_fn_in_trait/static.ASYNC_FN_IN_TRAIT.html
pub trait AsyncSessionPersister: Send + Sync {
    /// Errors that may arise from implementers storage layer
    type InternalStorageError: std::error::Error + Send + Sync + 'static;
    /// Session events types that we are persisting
    type SessionEvent: Send;

    /// Appends to list of session updates, Receives generic events
    fn save_event(
        &self,
        event: Self::SessionEvent,
    ) -> impl std::future::Future<Output = Result<(), Self::InternalStorageError>> + Send;

    /// Loads all the events from the session in the same order they were saved
    fn load(
        &self,
    ) -> impl std::future::Future<
        Output = Result<
            Box<dyn Iterator<Item = Self::SessionEvent> + Send>,
            Self::InternalStorageError,
        >,
    > + Send;

    /// Marks the session as closed, no more events will be appended.
    /// This is invoked when the session is terminated due to a fatal error
    /// or when the session is closed due to a success state
    fn close(
        &self,
    ) -> impl std::future::Future<Output = Result<(), Self::InternalStorageError>> + Send;
}

/// In-memory session persister for replaying sessions and introspecting events.
pub struct InMemoryPersister<V> {
    pub(crate) inner: std::sync::Mutex<InnerStorage<V>>,
}

impl<V> Default for InMemoryPersister<V> {
    fn default() -> Self { Self { inner: std::sync::Mutex::new(InnerStorage::default()) } }
}

pub(crate) struct InnerStorage<V> {
    pub(crate) events: Vec<V>,
    pub(crate) is_closed: bool,
}

impl<V> Default for InnerStorage<V> {
    fn default() -> Self { Self { events: vec![], is_closed: false } }
}

impl<V> SessionPersister for InMemoryPersister<V>
where
    V: Clone + 'static,
{
    type InternalStorageError = std::convert::Infallible;
    type SessionEvent = V;

    fn save_event(&self, event: Self::SessionEvent) -> Result<(), Self::InternalStorageError> {
        self.inner.lock().expect("Lock should not be poisoned").events.push(event);
        Ok(())
    }

    fn load(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::InternalStorageError> {
        let events = self.inner.lock().expect("Lock should not be poisoned").events.clone();
        Ok(Box::new(events.into_iter()))
    }

    fn close(&self) -> Result<(), Self::InternalStorageError> {
        self.inner.lock().expect("Lock should not be poisoned").is_closed = true;
        Ok(())
    }
}

#[cfg(test)]
/// Async in-memory session persister for replaying async sessions and introspecting events.
pub struct InMemoryAsyncPersister<V> {
    pub(crate) inner: tokio::sync::Mutex<InnerStorage<V>>,
}

#[cfg(test)]
impl<V> Default for InMemoryAsyncPersister<V> {
    fn default() -> Self { Self { inner: tokio::sync::Mutex::new(InnerStorage::default()) } }
}

#[cfg(test)]
impl<V> AsyncSessionPersister for InMemoryAsyncPersister<V>
where
    V: Clone + Send + Sync + 'static,
{
    type InternalStorageError = std::convert::Infallible;
    type SessionEvent = V;

    async fn save_event(
        &self,
        event: Self::SessionEvent,
    ) -> Result<(), Self::InternalStorageError> {
        self.inner.lock().await.events.push(event);
        Ok(())
    }

    async fn load(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent> + Send>, Self::InternalStorageError>
    {
        let events = self.inner.lock().await.events.clone();
        Ok(Box::new(events.into_iter()))
    }

    async fn close(&self) -> Result<(), Self::InternalStorageError> {
        self.inner.lock().await.is_closed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

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

    fn verify_sync<SuccessState: std::fmt::Debug + PartialEq, ErrorState: std::error::Error>(
        persister: &InMemoryPersister<InMemoryTestEvent>,
        result: Result<SuccessState, ErrorState>,
        expected_result: &ExpectedResult<SuccessState, ErrorState>,
    ) {
        let events = persister.load().expect("Persister should not fail").collect::<Vec<_>>();
        assert_eq!(events.len(), expected_result.events.len());
        for (event, expected_event) in events.iter().zip(expected_result.events.iter()) {
            assert_eq!(event.0, expected_event.0);
        }

        assert_eq!(
            persister.inner.lock().expect("Lock should not be poisoned").is_closed,
            expected_result.is_closed
        );

        match (&result, &expected_result.error) {
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

    async fn verify_async<
        SuccessState: std::fmt::Debug + PartialEq + Send,
        ErrorState: std::error::Error + Send,
    >(
        persister: &InMemoryAsyncPersister<InMemoryTestEvent>,
        result: Result<SuccessState, ErrorState>,
        expected_result: &ExpectedResult<SuccessState, ErrorState>,
    ) {
        let events = persister.load().await.expect("Persister should not fail").collect::<Vec<_>>();
        assert_eq!(events.len(), expected_result.events.len());
        for (event, expected_event) in events.iter().zip(expected_result.events.iter()) {
            assert_eq!(event.0, expected_event.0);
        }

        assert_eq!(persister.inner.lock().await.is_closed, expected_result.is_closed);

        match (&result, &expected_result.error) {
            (Ok(actual), None) => {
                assert_eq!(Some(actual), expected_result.success.as_ref());
            }
            (Err(actual), Some(exp)) => {
                // TODO: replace .to_string() with .eq(). This would introduce a trait bound on the internal API error type
                // And not all internal API errors implement PartialEq
                assert_eq!(actual.to_string(), exp.to_string());
            }
            _ => panic!("Unexpected result state"),
        }
    }

    macro_rules! run_test_cases {
        ($test_cases:expr) => {
            for test in &$test_cases {
                let persister = InMemoryPersister::default();
                let result = (test.make_transition)().save(&persister);
                verify_sync(&persister, result, &test.expected_result);

                let persister = InMemoryAsyncPersister::default();
                let result = (test.make_transition)().save_async(&persister).await;
                verify_async(&persister, result, &test.expected_result).await;
            }
        };
    }

    #[tokio::test]
    async fn test_initial_transition() {
        let event = InMemoryTestEvent("foo".to_string());
        let next_state = "Next state".to_string();

        let test_cases = vec![TestCase {
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
        let current_state = "Current state".to_string();

        let test_cases = vec![
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
                make_transition: Box::new({
                    let current_state = current_state.clone();
                    move || {
                        MaybeTransientTransition::transient(
                            InMemoryTestError {},
                            current_state.clone(),
                        )
                    }
                }),
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Transient(
                            InMemoryTestError {},
                            current_state.clone(),
                        ))
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

        let test_cases = vec![TestCase {
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
    async fn test_maybe_terminal_transition() {
        let event = InMemoryTestEvent("foo".to_string());
        let close_event = InMemoryTestEvent("close".to_string());
        let next_state = "Next state".to_string();

        let test_cases = vec![
            TestCase {
                make_transition: Box::new({
                    let event = event.clone();
                    let next_state = next_state.clone();
                    move || MaybeTerminalTransition::advance(event.clone(), next_state.clone())
                }),
                expected_result: ExpectedResult {
                    events: vec![event.clone()],
                    is_closed: false,
                    error: None,
                    success: Some(Some(next_state.clone())),
                },
            },
            TestCase {
                make_transition: Box::new({
                    let close_event = close_event.clone();
                    move || {
                        MaybeTerminalTransition::<_, InMemoryTestState>::terminate(
                            close_event.clone(),
                        )
                    }
                }),
                expected_result: ExpectedResult {
                    events: vec![close_event.clone()],
                    is_closed: true,
                    error: None,
                    success: Some(None),
                },
            },
        ];

        run_test_cases!(test_cases);
    }

    #[tokio::test]
    async fn test_maybe_terminal_success_transition() {
        let event = InMemoryTestEvent("foo".to_string());
        let close_event = InMemoryTestEvent("close".to_string());
        let fatal_event = InMemoryTestEvent("fatal".to_string());
        let fatal_close_event = InMemoryTestEvent("fatal close".to_string());
        let next_state = "Next state".to_string();

        let test_cases = vec![
            TestCase {
                make_transition: Box::new({
                    let event = event.clone();
                    let next_state = next_state.clone();
                    move || {
                        MaybeTerminalSuccessTransition::advance(event.clone(), next_state.clone())
                    }
                }),
                expected_result: ExpectedResult {
                    events: vec![event.clone()],
                    is_closed: false,
                    error: None,
                    success: Some(Some(next_state.clone())),
                },
            },
            TestCase {
                make_transition: Box::new({
                    let close_event = close_event.clone();
                    move || {
                        MaybeTerminalSuccessTransition::<
                            _,
                            InMemoryTestState,
                            InMemoryTestError,
                            InMemoryTestState,
                        >::terminate(close_event.clone())
                    }
                }),
                expected_result: ExpectedResult {
                    events: vec![close_event.clone()],
                    is_closed: true,
                    error: None,
                    success: Some(None),
                },
            },
            TestCase {
                make_transition: Box::new({
                    let fatal_event = fatal_event.clone();
                    let next_state = next_state.clone();
                    move || {
                        MaybeTerminalSuccessTransition::fatal_advance(
                            fatal_event.clone(),
                            next_state.clone(),
                            InMemoryTestError {},
                        )
                    }
                }),
                expected_result: ExpectedResult {
                    events: vec![fatal_event.clone()],
                    is_closed: false,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Fatal(InMemoryTestError {})).into(),
                    ),
                    success: None,
                },
            },
            TestCase {
                make_transition: Box::new({
                    let fatal_close_event = fatal_close_event.clone();
                    move || {
                        MaybeTerminalSuccessTransition::<
                            _,
                            InMemoryTestState,
                            InMemoryTestError,
                            InMemoryTestState,
                        >::fatal_terminate(
                            fatal_close_event.clone(), InMemoryTestError {}
                        )
                    }
                }),
                expected_result: ExpectedResult {
                    events: vec![fatal_close_event.clone()],
                    is_closed: true,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Fatal(InMemoryTestError {})).into(),
                    ),
                    success: None,
                },
            },
            TestCase {
                make_transition: Box::new({
                    let current_state = "Current state".to_string();
                    move || {
                        MaybeTerminalSuccessTransition::<
                            InMemoryTestEvent,
                            InMemoryTestState,
                            InMemoryTestError,
                            InMemoryTestState,
                        >::transient(
                            InMemoryTestError {}, current_state.clone()
                        )
                    }
                }),
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Transient(
                            InMemoryTestError {},
                            "Current state".to_string(),
                        ))
                        .into(),
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

        let test_cases = vec![
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
                make_transition: Box::new(|| {
                    MaybeFatalTransition::transient(
                        InMemoryTestError {},
                        "Current state".to_string(),
                    )
                }),
                expected_result: ExpectedResult::<
                    _,
                    PersistedError<InMemoryTestError, std::convert::Infallible, (), String>,
                > {
                    events: vec![],
                    is_closed: false,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Transient(
                            InMemoryTestError {},
                            "Current state".to_string(),
                        ))
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

        let test_cases = vec![
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
                    PersistedError<
                        InMemoryTestError,
                        std::convert::Infallible,
                        (),
                        InMemoryTestState,
                    >,
                > {
                    events: vec![],
                    is_closed: false,
                    error: None,
                    success: Some(OptionalTransitionOutcome::Stasis(current_state.clone())),
                },
            },
            TestCase {
                make_transition: Box::new({
                    let current_state = current_state.clone();
                    move || {
                        MaybeSuccessTransitionWithNoResults::transient(
                            InMemoryTestError {},
                            current_state.clone(),
                        )
                    }
                }),
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Transient(
                            InMemoryTestError {},
                            current_state.clone(),
                        ))
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

        let test_cases = vec![
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
                    PersistedError<
                        InMemoryTestError,
                        std::convert::Infallible,
                        (),
                        InMemoryTestState,
                    >,
                > {
                    events: vec![],
                    is_closed: false,
                    error: None,
                    success: Some(OptionalTransitionOutcome::Stasis(current_state.clone())),
                },
            },
            TestCase {
                make_transition: Box::new({
                    let current_state = current_state.clone();
                    move || {
                        MaybeFatalTransitionWithNoResults::transient(
                            InMemoryTestError {},
                            current_state.clone(),
                        )
                    }
                }),
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Transient(
                            InMemoryTestError {},
                            current_state.clone(),
                        ))
                        .into(),
                    ),
                    success: None,
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

        let test_cases = vec![
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
                    PersistedError<
                        InMemoryTestError,
                        std::convert::Infallible,
                        (),
                        InMemoryTestState,
                    >,
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
                make_transition: Box::new({
                    let current_state = current_state.clone();
                    move || {
                        MaybeFatalOrSuccessTransition::transient(
                            InMemoryTestError {},
                            current_state.clone(),
                        )
                    }
                }),
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: Some(
                        InternalPersistedError::Api(ApiError::Transient(
                            InMemoryTestError {},
                            current_state.clone(),
                        ))
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

        // Test Storage error case
        let storage_error = PersistedError::<InMemoryTestError, InMemoryTestError>(
            InternalPersistedError::Storage(InMemoryTestError {}),
        );
        assert!(storage_error.storage_error_ref().is_some());
        assert!(storage_error.api_error_ref().is_none());
        assert!(!storage_error.is_transient());
        assert!(!storage_error.is_fatal());
        assert_eq!(storage_error.transient_state(), None);

        // Test Internal API error cases
        let fatal_error = PersistedError::<InMemoryTestError, InMemoryTestError>(
            InternalPersistedError::Api(ApiError::Fatal(api_err.clone())),
        );
        assert!(fatal_error.storage_error_ref().is_none());
        assert!(fatal_error.api_error_ref().is_some());
        assert!(!fatal_error.is_transient());
        assert!(fatal_error.is_fatal());
        assert_eq!(fatal_error.transient_state(), None);

        let fatal_with_state_error = PersistedError::<InMemoryTestError, InMemoryTestError, String>(
            InternalPersistedError::Api(ApiError::FatalWithState(
                api_err.clone(),
                "Error state".to_string(),
            )),
        );
        assert!(fatal_with_state_error.storage_error_ref().is_none());
        assert!(fatal_with_state_error.api_error_ref().is_some());
        assert!(!fatal_with_state_error.is_transient());
        assert!(fatal_with_state_error.is_fatal());
        assert_eq!(fatal_with_state_error.fatal_state(), Some("Error state".to_string()));

        let transient_error = PersistedError::<InMemoryTestError, InMemoryTestError, (), String>(
            InternalPersistedError::Api(ApiError::Transient(
                api_err.clone(),
                "Current state".to_string(),
            )),
        );
        assert!(transient_error.storage_error_ref().is_none());
        assert!(transient_error.api_error_ref().is_some());
        assert!(transient_error.is_transient());
        assert!(!transient_error.is_fatal());
        assert_eq!(transient_error.transient_state(), Some("Current state".to_string()));
    }
}

use crate::receive::v2::ReceiverSessionEvent;
use crate::send::v2::SenderSessionEvent;

/// Notes
/// Schema:
/// Current State -> state transition function ->  Next state: Possible transitions
///
/// Uninit -> create_session() -> WithContext : Accept(next_state) | Reject(BadInitInputs)
/// With Context -> process_res() -> UncheckedProposal : Accept(next_state) | Accept(NoResults) | Reject(Fatal) | Reject(Transient) // Transient bc OHTTP decap failure or directory failures. Fatal bc the senders message was invalid or malformed. Question: if errors get posted back to directory and its implicit that there is retry are there any fatal errors?
/// UncheckedProposal -> check_broadcast_suitability() -> Receiver<MaybeInputsOwned> : Accept(next_state) | Reject(Fatal) | Reject(Transient)
/// MaybeInputsOwned -> check_inputs() -> MaybeInputsSeen : Accept(next_state) | Reject(Fatal) | Reject(Transient) // If you own inputs -> Fatal. Otherwise implementation error should be treated as transient
/// MaybeInputsSeen -> check_no_inputs_seen() -> OutputsUnknown : Accept(next_state) | Reject(Fatal) | Reject(Transient) // Same reasoning as above
/// OutputsUnknown -> identify_receiver_outputs() -> WantsOutputs : Accept(next_state) | Reject(Fatal) | Reject(Transient) // Same reasoning as above
/// WantsOutputs -> CommitOutputs() -> WantsInputs: Accept(next_state) // substiute outputs could fail and its a loop to the same state. But these are programmer errors, probably don't need to persist these events
/// WantsInputs -> commit_inputs() -> ProvisionalProposal : Accept(next_state) // Same reasoning as above
/// ProvisionalProposal -> finalize_proposal() -> PayjoinProposal : Accept(next_state) | Reject(Transient) // Same reasoning as above
/// PayjoinProposal -> process_res() -> () : Success | Reject(Transient) | // Transient bc OHTTP decap could fail or the directory is malfuctioning
///
/// Has fatal errors: process_res(), check_broadcast_suitability(), check_inputs(), check_no_inputs_seen(), identify_receiver_outputs(), finalize_proposal()
///
/// Note: once you have validate all possible byzantine inputs then you shouldnt have fatal errors, only transient errors
/// RejectionType: INfallible, Transient, Fatal
/// Fatal should mean: we record a reason why and close the session
///

/// The Ok branch always contains the Accepted tuple.
/// This contains 1 or more (maybe exactly one?) events
/// and the Receiver with the state transition applied to it
/// as private fields
/// Event is the session event type
/// NextState is the new state type
///

/// A transition that can be either fatal or transient or have no results.
/// If success it must have a next state and an event to save

/// A transition that can result in a state transition, fatal error, transient error, or successfully have no results.
pub struct MaybeFatalTransitionWithNoResults<Event, NextState, CurrentState, Err>(
    Result<
        AcceptWithMaybeNoResults<Event, NextState, CurrentState>,
        MaybeFatalRejection<Event, Err>,
    >,
);

impl<Event, NextState, CurrentState, Err>
    MaybeFatalTransitionWithNoResults<Event, NextState, CurrentState, Err>
{
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn fatal(event: Event, error: Err) -> Self {
        MaybeFatalTransitionWithNoResults(Err(MaybeFatalRejection::fatal(event, error)))
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn transient(error: Err) -> Self {
        MaybeFatalTransitionWithNoResults(Err(MaybeFatalRejection::transient(error)))
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn no_results(current_state: CurrentState) -> Self {
        MaybeFatalTransitionWithNoResults(Ok(AcceptWithMaybeNoResults::NoResults(current_state)))
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn success(event: Event, next_state: NextState) -> Self {
        MaybeFatalTransitionWithNoResults(Ok(AcceptWithMaybeNoResults::Success(AcceptNextState(
            event, next_state,
        ))))
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<
        PersistedSucccessWithMaybeNoResults<NextState, CurrentState>,
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
pub struct MaybeFatalTransition<Event, NextState, Err>(
    Result<AcceptNextState<Event, NextState>, MaybeFatalRejection<Event, Err>>,
);

impl<Event, NextState, Err> MaybeFatalTransition<Event, NextState, Err> {
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn fatal(event: Event, error: Err) -> Self {
        MaybeFatalTransition(Err(MaybeFatalRejection::fatal(event, error)))
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn transient(error: Err) -> Self {
        MaybeFatalTransition(Err(MaybeFatalRejection::transient(error)))
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn success(event: Event, next_state: NextState) -> Self {
        MaybeFatalTransition(Ok(AcceptNextState(event, next_state)))
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<NextState, PersistedError<Err, P::InternalStorageError>>
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
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn success(event: Event, next_state: NextState) -> Self {
        MaybeTransientTransition(Ok(AcceptNextState(event, next_state)))
    }

    #[inline]
    #[allow(dead_code)]
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
/// If success there are no events to save or a next state.
/// Fatal errors cannot occur in this transition.
pub struct MaybeSuccessTransition<SuccessValue, Err>(
    Result<AcceptCompleted<SuccessValue>, RejectTransient<Err>>,
);

impl<SuccessValue, Err> MaybeSuccessTransition<SuccessValue, Err>
where
    Err: std::error::Error,
{
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn success(success_value: SuccessValue) -> Self {
        MaybeSuccessTransition(Ok(AcceptCompleted(success_value)))
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn transient(error: Err) -> Self {
        MaybeSuccessTransition(Err(RejectTransient(error)))
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<SuccessValue, PersistedError<Err, P::InternalStorageError>>
    where
        P: SessionPersister,
    {
        persister.save_maybe_success_transition(self)
    }
}

/// A transition that always results in a state transition.
pub struct NextStateTransition<Event, NextState>(AcceptNextState<Event, NextState>);

impl<Event, NextState> NextStateTransition<Event, NextState> {
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn success(event: Event, next_state: NextState) -> Self {
        NextStateTransition(AcceptNextState(event, next_state))
    }

    pub fn save<P>(self, persister: &P) -> Result<NextState, StorageError<P::InternalStorageError>>
    where
        P: SessionPersister<SessionEvent = Event>,
    {
        persister.save_progression_transition(self)
    }
}

/// A transition that can result in a state transition or a bad init inputs error.
/// This is a special case because the session should not exist at this point.
/// the state machine initial inputs are not valid. The only thing we can do is reject the session.
pub struct MaybeBadInitInputsTransition<Event, NextState, Err>(
    Result<AcceptNextState<Event, NextState>, RejectBadInitInputs<Err>>,
);

impl<Event, NextState, Err> MaybeBadInitInputsTransition<Event, NextState, Err> {
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn success(event: Event, next_state: NextState) -> Self {
        MaybeBadInitInputsTransition(Ok(AcceptNextState(event, next_state)))
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn bad_init_inputs(error: Err) -> Self {
        MaybeBadInitInputsTransition(Err(RejectBadInitInputs(error)))
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<NextState, PersistedError<Err, P::InternalStorageError>>
    where
        P: SessionPersister<SessionEvent = Event>,
        Err: std::error::Error,
    {
        persister.save_maybe_bad_init_inputs(self)
    }
}

/// Wrapper that marks the progression of a state machine
pub struct AcceptNextState<Event, NextState>(Event, NextState);
/// Wrapper that marks the success of a state machine with a value that was returned
struct AcceptCompleted<SuccessValue>(SuccessValue);

/// Wrapper representing a state transition or no results from calling a state transition method
pub enum AcceptWithMaybeNoResults<Event, NextState, CurrentState> {
    Success(AcceptNextState<Event, NextState>),
    NoResults(CurrentState),
}

/// Wrapper representing a fatal error or a transient error
pub enum MaybeFatalRejection<Event, Err> {
    Fatal(RejectFatal<Event, Err>),
    Transient(RejectTransient<Err>),
}

impl<Event, Err> MaybeFatalRejection<Event, Err> {
    #[inline]
    #[allow(dead_code)]
    pub fn fatal(event: Event, error: Err) -> Self {
        MaybeFatalRejection::Fatal(RejectFatal(event, error))
    }
    #[inline]
    #[allow(dead_code)]
    pub fn transient(error: Err) -> Self { MaybeFatalRejection::Transient(RejectTransient(error)) }
}

/// Wrapper representing a fatal error
pub struct RejectFatal<Event, Err>(Event, Err);
/// Wrapper representing a transient error
pub struct RejectTransient<Err>(Err);
/// Wrapper representing a bad initial inputs to the state machine
pub struct RejectBadInitInputs<Err>(Err);

/// Error type that represents all possible errors that can be returned when processing a state transition
#[derive(Debug, Clone)]
pub struct PersistedError<ApiError: std::error::Error, StorageError: std::error::Error>(
    pub InternalPersistedError<ApiError, StorageError>,
);

impl<ApiError: std::error::Error, StorageError: std::error::Error>
    From<InternalPersistedError<ApiError, StorageError>>
    for PersistedError<ApiError, StorageError>
{
    fn from(value: InternalPersistedError<ApiError, StorageError>) -> Self { PersistedError(value) }
}

impl<ApiError: std::error::Error, StorageError: std::error::Error> std::error::Error
    for PersistedError<ApiError, StorageError>
{
}

impl<ApiError: std::error::Error, StorageError: std::error::Error> std::fmt::Display
    for PersistedError<ApiError, StorageError>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            InternalPersistedError::Transient(err) => write!(f, "Transient error: {err}"),
            InternalPersistedError::Fatal(err) => write!(f, "Fatal error: {err}"),
            InternalPersistedError::BadInitInputs(err) => write!(f, "Bad init inputs error: {err}"),
            InternalPersistedError::Storage(err) => write!(f, "Storage error: {err}"),
        }
    }
}

impl<ApiErr, StorageErr> PersistedError<ApiErr, StorageErr>
where
    StorageErr: std::error::Error,
    ApiErr: std::error::Error,
{
    #[allow(dead_code)]
    pub fn storage_error(self) -> Option<StorageError<StorageErr>> {
        match self.0 {
            InternalPersistedError::Storage(e) => Some(e),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn api_error(self) -> Option<ApiErr> {
        match self.0 {
            InternalPersistedError::Fatal(e)
            | InternalPersistedError::BadInitInputs(e)
            | InternalPersistedError::Transient(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum InternalPersistedError<InternalApiError, StorageErr>
where
    InternalApiError: std::error::Error,
    StorageErr: std::error::Error,
{
    /// Error indicating that the session should be retried from the same state
    Transient(InternalApiError),
    /// Error indicating that the session is terminally closed
    Fatal(InternalApiError),
    /// Error indicating that the session cannot be created because session configurations are invalid
    BadInitInputs(InternalApiError),
    /// Error indicating that application failed to save the session event. This should be treated as a transient error
    /// but is represented as a separate error because this error is propagated from the application's storage layer
    Storage(StorageError<StorageErr>),
}

#[derive(Debug, PartialEq)]
pub enum PersistedSucccessWithMaybeNoResults<NextState, CurrentState> {
    Success(NextState),
    NoResults(CurrentState),
}

impl<NextState, CurrentState> PersistedSucccessWithMaybeNoResults<NextState, CurrentState> {
    pub fn is_none(&self) -> bool {
        matches!(self, PersistedSucccessWithMaybeNoResults::NoResults(_))
    }

    pub fn is_success(&self) -> bool {
        matches!(self, PersistedSucccessWithMaybeNoResults::Success(_))
    }

    pub fn success(&self) -> Option<&NextState> {
        match self {
            PersistedSucccessWithMaybeNoResults::Success(next_state) => Some(next_state),
            PersistedSucccessWithMaybeNoResults::NoResults(_) => None,
        }
    }
}

/// Wrapper representing a storage error that can be returned from an application's storage layer
#[derive(Debug, Clone)]
pub struct StorageError<Err>(Err);

impl<Err> std::error::Error for StorageError<Err> where Err: std::error::Error {}

impl<Err> std::fmt::Display for StorageError<Err>
where
    Err: std::error::Error,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Storage Error: {self:?}")
    }
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
    fn save_event(&self, event: &Self::SessionEvent) -> Result<(), Self::InternalStorageError>;

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
    /// Save state transition where state transition does not return an error
    /// Only returns an error if the storage fails
    fn save_progression_transition<NextState>(
        &self,
        state_transition: NextStateTransition<Self::SessionEvent, NextState>,
    ) -> Result<NextState, StorageError<Self::InternalStorageError>> {
        self.save_event(&state_transition.0 .0).map_err(StorageError)?;
        Ok(state_transition.0 .1)
    }

    /// Save a transition that can be a state transition or a transient error
    fn save_maybe_success_transition<SuccessValue, Err>(
        &self,
        state_transition: MaybeSuccessTransition<SuccessValue, Err>,
    ) -> Result<SuccessValue, PersistedError<Err, Self::InternalStorageError>>
    where
        Err: std::error::Error,
    {
        match state_transition.0 {
            Ok(AcceptCompleted(success_value)) => {
                self.close().map_err(|e| InternalPersistedError::Storage(StorageError(e)))?;
                Ok(success_value)
            }
            Err(RejectTransient(err)) => Err(InternalPersistedError::Transient(err).into()),
        }
    }

    /// Save the first transition of a session
    /// This transition can result in a bad initial inputs error or a state transition
    /// If there is a bad initial inputs error, no events are saved and there is no session to be closed
    /// because the session is not created until the first transition
    fn save_maybe_bad_init_inputs<NextState, Err>(
        &self,
        state_transition: MaybeBadInitInputsTransition<Self::SessionEvent, NextState, Err>,
    ) -> Result<NextState, PersistedError<Err, Self::InternalStorageError>>
    where
        Err: std::error::Error,
    {
        match state_transition.0 {
            Ok(AcceptNextState(event, next_state)) => {
                self.save_event(&event)
                    .map_err(|e| InternalPersistedError::Storage(StorageError(e)))?;
                Ok(next_state)
            }
            Err(RejectBadInitInputs(err)) => Err(InternalPersistedError::BadInitInputs(err).into()),
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
        PersistedSucccessWithMaybeNoResults<NextState, CurrentState>,
        PersistedError<Err, Self::InternalStorageError>,
    >
    where
        Err: std::error::Error,
    {
        match state_transition.0 {
            Ok(AcceptWithMaybeNoResults::Success(AcceptNextState(event, next_state))) => {
                self.save_event(&event)
                    .map_err(|e| InternalPersistedError::Storage(StorageError(e)))?;
                Ok(PersistedSucccessWithMaybeNoResults::Success(next_state))
            }
            Ok(AcceptWithMaybeNoResults::NoResults(current_state)) =>
                Ok(PersistedSucccessWithMaybeNoResults::NoResults(current_state)),
            Err(MaybeFatalRejection::Fatal(fatal_rejection)) => {
                self.handle_fatal_reject(&fatal_rejection)?;
                Err(InternalPersistedError::Fatal(fatal_rejection.1).into())
            }
            Err(MaybeFatalRejection::Transient(RejectTransient(err))) =>
                Err(InternalPersistedError::Transient(err).into()),
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
                self.save_event(&event)
                    .map_err(|e| InternalPersistedError::Storage(StorageError(e)))?;
                Ok(next_state)
            }
            Err(RejectTransient(err)) => Err(InternalPersistedError::Transient(err).into()),
        }
    }

    /// Save a transition that can be a fatal error, transient error or a state transition
    fn save_maybe_fatal_error_transition<NextState, Err>(
        &self,
        state_transition: MaybeFatalTransition<Self::SessionEvent, NextState, Err>,
    ) -> Result<NextState, PersistedError<Err, Self::InternalStorageError>>
    where
        Err: std::error::Error,
    {
        match state_transition.0 {
            Ok(AcceptNextState(event, next_state)) => {
                self.save_event(&event)
                    .map_err(|e| InternalPersistedError::Storage(StorageError(e)))?;
                Ok(next_state)
            }
            Err(e) => {
                match e {
                    MaybeFatalRejection::Fatal(fatal_rejection) => {
                        self.handle_fatal_reject(&fatal_rejection)?;
                        Err(InternalPersistedError::Fatal(fatal_rejection.1).into())
                    }
                    MaybeFatalRejection::Transient(RejectTransient(err)) => {
                        // No event to store for transient errors
                        Err(InternalPersistedError::Transient(err).into())
                    }
                }
            }
        }
    }

    fn handle_fatal_reject<Err>(
        &self,
        fatal_rejection: &RejectFatal<Self::SessionEvent, Err>,
    ) -> Result<(), InternalPersistedError<Err, Self::InternalStorageError>>
    where
        Err: std::error::Error,
    {
        self.save_event(&fatal_rejection.0)
            .map_err(|e| InternalPersistedError::Storage(StorageError(e)))?;
        // Session is in a terminal state, close it
        self.close().map_err(|e| InternalPersistedError::Storage(StorageError(e)))
    }
}

impl<T: SessionPersister> InternalSessionPersister for T {}

/// A persister that does nothing
/// This persister cannot be used to replay a session
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NoopPersisterEvent;

impl From<ReceiverSessionEvent> for NoopPersisterEvent {
    fn from(_event: ReceiverSessionEvent) -> Self { NoopPersisterEvent }
}

impl From<SenderSessionEvent> for NoopPersisterEvent {
    fn from(_event: SenderSessionEvent) -> Self { NoopPersisterEvent }
}

#[cfg(feature = "_multiparty")]
impl From<crate::send::multiparty::SenderSessionEvent> for NoopPersisterEvent {
    fn from(_event: crate::send::multiparty::SenderSessionEvent) -> Self { NoopPersisterEvent }
}

#[derive(Debug, Clone)]
pub struct NoopSessionPersister<E = NoopPersisterEvent>(std::marker::PhantomData<E>);

impl<E> Default for NoopSessionPersister<E> {
    fn default() -> Self { Self(std::marker::PhantomData) }
}

impl<E: 'static> SessionPersister for NoopSessionPersister<E> {
    type InternalStorageError = std::convert::Infallible;
    type SessionEvent = E;

    fn save_event(&self, _event: &Self::SessionEvent) -> Result<(), Self::InternalStorageError> {
        Ok(())
    }

    fn load(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::InternalStorageError> {
        Ok(Box::new(std::iter::empty()))
    }

    fn close(&self) -> Result<(), Self::InternalStorageError> { Ok(()) }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use serde::{Deserialize, Serialize};

    use super::*;

    type InMemoryTestState = String;
    #[derive(Clone, Default)]
    struct InMemoryTestPersister {
        inner: Arc<RwLock<InnerStorage>>,
    }

    #[derive(Clone, Default)]
    struct InnerStorage {
        events: Vec<String>,
        is_closed: bool,
    }

    #[derive(Debug, Clone, PartialEq)]
    /// Dummy error type for testing
    struct InMemoryTestError {}

    impl std::error::Error for InMemoryTestError {}

    impl std::fmt::Display for InMemoryTestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "InMemoryTestError")
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct InMemoryTestEvent(String);
    impl SessionPersister for InMemoryTestPersister {
        type InternalStorageError = std::convert::Infallible;
        type SessionEvent = InMemoryTestEvent;

        fn save_event(&self, event: &Self::SessionEvent) -> Result<(), Self::InternalStorageError> {
            let mut inner = self.inner.write().expect("Lock should not be poisoned");
            inner.events.push(event.0.clone());
            Ok(())
        }

        fn load(
            &self,
        ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::InternalStorageError>
        {
            let inner = self.inner.read().expect("Lock should not be poisoned");
            let events = inner.events.clone();
            Ok(Box::new(events.into_iter().map(InMemoryTestEvent)))
        }

        fn close(&self) -> Result<(), Self::InternalStorageError> {
            let mut inner = self.inner.write().expect("Lock should not be poisoned");
            inner.is_closed = true;
            Ok(())
        }
    }

    struct TestCase<SuccessState, ErrorState> {
        // Allow type complexity for the test closure
        #[allow(clippy::type_complexity)]
        test: Box<dyn Fn(&InMemoryTestPersister) -> Result<SuccessState, ErrorState>>,
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
        persister: &InMemoryTestPersister,
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
    fn test_maybe_bad_init_inputs() {
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
                    MaybeBadInitInputsTransition::success(event.clone(), next_state.clone())
                        .save(persister)
                }),
            },
            // Bad init inputs
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: Some(InternalPersistedError::BadInitInputs(InMemoryTestError {}).into()),
                    success: None,
                },
                test: Box::new(move |persister| {
                    MaybeBadInitInputsTransition::bad_init_inputs(InMemoryTestError {})
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
        let test_cases: Vec<TestCase<InMemoryTestState, StorageError<std::convert::Infallible>>> = vec![
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
        let test_cases: Vec<
            TestCase<(), PersistedError<InMemoryTestError, std::convert::Infallible>>,
        > = vec![
            // Success
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: true,
                    error: None,
                    success: Some(()),
                },
                test: Box::new(move |persister| {
                    MaybeSuccessTransition::success(()).save(persister)
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
    fn test_maybe_fatal_transition_with_no_results() {
        let event = InMemoryTestEvent("foo".to_string());
        let error_event = InMemoryTestEvent("error event".to_string());
        let current_state = "Current state".to_string();
        let next_state = "Next state".to_string();
        let test_cases: Vec<
            TestCase<
                PersistedSucccessWithMaybeNoResults<InMemoryTestState, InMemoryTestState>,
                PersistedError<InMemoryTestError, std::convert::Infallible>,
            >,
        > = vec![
            // Success
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![event.clone()],
                    is_closed: false,
                    error: None,
                    success: Some(PersistedSucccessWithMaybeNoResults::Success(next_state.clone())),
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
                    success: Some(PersistedSucccessWithMaybeNoResults::NoResults(
                        current_state.clone(),
                    )),
                },
                test: Box::new(move |persister| {
                    MaybeFatalTransitionWithNoResults::no_results(current_state.clone())
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
                    MaybeFatalTransitionWithNoResults::transient(InMemoryTestError {})
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
    fn test_persisted_success_with_maybe_no_results_helpers() {
        let next_state = "Next state".to_string();
        let current_state = "Current state".to_string();

        let success =
            PersistedSucccessWithMaybeNoResults::<String, String>::Success(next_state.clone());
        assert!(!success.is_none());
        assert!(success.is_success());
        assert_eq!(success.success(), Some(&next_state));

        let no_results =
            PersistedSucccessWithMaybeNoResults::<String, String>::NoResults(current_state.clone());
        assert!(no_results.is_none());
        assert!(!no_results.is_success());
        assert_eq!(no_results.success(), None);
    }

    #[test]
    fn test_persisted_error_helpers() {
        let storage_err = StorageError(InMemoryTestError {});
        let api_err = InMemoryTestError {};

        // Test Storage error case
        let storage_error = PersistedError::<InMemoryTestError, InMemoryTestError>(
            InternalPersistedError::Storage(storage_err.clone()),
        );
        assert!(storage_error.clone().storage_error().is_some());
        assert!(storage_error.api_error().is_none());

        // Test Internal API error cases
        let fatal_error = PersistedError::<InMemoryTestError, InMemoryTestError>(
            InternalPersistedError::Fatal(api_err.clone()),
        );
        assert!(fatal_error.clone().storage_error().is_none());
        assert!(fatal_error.api_error().is_some());

        let transient_error = PersistedError::<InMemoryTestError, InMemoryTestError>(
            InternalPersistedError::Transient(api_err.clone()),
        );
        assert!(transient_error.clone().storage_error().is_none());
        assert!(transient_error.api_error().is_some());

        let bad_inputs_error = PersistedError::<InMemoryTestError, InMemoryTestError>(
            InternalPersistedError::BadInitInputs(api_err.clone()),
        );
        assert!(bad_inputs_error.clone().storage_error().is_none());
        assert!(bad_inputs_error.api_error().is_some());
    }
}

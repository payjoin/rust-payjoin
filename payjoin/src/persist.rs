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
pub enum MaybeFatalTransitionWithNoResults<Event, NextState, CurrentState, Err> {
    Ok(AcceptWithMaybeNoResults<Event, NextState, CurrentState>),
    Err(MaybeFatalRejection<Event, Err>),
}

impl<Event, NextState, CurrentState, Err>
    MaybeFatalTransitionWithNoResults<Event, NextState, CurrentState, Err>
{
    #[inline]
    pub fn fatal(event: Event, error: Err) -> Self {
        MaybeFatalTransitionWithNoResults::Err(MaybeFatalRejection::fatal(event, error))
    }

    #[inline]
    pub fn transient(error: Err) -> Self {
        MaybeFatalTransitionWithNoResults::Err(MaybeFatalRejection::transient(error))
    }

    #[inline]
    pub fn no_results(current_state: CurrentState) -> Self {
        MaybeFatalTransitionWithNoResults::Ok(AcceptWithMaybeNoResults::NoResults(current_state))
    }

    #[inline]
    pub fn success(event: Event, next_state: NextState) -> Self {
        MaybeFatalTransitionWithNoResults::Ok(AcceptWithMaybeNoResults::Success(AcceptNextState(
            event, next_state,
        )))
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<
        PersistedSucccessWithMaybeNoResults<NextState, CurrentState>,
        PersistedError<Err, P::InternalStorageError>,
    >
    where
        P: PersistedSession<SessionEvent = Event>,
        Err: std::error::Error,
    {
        persister.save_maybe_no_results_transition(self)
    }
}

/// A transition that can be either fatal or transient.
/// If success it must have a next state and an event to save
pub enum MaybeFatalTransition<Event, NextState, Err> {
    Ok(AcceptNextState<Event, NextState>),
    Err(MaybeFatalRejection<Event, Err>),
}

impl<Event, NextState, Err> MaybeFatalTransition<Event, NextState, Err> {
    #[inline]
    pub fn fatal(event: Event, error: Err) -> Self {
        MaybeFatalTransition::Err(MaybeFatalRejection::fatal(event, error))
    }

    #[inline]
    pub fn transient(error: Err) -> Self {
        MaybeFatalTransition::Err(MaybeFatalRejection::transient(error))
    }

    #[inline]
    pub fn success(event: Event, next_state: NextState) -> Self {
        MaybeFatalTransition::Ok(AcceptNextState(event, next_state))
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<NextState, PersistedError<Err, P::InternalStorageError>>
    where
        P: PersistedSession<SessionEvent = Event>,
        Err: std::error::Error,
    {
        persister.save_maybe_fatal_error_transition(self)
    }
}

/// A transition that can be transient.
/// If success it must have a next state and an event to save
pub struct MaybeTransientTransition<Event, NextState, Err>(
    pub(crate) Result<AcceptNextState<Event, NextState>, RejectTransient<Err>>,
);

impl<Event, NextState, Err> From<Result<AcceptNextState<Event, NextState>, RejectTransient<Err>>>
    for MaybeTransientTransition<Event, NextState, Err>
{
    fn from(value: Result<AcceptNextState<Event, NextState>, RejectTransient<Err>>) -> Self {
        MaybeTransientTransition(value)
    }
}

impl<Event, NextState, Err> MaybeTransientTransition<Event, NextState, Err> {
    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<NextState, PersistedError<Err, P::InternalStorageError>>
    where
        P: PersistedSession<SessionEvent = Event>,
        Err: std::error::Error,
    {
        persister.save_maybe_transient_error_transition(self)
    }
}

/// A transition that can be success or transient error
/// If success there are no events to save or next state
/// If transient error we can retry this state transition
pub struct MaybeSuccessTransition<Err>(pub(crate) Result<AcceptCompleted, RejectTransient<Err>>);

impl<Err> From<Result<AcceptCompleted, RejectTransient<Err>>> for MaybeSuccessTransition<Err> {
    fn from(value: Result<AcceptCompleted, RejectTransient<Err>>) -> Self {
        MaybeSuccessTransition(value)
    }
}

impl<Err> MaybeSuccessTransition<Err>
where
    Err: std::error::Error,
{
    pub fn success() -> Self { MaybeSuccessTransition(Ok(AcceptCompleted())) }

    pub fn transient(error: Err) -> Self { MaybeSuccessTransition(Err(RejectTransient(error))) }

    pub fn save<P>(self, persister: &P) -> Result<(), PersistedError<Err, P::InternalStorageError>>
    where
        P: PersistedSession,
    {
        persister.save_maybe_success_transition(self)
    }
}

/// A transition that is always a next state transition
pub struct NextStateTransition<Event, NextState>(pub(crate) AcceptNextState<Event, NextState>);

impl<Event, NextState> From<AcceptNextState<Event, NextState>>
    for NextStateTransition<Event, NextState>
{
    fn from(value: AcceptNextState<Event, NextState>) -> Self { NextStateTransition(value) }
}

impl<Event, NextState> NextStateTransition<Event, NextState> {
    pub fn success(event: Event, next_state: NextState) -> Self {
        NextStateTransition(AcceptNextState(event, next_state))
    }

    pub fn save<P>(self, persister: &P) -> Result<NextState, StorageError<P::InternalStorageError>>
    where
        P: PersistedSession<SessionEvent = Event>,
    {
        persister.save_progression_transition(self)
    }
}

/// A transition that can be success or bad init inputs
/// This is a special case where the state machine init inputs are bad and we can't proceed
/// The only thing we can do is reject the session. Since the session doesnt really exist at this point
/// there is no need to save events or close the session
pub struct MaybeBadInitInputsTransition<Event, NextState, Err>(
    pub(crate) Result<AcceptNextState<Event, NextState>, RejectBadInitInputs<Err>>,
);

impl<Event, NextState, Err>
    From<Result<AcceptNextState<Event, NextState>, RejectBadInitInputs<Err>>>
    for MaybeBadInitInputsTransition<Event, NextState, Err>
{
    fn from(value: Result<AcceptNextState<Event, NextState>, RejectBadInitInputs<Err>>) -> Self {
        MaybeBadInitInputsTransition(value)
    }
}
impl<Event, NextState, Err> MaybeBadInitInputsTransition<Event, NextState, Err> {
    pub fn success(event: Event, next_state: NextState) -> Self {
        MaybeBadInitInputsTransition(Ok(AcceptNextState(event, next_state)))
    }

    pub fn bad_init_inputs(error: Err) -> Self {
        MaybeBadInitInputsTransition(Err(RejectBadInitInputs(error)))
    }

    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<NextState, PersistedError<Err, P::InternalStorageError>>
    where
        P: PersistedSession<SessionEvent = Event>,
        Err: std::error::Error,
    {
        persister.save_maybe_bad_init_inputs(self)
    }
}

/* Accept */
// TODO: should these be pub?
/// A transition that marks the progression of a state machine
pub struct AcceptNextState<Event, NextState>(pub Event, pub NextState);
/// A transition that marks the success of a state machine
pub struct AcceptCompleted();

/// A transition that can be success or no results
pub enum AcceptWithMaybeNoResults<Event, NextState, CurrentState> {
    Success(AcceptNextState<Event, NextState>),
    NoResults(CurrentState),
}

/* Reject */
/// A rejection that can be either fatal or transient
pub enum MaybeFatalRejection<Event, Err> {
    Fatal(RejectFatal<Event, Err>),
    Transient(RejectTransient<Err>),
}

impl<Event, Err> MaybeFatalRejection<Event, Err> {
    #[inline]
    pub fn fatal(event: Event, error: Err) -> Self {
        MaybeFatalRejection::Fatal(RejectFatal(event, error))
    }
    #[inline]
    pub fn transient(error: Err) -> Self { MaybeFatalRejection::Transient(RejectTransient(error)) }
}

pub struct RejectFatal<Event, Err>(pub Event, pub Err);
pub struct RejectTransient<Err>(pub Err);
pub struct RejectBadInitInputs<Err>(pub Err);

/// The Err branch always contains the Rejected triple.
/// This is the same as Accepted except it contains an error.
/// The receiver is kept in the current state.
/// Event is the session event type
/// Err is the error type
/// CurrentState is the current state type
pub enum Rejected<Event, Err> {
    None(),
    Soft(Event, Err),
    Fatal(Event, Err),
}

/// Serializable error types that can be persisted in a session
/// TODO: see if this can be a ext. trait with a blanket impl for all error types
pub trait PersistableError: std::error::Error + ToString {}

// Note: What can API errors actually contain?
// Its bip77 specific errors, and callback errors generated by application
#[derive(Debug)]
pub enum PersistedError<ApiErr, StorageErr>
where
    ApiErr: std::error::Error,
    StorageErr: std::error::Error,
{
    /// Error indicating that the session should be retried from the same state
    Transient(ApiErr),
    /// Error indicating that the session is terminally closed
    Fatal(ApiErr),
    /// Error indicating that the session cannot be created because session configurations are invalid
    BadInitInputs(ApiErr),
    /// Error indicating that application failed to save the session event. This should be treated as a transient error
    Storage(StorageError<StorageErr>),
}

impl<ApiErr, StorageErr> PersistedError<ApiErr, StorageErr>
where
    StorageErr: std::error::Error,
    ApiErr: std::error::Error,
{
    pub fn storage_error(self) -> Option<StorageError<StorageErr>> {
        match self {
            PersistedError::Storage(e) => Some(e),
            _ => None,
        }
    }

    pub fn api_error(self) -> Option<ApiErr> {
        match self {
            PersistedError::Fatal(e)
            | PersistedError::BadInitInputs(e)
            | PersistedError::Transient(e) => Some(e),
            _ => None,
        }
    }
}

impl<ApiErr, StorageErr> std::error::Error for PersistedError<ApiErr, StorageErr>
where
    ApiErr: std::error::Error,
    StorageErr: std::error::Error,
{
}

impl<ApiErr, StorageErr> std::fmt::Display for PersistedError<ApiErr, StorageErr>
where
    ApiErr: std::error::Error,
    StorageErr: std::error::Error,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{:?}", self) }
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

#[derive(Debug)]
pub struct StorageError<Err>(Err);

impl<Err> std::error::Error for StorageError<Err> where Err: std::error::Error {}

impl<Err> std::fmt::Display for StorageError<Err>
where
    Err: std::error::Error,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{:?}", self) }
}

/// A session that can be persisted and loaded from a store
///
/// This is a generic trait that can be implemented for any type that implements `Event`.
///
///
pub trait PersistedSession {
    /// Errors that may arise from implementers storage layer
    type InternalStorageError: std::error::Error + Send + Sync + 'static;
    /// Session events types that we are persisting
    type SessionEvent;

    /// Appends to list of session updates, Receives generic events
    fn save_event(&self, event: &Self::SessionEvent) -> Result<(), Self::InternalStorageError>;

    fn load(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::InternalStorageError>; // Loads the latest session given all updates
                                                                                           // TODO: this should consume self
    fn close(&self) -> Result<(), Self::InternalStorageError>; // Marks the session as closed, no more updates will be appended
}

pub(crate) trait InternalPersistedSession: PersistedSession {
    /// Save progression transition where state transition does not return an error
    /// Only returns an error if the storage fails
    fn save_progression_transition<NextState>(
        &self,
        state_transition: NextStateTransition<Self::SessionEvent, NextState>,
    ) -> Result<NextState, StorageError<Self::InternalStorageError>> {
        self.save_event(&state_transition.0 .0).map_err(|e| StorageError(e))?;
        Ok(state_transition.0 .1)
    }

    /// Save a transition that can be success or transient error
    fn save_maybe_success_transition<Err>(
        &self,
        state_transition: MaybeSuccessTransition<Err>,
    ) -> Result<(), PersistedError<Err, Self::InternalStorageError>>
    where
        Err: std::error::Error,
    {
        match state_transition.0 {
            Ok(AcceptCompleted()) => {
                self.close().map_err(|e| PersistedError::Storage(StorageError(e)))?;
                return Ok(());
            }
            Err(RejectTransient(err)) => Err(PersistedError::Transient(err)),
        }
    }

    fn save_maybe_bad_init_inputs<NextState, Err>(
        &self,
        state_transition: MaybeBadInitInputsTransition<Self::SessionEvent, NextState, Err>,
    ) -> Result<NextState, PersistedError<Err, Self::InternalStorageError>>
    where
        Err: std::error::Error,
    {
        match state_transition.0 {
            Ok(AcceptNextState(event, next_state)) => {
                self.save_event(&event).map_err(|e| PersistedError::Storage(StorageError(e)))?;
                Ok(next_state)
            }
            Err(RejectBadInitInputs(err)) => Err(PersistedError::BadInitInputs(err)),
        }
    }
    /// Save a transition that can be
    /// next state as a success case
    /// Transient error as a error case
    /// Fatal error as a error case
    /// Or no results as a error case
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
        match state_transition {
            MaybeFatalTransitionWithNoResults::Ok(AcceptWithMaybeNoResults::Success(
                AcceptNextState(event, next_state),
            )) => {
                self.save_event(&event).map_err(|e| PersistedError::Storage(StorageError(e)))?;
                Ok(PersistedSucccessWithMaybeNoResults::Success(next_state))
            }
            MaybeFatalTransitionWithNoResults::Ok(AcceptWithMaybeNoResults::NoResults(
                current_state,
            )) => Ok(PersistedSucccessWithMaybeNoResults::NoResults(current_state)),
            MaybeFatalTransitionWithNoResults::Err(MaybeFatalRejection::Fatal(fatal_rejection)) => {
                self.handle_fatal_reject(&fatal_rejection)?;
                Err(PersistedError::Fatal(fatal_rejection.1))
            }
            MaybeFatalTransitionWithNoResults::Err(MaybeFatalRejection::Transient(
                RejectTransient(err),
            )) => Err(PersistedError::Transient(err)),
        }
    }

    /// Save a transition where we either get a next state
    /// or a transient error
    fn save_maybe_transient_error_transition<NextState, Err>(
        &self,
        state_transition: MaybeTransientTransition<Self::SessionEvent, NextState, Err>,
    ) -> Result<NextState, PersistedError<Err, Self::InternalStorageError>>
    where
        Err: std::error::Error,
    {
        match state_transition.0 {
            Ok(AcceptNextState(event, next_state)) => {
                self.save_event(&event).map_err(|e| PersistedError::Storage(StorageError(e)))?;
                Ok(next_state)
            }
            Err(RejectTransient(err)) => {
                // No event to store for transient errors
                Err(PersistedError::Transient(err))
            }
        }
    }

    /// Save a transition where we either get a next state
    /// or a fatal error
    /// or a transient error
    fn save_maybe_fatal_error_transition<NextState, Err>(
        &self,
        state_transition: MaybeFatalTransition<Self::SessionEvent, NextState, Err>,
    ) -> Result<NextState, PersistedError<Err, Self::InternalStorageError>>
    where
        Err: std::error::Error,
    {
        match state_transition {
            MaybeFatalTransition::Ok(AcceptNextState(event, next_state)) => {
                self.save_event(&event).map_err(|e| PersistedError::Storage(StorageError(e)))?;
                Ok(next_state)
            }
            MaybeFatalTransition::Err(e) => {
                match e {
                    MaybeFatalRejection::Fatal(fatal_rejection) => {
                        self.handle_fatal_reject(&fatal_rejection)?;
                        Err(PersistedError::Fatal(fatal_rejection.1))
                    }
                    MaybeFatalRejection::Transient(RejectTransient(err)) => {
                        // No event to store for transient errors
                        Err(PersistedError::Transient(err))
                    }
                }
            }
        }
    }

    /// Save a fatal error event
    /// This will save the event and close the session
    /// This method only exists to reduce code duplication
    fn handle_fatal_reject<Err>(
        &self,
        fatal_rejection: &RejectFatal<Self::SessionEvent, Err>,
    ) -> Result<(), PersistedError<Err, Self::InternalStorageError>>
    where
        Err: std::error::Error,
    {
        self.save_event(&fatal_rejection.0)
            .map_err(|e| PersistedError::Storage(StorageError(e)))?;
        // Nothing to do close session
        self.close().map_err(|e| PersistedError::Storage(StorageError(e)))
    }
}

// Automatically implement the internal trait for anything that implements PersistedSession
impl<T: PersistedSession> InternalPersistedSession for T {}

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
pub struct NoopPersister<E = NoopPersisterEvent>(std::marker::PhantomData<E>);

impl<E> Default for NoopPersister<E> {
    fn default() -> Self { Self(std::marker::PhantomData) }
}

impl<E: 'static> PersistedSession for NoopPersister<E> {
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
    use std::time::UNIX_EPOCH;

    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::receive::v2::ReceiverReplayError;

    type InMemoryTestState = String;
    #[derive(Clone, Default)]
    pub struct InMemoryTestPersister {
        inner: Arc<RwLock<InnerStorage>>,
    }

    #[derive(Clone)]
    struct InnerStorage {
        events: Vec<String>,
        is_closed: bool,
    }
    impl Default for InnerStorage {
        fn default() -> Self { Self { events: Vec::new(), is_closed: false } }
    }
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct InMemoryTestEvent(String);

    impl PersistedSession for InMemoryTestPersister {
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
            Ok(Box::new(events.into_iter().map(|e| InMemoryTestEvent(e))))
        }

        fn close(&self) -> Result<(), Self::InternalStorageError> {
            let mut inner = self.inner.write().expect("Lock should not be poisoned");
            inner.is_closed = true;
            Ok(())
        }
    }

    struct TestCase<SuccessState, ErrorState> {
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
                PersistedError<ReceiverReplayError, std::convert::Infallible>,
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
                    error: Some(PersistedError::BadInitInputs(
                        ReceiverReplayError::SessionExpired(UNIX_EPOCH),
                    )),
                    success: None,
                },
                test: Box::new(move |persister| {
                    MaybeBadInitInputsTransition::bad_init_inputs(
                        ReceiverReplayError::SessionExpired(UNIX_EPOCH),
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
            TestCase<(), PersistedError<ReceiverReplayError, std::convert::Infallible>>,
        > = vec![
            // Success
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: true,
                    error: None,
                    success: Some(()),
                },
                test: Box::new(move |persister| MaybeSuccessTransition::success().save(persister)),
            },
            // Transient error
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![],
                    is_closed: false,
                    error: Some(PersistedError::Transient(ReceiverReplayError::SessionExpired(
                        UNIX_EPOCH,
                    ))),
                    success: None,
                },
                test: Box::new(move |persister| {
                    MaybeSuccessTransition::transient(ReceiverReplayError::SessionExpired(
                        UNIX_EPOCH,
                    ))
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
                PersistedError<ReceiverReplayError, std::convert::Infallible>,
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
                    error: Some(PersistedError::Transient(ReceiverReplayError::SessionExpired(
                        UNIX_EPOCH,
                    ))),
                    success: None,
                },
                test: Box::new(move |persister| {
                    MaybeFatalTransition::transient(ReceiverReplayError::SessionExpired(UNIX_EPOCH))
                        .save(persister)
                }),
            },
            // Fatal error
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![error_event.clone()],
                    is_closed: true,
                    error: Some(PersistedError::Fatal(ReceiverReplayError::SessionExpired(
                        UNIX_EPOCH,
                    ))),
                    success: None,
                },
                test: Box::new(move |persister| {
                    MaybeFatalTransition::fatal(
                        error_event.clone(),
                        ReceiverReplayError::SessionExpired(UNIX_EPOCH),
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
                PersistedSucccessWithMaybeNoResults<InMemoryTestState, InMemoryTestState>,
                PersistedError<ReceiverReplayError, std::convert::Infallible>,
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
                    error: Some(PersistedError::Transient(ReceiverReplayError::SessionExpired(
                        UNIX_EPOCH,
                    ))),
                    success: None,
                },
                test: Box::new(move |persister| {
                    MaybeFatalTransitionWithNoResults::transient(
                        ReceiverReplayError::SessionExpired(UNIX_EPOCH),
                    )
                    .save(persister)
                }),
            },
            // Fatal error
            TestCase {
                expected_result: ExpectedResult {
                    events: vec![error_event.clone()],
                    is_closed: true,
                    error: Some(PersistedError::Fatal(ReceiverReplayError::SessionExpired(
                        UNIX_EPOCH,
                    ))),
                    success: None,
                },
                test: Box::new(move |persister| {
                    MaybeFatalTransitionWithNoResults::fatal(
                        error_event.clone(),
                        ReceiverReplayError::SessionExpired(UNIX_EPOCH),
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
}

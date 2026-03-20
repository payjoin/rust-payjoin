use std::sync::Arc;

use payjoin::bitcoin::psbt::PsbtParseError as CorePsbtParseError;
use payjoin::error::ReplayErrorVariant as CoreReplayErrorVariant;
use payjoin::persist::PersistedErrorVariant;
use payjoin::send;

use crate::error::{
    FfiValidationError, ImplementationError, ReplayErrorKind as FfiReplayErrorKind,
    ReplayInvalidEventKind as FfiReplayInvalidEventKind,
};

/// Error building a Sender from a SenderBuilder.
///
/// This error is unrecoverable.
#[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Object)]
#[error("Error initializing the sender: {msg}")]
pub struct BuildSenderError {
    msg: String,
}

impl From<PsbtParseError> for BuildSenderError {
    fn from(value: PsbtParseError) -> Self { BuildSenderError { msg: value.to_string() } }
}

impl From<send::BuildSenderError> for BuildSenderError {
    fn from(value: send::BuildSenderError) -> Self { BuildSenderError { msg: value.to_string() } }
}

/// FFI-visible PSBT parsing error surfaced at the sender boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PsbtParseError {
    /// The provided PSBT string could not be parsed.
    #[error("Invalid PSBT: {0}")]
    InvalidPsbt(String),
}

impl From<CorePsbtParseError> for PsbtParseError {
    fn from(value: CorePsbtParseError) -> Self { PsbtParseError::InvalidPsbt(value.to_string()) }
}

/// Raised when inputs provided to the sender are malformed or sender build fails.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SenderInputError {
    #[error(transparent)]
    Psbt(PsbtParseError),
    #[error(transparent)]
    Build(Arc<BuildSenderError>),
    #[error(transparent)]
    FfiValidation(FfiValidationError),
}

impl From<FfiValidationError> for SenderInputError {
    fn from(value: FfiValidationError) -> Self { SenderInputError::FfiValidation(value) }
}

/// Error returned when request could not be created.
///
/// This error can currently only happen due to programmer mistake.
/// `unwrap()`ing it is thus considered OK in Rust but you may achieve nicer message by displaying
/// it.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct CreateRequestError(#[from] send::v2::CreateRequestError);

/// Error returned for v2-specific payload encapsulation errors.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct EncapsulationError(#[from] send::v2::EncapsulationError);

/// Error that may occur when the response from receiver is malformed.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct ValidationError(#[from] send::ValidationError);

/// Represent an error returned by Payjoin receiver.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ResponseError {
    /// `WellKnown` Errors are defined in the [`BIP78::ReceiverWellKnownError`] spec.
    ///
    /// It is safe to display `WellKnown` errors to end users.
    ///
    /// [`BIP78::ReceiverWellKnownError`]: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#user-content-Receivers_well_known_errors
    #[error("A receiver error occurred: {0}")]
    WellKnown(Arc<WellKnownError>),

    /// Errors caused by malformed responses.
    #[error("An error occurred due to a malformed response: {0}")]
    Validation(Arc<ValidationError>),

    /// `Unrecognized` Errors are NOT defined in the [`BIP78::ReceiverWellKnownError`] spec.
    ///
    /// It is NOT safe to display `Unrecognized` errors to end users as they could be used
    /// maliciously to phish a non technical user. Only display them in debug logs.
    ///
    /// [`BIP78::ReceiverWellKnownError`]: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#user-content-Receivers_well_known_errors
    #[error("An unrecognized error occurred")]
    Unrecognized { error_code: String, msg: String },
}

impl From<send::ResponseError> for ResponseError {
    fn from(value: send::ResponseError) -> Self {
        match value {
            send::ResponseError::WellKnown(e) => ResponseError::WellKnown(Arc::new(e.into())),
            send::ResponseError::Validation(e) => ResponseError::Validation(Arc::new(e.into())),
            send::ResponseError::Unrecognized { error_code, message } =>
                ResponseError::Unrecognized { error_code, msg: message },
        }
    }
}

/// A well-known error that can be safely displayed to end users.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct WellKnownError(#[from] send::WellKnownError);

/// Error that may occur when the sender session event log is replayed.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("{message}")]
pub struct SenderReplayError {
    kind: FfiReplayErrorKind,
    message: String,
    invalid_event_kind: Option<FfiReplayInvalidEventKind>,
    expired_at_unix_seconds: Option<u32>,
    persistence_failure: Option<Arc<ImplementationError>>,
}

impl From<payjoin::error::ReplayError<send::v2::SendSession, send::v2::SessionEvent>>
    for SenderReplayError
{
    fn from(
        value: payjoin::error::ReplayError<send::v2::SendSession, send::v2::SessionEvent>,
    ) -> Self {
        let message = value.to_string();
        match value.into_variant() {
            CoreReplayErrorVariant::NoEvents => Self {
                kind: FfiReplayErrorKind::NoEvents,
                message,
                invalid_event_kind: None,
                expired_at_unix_seconds: None,
                persistence_failure: None,
            },
            CoreReplayErrorVariant::InvalidFirstEvent => Self {
                kind: FfiReplayErrorKind::InvalidEvent,
                message,
                invalid_event_kind: Some(FfiReplayInvalidEventKind::InitialEvent),
                expired_at_unix_seconds: None,
                persistence_failure: None,
            },
            CoreReplayErrorVariant::InvalidEventForState => Self {
                kind: FfiReplayErrorKind::InvalidEvent,
                message,
                invalid_event_kind: Some(FfiReplayInvalidEventKind::SessionTransition),
                expired_at_unix_seconds: None,
                persistence_failure: None,
            },
            CoreReplayErrorVariant::Expired { expired_at_unix_seconds } => Self {
                kind: FfiReplayErrorKind::Expired,
                message,
                invalid_event_kind: None,
                expired_at_unix_seconds: Some(expired_at_unix_seconds),
                persistence_failure: None,
            },
            CoreReplayErrorVariant::PersistenceFailure(error) => Self {
                kind: FfiReplayErrorKind::PersistenceFailure,
                message,
                invalid_event_kind: None,
                expired_at_unix_seconds: None,
                persistence_failure: Some(Arc::new(error.into())),
            },
        }
    }
}

#[uniffi::export]
impl SenderReplayError {
    pub fn kind(&self) -> FfiReplayErrorKind { self.kind }

    pub fn message(&self) -> String { self.message.clone() }

    pub fn invalid_event_kind(&self) -> Option<FfiReplayInvalidEventKind> {
        self.invalid_event_kind
    }

    pub fn expired_at_unix_seconds(&self) -> Option<u32> { self.expired_at_unix_seconds }

    pub fn persistence_failure(&self) -> Option<Arc<ImplementationError>> {
        self.persistence_failure.clone()
    }
}

/// Error that may occur during state machine transitions
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SenderPersistedError {
    /// Storage failure while persisting session state.
    #[error(transparent)]
    Storage(Arc<ImplementationError>),
    /// Retry the same sender transition after handling the encapsulation failure.
    #[error("Transient sender encapsulation error: {0}")]
    TransientEncapsulationError(Arc<EncapsulationError>),
    /// The sender session terminated because request encapsulation failed.
    #[error("Fatal sender encapsulation error: {0}")]
    FatalEncapsulationError(Arc<EncapsulationError>),
    /// Retry the same sender transition after handling the response failure.
    #[error("Transient sender response error: {0}")]
    TransientResponseError(ResponseError),
    /// The sender session terminated because response handling failed.
    #[error("Fatal sender response error: {0}")]
    FatalResponseError(ResponseError),
    /// Retry the same sender transition after handling the build failure.
    #[error("Transient sender build error: {0}")]
    TransientBuildSenderError(Arc<BuildSenderError>),
    /// The sender session terminated because sender construction failed.
    #[error("Fatal sender build error: {0}")]
    FatalBuildSenderError(Arc<BuildSenderError>),
    /// Unexpected error shape that should not occur for sender transitions.
    #[error("An unexpected error occurred")]
    Unexpected,
}

impl From<ImplementationError> for SenderPersistedError {
    fn from(value: ImplementationError) -> Self { SenderPersistedError::Storage(Arc::new(value)) }
}

impl<S> From<payjoin::persist::PersistedError<send::v2::EncapsulationError, S>>
    for SenderPersistedError
where
    S: std::error::Error + Send + Sync + 'static,
{
    fn from(err: payjoin::persist::PersistedError<send::v2::EncapsulationError, S>) -> Self {
        match err.into_variant() {
            PersistedErrorVariant::Storage(storage_err) =>
                SenderPersistedError::from(ImplementationError::new(storage_err)),
            PersistedErrorVariant::Transient(api_err) =>
                SenderPersistedError::TransientEncapsulationError(Arc::new(api_err.into())),
            PersistedErrorVariant::Fatal(api_err) =>
                SenderPersistedError::FatalEncapsulationError(Arc::new(api_err.into())),
            PersistedErrorVariant::FatalWithState(_, _) => SenderPersistedError::Unexpected,
        }
    }
}

impl<S> From<payjoin::persist::PersistedError<send::ResponseError, S>> for SenderPersistedError
where
    S: std::error::Error + Send + Sync + 'static,
{
    fn from(err: payjoin::persist::PersistedError<send::ResponseError, S>) -> Self {
        match err.into_variant() {
            PersistedErrorVariant::Storage(storage_err) =>
                SenderPersistedError::from(ImplementationError::new(storage_err)),
            PersistedErrorVariant::Transient(api_err) =>
                SenderPersistedError::TransientResponseError(api_err.into()),
            PersistedErrorVariant::Fatal(api_err) =>
                SenderPersistedError::FatalResponseError(api_err.into()),
            PersistedErrorVariant::FatalWithState(_, _) => SenderPersistedError::Unexpected,
        }
    }
}

impl<S> From<payjoin::persist::PersistedError<send::BuildSenderError, S>> for SenderPersistedError
where
    S: std::error::Error + Send + Sync + 'static,
{
    fn from(err: payjoin::persist::PersistedError<send::BuildSenderError, S>) -> Self {
        match err.into_variant() {
            PersistedErrorVariant::Storage(storage_err) =>
                SenderPersistedError::from(ImplementationError::new(storage_err)),
            PersistedErrorVariant::Transient(api_err) =>
                SenderPersistedError::TransientBuildSenderError(Arc::new(api_err.into())),
            PersistedErrorVariant::Fatal(api_err) =>
                SenderPersistedError::FatalBuildSenderError(Arc::new(api_err.into())),
            PersistedErrorVariant::FatalWithState(_, _) => SenderPersistedError::Unexpected,
        }
    }
}

#[cfg(all(test, feature = "_test-utils"))]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::SenderPersistedError;
    use crate::error::{ForeignError, ReplayErrorKind};
    use crate::receive::JsonReceiverSessionPersister;
    use crate::send::{JsonSenderSessionPersister, SenderBuilder};
    use crate::test_utils::{original_psbt, TestServices};
    use crate::ReceiverBuilder;

    #[derive(Default)]
    struct InMemoryReceiverPersister {
        events: Mutex<Vec<String>>,
    }

    impl JsonReceiverSessionPersister for InMemoryReceiverPersister {
        fn save(&self, event: String) -> Result<(), ForeignError> {
            self.events.lock().expect("lock").push(event);
            Ok(())
        }

        fn load(&self) -> Result<Vec<String>, ForeignError> {
            Ok(self.events.lock().expect("lock").clone())
        }

        fn close(&self) -> Result<(), ForeignError> { Ok(()) }
    }

    #[derive(Default)]
    struct InMemorySenderPersister {
        events: Mutex<Vec<String>>,
    }

    impl JsonSenderSessionPersister for InMemorySenderPersister {
        fn save(&self, event: String) -> Result<(), ForeignError> {
            self.events.lock().expect("lock").push(event);
            Ok(())
        }

        fn load(&self) -> Result<Vec<String>, ForeignError> {
            Ok(self.events.lock().expect("lock").clone())
        }

        fn close(&self) -> Result<(), ForeignError> { Ok(()) }
    }

    #[derive(Default)]
    struct LoadFailsSenderPersister;

    impl JsonSenderSessionPersister for LoadFailsSenderPersister {
        fn save(&self, _: String) -> Result<(), ForeignError> { Ok(()) }

        fn load(&self) -> Result<Vec<String>, ForeignError> {
            Err(ForeignError::InternalError("storage offline".to_string()))
        }

        fn close(&self) -> Result<(), ForeignError> { Ok(()) }
    }

    fn with_reply_key() -> crate::send::WithReplyKey {
        let services = TestServices::initialize().expect("services initialize");
        let ohttp_keys = Arc::new(services.fetch_ohttp_keys().expect("fetch ohttp keys"));
        let receiver_persister = Arc::new(InMemoryReceiverPersister::default());
        let initialized = ReceiverBuilder::new(
            "2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7".to_string(),
            services.directory_url(),
            ohttp_keys,
        )
        .expect("receiver builder")
        .build()
        .save(receiver_persister)
        .expect("save initialized receiver");
        let uri = initialized.pj_uri();

        let sender_persister = Arc::new(InMemorySenderPersister::default());
        SenderBuilder::new(original_psbt(), Arc::new(uri))
            .expect("sender builder")
            .build_recommended(1000)
            .expect("build sender")
            .save(sender_persister)
            .expect("save sender")
    }

    #[test]
    fn test_sender_persisted_error_preserves_encapsulation_classification() {
        let with_reply_key = with_reply_key();

        let transient_request =
            with_reply_key.create_v2_post_request("http://relay.invalid".to_string()).unwrap();
        let transient = with_reply_key
            .clone()
            .process_response(&[], transient_request.ohttp_ctx.as_ref())
            .save(Arc::new(InMemorySenderPersister::default()));
        let transient = match transient {
            Ok(_) => panic!("empty relay response should be transient"),
            Err(error) => error,
        };
        assert!(matches!(transient, SenderPersistedError::TransientEncapsulationError(_)));

        let fatal_request =
            with_reply_key.create_v2_post_request("http://relay.invalid".to_string()).unwrap();
        let fatal = with_reply_key
            .process_response(&fatal_request.request.body, fatal_request.ohttp_ctx.as_ref())
            .save(Arc::new(InMemorySenderPersister::default()));
        let fatal = match fatal {
            Ok(_) => panic!("garbage response with valid size should be fatal"),
            Err(error) => error,
        };
        assert!(matches!(fatal, SenderPersistedError::FatalEncapsulationError(_)));
    }

    #[test]
    fn test_sender_replay_error_exposes_persistence_failure_kind() {
        let error = match crate::send::replay_sender_event_log(Arc::new(LoadFailsSenderPersister)) {
            Ok(_) => panic!("replay should surface persistence failure"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ReplayErrorKind::PersistenceFailure);
        assert!(error.persistence_failure().is_some());
        assert!(error.invalid_event_kind().is_none());
    }
}

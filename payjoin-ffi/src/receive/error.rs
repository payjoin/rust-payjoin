use std::sync::Arc;

use payjoin::error::ReplayErrorVariant as CoreReplayErrorVariant;
use payjoin::persist::PersistedErrorVariant;
use payjoin::receive;

use crate::error::{
    FfiValidationError, ImplementationError, ReplayErrorKind as FfiReplayErrorKind,
    ReplayInvalidEventKind as FfiReplayInvalidEventKind,
};
use crate::receive::HasReplyableError;
use crate::uri::error::IntoUrlError;

/// The top-level error type for the payjoin receiver
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum ReceiverError {
    /// Error in underlying protocol function
    #[error("Protocol error: {0}")]
    Protocol(Arc<ProtocolError>),
    /// Error arising due to the specific receiver implementation
    ///
    /// e.g. database errors, network failures, wallet errors
    #[error("Implementation error: {0}")]
    Implementation(Arc<ImplementationError>),
    /// Error that may occur when converting a some type to a URL
    #[error("IntoUrl error: {0}")]
    IntoUrl(Arc<IntoUrlError>),
    /// Catch-all for unhandled error variants
    #[error("An unexpected error occurred")]
    Unexpected,
}

impl From<receive::Error> for ReceiverError {
    fn from(value: receive::Error) -> Self {
        use ReceiverError::*;

        match value {
            receive::Error::Protocol(e) => Protocol(Arc::new(ProtocolError(e))),
            receive::Error::Implementation(e) =>
                Implementation(Arc::new(ImplementationError::from(e))),
            _ => Unexpected,
        }
    }
}

/// Error that may occur during state machine transitions
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ReceiverPersistedError {
    /// Storage failure while persisting session state.
    #[error(transparent)]
    Storage(Arc<ImplementationError>),
    /// Retry the same receiver transition from the current session state.
    #[error("Transient receiver error: {error}")]
    Transient { error: ReceiverError },
    /// The receiver session terminated and should not be resumed.
    #[error("Fatal receiver error: {error}")]
    Fatal { error: ReceiverError },
    /// The receiver transitioned into a replyable error state.
    ///
    /// Continue the protocol with the returned `state` to reply to the sender.
    #[error("Fatal receiver error with state: {error}")]
    FatalWithState { error: ReceiverError, state: Arc<HasReplyableError> },
    /// Unexpected error shape that should not occur for receiver transitions.
    #[error("An unexpected error occurred")]
    Unexpected,
}

impl From<ImplementationError> for ReceiverPersistedError {
    fn from(value: ImplementationError) -> Self { ReceiverPersistedError::Storage(Arc::new(value)) }
}

impl From<crate::error::ForeignError> for ReceiverPersistedError {
    fn from(value: crate::error::ForeignError) -> Self {
        ReceiverPersistedError::from(ImplementationError::new(value))
    }
}

macro_rules! impl_persisted_error_from {
    (
        $api_error_ty:ty,
        $receiver_arm:expr
    ) => {
        impl<S> From<payjoin::persist::PersistedError<$api_error_ty, S>> for ReceiverPersistedError
        where
            S: std::error::Error + Send + Sync + 'static,
        {
            fn from(err: payjoin::persist::PersistedError<$api_error_ty, S>) -> Self {
                match err.into_variant() {
                    PersistedErrorVariant::Storage(storage_err) =>
                        ReceiverPersistedError::from(ImplementationError::new(storage_err)),
                    PersistedErrorVariant::Transient(api_err) =>
                        ReceiverPersistedError::Transient { error: $receiver_arm(api_err) },
                    PersistedErrorVariant::Fatal(api_err) =>
                        ReceiverPersistedError::Fatal { error: $receiver_arm(api_err) },
                    PersistedErrorVariant::FatalWithState(_, _) =>
                        ReceiverPersistedError::Unexpected,
                }
            }
        }
    };
}

impl_persisted_error_from!(receive::ProtocolError, |api_err: receive::ProtocolError| {
    ReceiverError::Protocol(Arc::new(api_err.into()))
});

impl_persisted_error_from!(receive::Error, |api_err: receive::Error| api_err.into());

impl_persisted_error_from!(payjoin::IntoUrlError, |api_err: payjoin::IntoUrlError| {
    ReceiverError::IntoUrl(Arc::new(api_err.into()))
});

impl_persisted_error_from!(
    payjoin::ImplementationError,
    |api_err: payjoin::ImplementationError| {
        ReceiverError::Implementation(Arc::new(api_err.into()))
    }
);

impl<S>
    From<
        payjoin::persist::PersistedError<
            receive::Error,
            S,
            payjoin::receive::v2::Receiver<payjoin::receive::v2::HasReplyableError>,
        >,
    > for ReceiverPersistedError
where
    S: std::error::Error + Send + Sync + 'static,
{
    fn from(
        err: payjoin::persist::PersistedError<
            receive::Error,
            S,
            payjoin::receive::v2::Receiver<payjoin::receive::v2::HasReplyableError>,
        >,
    ) -> Self {
        match err.into_variant() {
            PersistedErrorVariant::Storage(storage_err) =>
                ReceiverPersistedError::from(ImplementationError::new(storage_err)),
            PersistedErrorVariant::Transient(api_err) =>
                ReceiverPersistedError::Transient { error: api_err.into() },
            PersistedErrorVariant::Fatal(api_err) =>
                ReceiverPersistedError::Fatal { error: api_err.into() },
            PersistedErrorVariant::FatalWithState(api_err, state) =>
                ReceiverPersistedError::FatalWithState {
                    error: api_err.into(),
                    state: Arc::new(state.into()),
                },
        }
    }
}

/// Error that may occur when building a receiver session.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum ReceiverBuilderError {
    /// The provided Bitcoin address is invalid.
    #[error("Invalid Bitcoin address: {0}")]
    InvalidAddress(Arc<AddressParseError>),
    /// Error that may occur when converting a value into a URL.
    #[error("Invalid directory URL: {0}")]
    IntoUrl(Arc<IntoUrlError>),
}

impl From<payjoin::IntoUrlError> for ReceiverBuilderError {
    fn from(value: payjoin::IntoUrlError) -> Self {
        ReceiverBuilderError::IntoUrl(Arc::new(value.into()))
    }
}

impl From<payjoin::bitcoin::address::ParseError> for ReceiverBuilderError {
    fn from(value: payjoin::bitcoin::address::ParseError) -> Self {
        ReceiverBuilderError::InvalidAddress(Arc::new(value.into()))
    }
}

/// Error parsing a Bitcoin address.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("Invalid Bitcoin address: {msg}")]
pub struct AddressParseError {
    msg: String,
}

impl From<payjoin::bitcoin::address::ParseError> for AddressParseError {
    fn from(value: payjoin::bitcoin::address::ParseError) -> Self {
        AddressParseError { msg: value.to_string() }
    }
}

/// The replyable error type for the payjoin receiver, representing failures need to be
/// returned to the sender.
///
/// The error handling is designed to:
/// 1. Provide structured error responses for protocol-level failures
/// 2. Hide implementation details of external errors for security
/// 3. Support proper error propagation through the receiver stack
/// 4. Provide errors according to BIP-78 JSON error specifications for return
///    after conversion into [`JsonReply`]
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct ProtocolError(#[from] receive::ProtocolError);

/// The standard format for errors that can be replied as JSON.
///
/// The JSON output includes the following fields:
/// ```json
/// {
///     "errorCode": "specific-error-code",
///     "message": "Human readable error message"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Object)]
pub struct JsonReply(receive::JsonReply);

impl From<JsonReply> for receive::JsonReply {
    fn from(value: JsonReply) -> Self { value.0 }
}

impl From<receive::JsonReply> for JsonReply {
    fn from(value: receive::JsonReply) -> Self { Self(value) }
}

impl From<ProtocolError> for JsonReply {
    fn from(value: ProtocolError) -> Self { Self((&value.0).into()) }
}

/// Error that may occur during a v2 session typestate change
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct SessionError(#[from] receive::v2::SessionError);

/// Protocol error raised during output substitution.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct OutputSubstitutionProtocolError(#[from] receive::OutputSubstitutionError);

/// Error that may occur when output substitution fails.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum OutputSubstitutionError {
    #[error(transparent)]
    Protocol(Arc<OutputSubstitutionProtocolError>),
    #[error(transparent)]
    FfiValidation(FfiValidationError),
}

impl From<receive::OutputSubstitutionError> for OutputSubstitutionError {
    fn from(value: receive::OutputSubstitutionError) -> Self {
        OutputSubstitutionError::Protocol(Arc::new(value.into()))
    }
}

impl From<FfiValidationError> for OutputSubstitutionError {
    fn from(value: FfiValidationError) -> Self { OutputSubstitutionError::FfiValidation(value) }
}

/// Error that may occur when coin selection fails.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct SelectionError(#[from] receive::SelectionError);

/// Error that may occur when input contribution fails.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct InputContributionError(#[from] receive::InputContributionError);

/// Error validating a PSBT Input
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct PsbtInputError(#[from] receive::PsbtInputError);

/// Error constructing an [`InputPair`](crate::InputPair).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum InputPairError {
    /// Provided outpoint could not be parsed.
    #[error("Invalid outpoint (txid={txid}, vout={vout})")]
    InvalidOutPoint { txid: String, vout: u32 },
    /// PSBT input failed validation in the core library.
    #[error("Invalid PSBT input: {0}")]
    InvalidPsbtInput(Arc<PsbtInputError>),
    /// Input failed validation in the FFI layer.
    #[error("Invalid input: {0}")]
    FfiValidation(FfiValidationError),
}

impl InputPairError {
    pub fn invalid_outpoint(txid: String, vout: u32) -> Self {
        InputPairError::InvalidOutPoint { txid, vout }
    }
}

impl From<FfiValidationError> for InputPairError {
    fn from(value: FfiValidationError) -> Self { InputPairError::FfiValidation(value) }
}

/// Error that may occur when a receiver event log is replayed.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("{message}")]
pub struct ReceiverReplayError {
    kind: FfiReplayErrorKind,
    message: String,
    invalid_event_kind: Option<FfiReplayInvalidEventKind>,
    expired_at_unix_seconds: Option<u32>,
    persistence_failure: Option<Arc<ImplementationError>>,
}

impl From<payjoin::error::ReplayError<receive::v2::ReceiveSession, receive::v2::SessionEvent>>
    for ReceiverReplayError
{
    fn from(
        value: payjoin::error::ReplayError<receive::v2::ReceiveSession, receive::v2::SessionEvent>,
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
impl ReceiverReplayError {
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

#[cfg(all(test, feature = "_test-utils"))]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use payjoin_test_utils::TestServices;
    use tokio::time::sleep;

    use super::ReceiverPersistedError;
    use crate::error::{ForeignError, ReplayErrorKind};
    use crate::receive::{
        InitializedTransitionOutcome, JsonReceiverSessionPersister, ReceiverBuilder,
    };
    use crate::send::{JsonSenderSessionPersister, SenderBuilder};

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
    struct EmptyReceiverPersister;

    impl JsonReceiverSessionPersister for EmptyReceiverPersister {
        fn save(&self, _: String) -> Result<(), ForeignError> { Ok(()) }

        fn load(&self) -> Result<Vec<String>, ForeignError> { Ok(Vec::new()) }

        fn close(&self) -> Result<(), ForeignError> { Ok(()) }
    }

    struct RejectBroadcast;

    impl crate::receive::CanBroadcast for RejectBroadcast {
        fn callback(&self, _: Vec<u8>) -> Result<bool, ForeignError> { Ok(false) }
    }

    async fn post_request(services: &TestServices, request: crate::Request) -> Vec<u8> {
        let response = services
            .http_agent()
            .post(request.url)
            .header("Content-Type", request.content_type)
            .body(request.body)
            .send()
            .await
            .expect("request should succeed");
        response.bytes().await.expect("response bytes").to_vec()
    }

    #[tokio::test]
    async fn test_receiver_persisted_error_preserves_fatal_with_state() {
        let services = TestServices::initialize().await.expect("services initialize");
        services.wait_for_services_ready().await.expect("services ready");

        let receiver_persister = Arc::new(InMemoryReceiverPersister::default());
        let initialized = ReceiverBuilder::new(
            "2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7".to_string(),
            services.directory_url(),
            Arc::new(services.fetch_ohttp_keys().await.expect("fetch ohttp keys").into()),
        )
        .expect("receiver builder")
        .build()
        .save(receiver_persister.clone())
        .expect("save initialized receiver");

        let sender_persister = Arc::new(InMemorySenderPersister::default());
        let with_reply_key =
            SenderBuilder::new(crate::test_utils::original_psbt(), Arc::new(initialized.pj_uri()))
                .expect("sender builder")
                .build_recommended(1000)
                .expect("build sender")
                .save(sender_persister)
                .expect("save sender");

        let sender_request =
            with_reply_key.create_v2_post_request(services.ohttp_relay_url()).unwrap();
        let _ = post_request(&services, sender_request.request).await;

        let mut initialized = initialized;
        let unchecked = loop {
            let poll = initialized.create_poll_request(services.ohttp_relay_url()).unwrap();
            let response = post_request(&services, poll.request).await;
            let outcome = initialized
                .process_response(&response, poll.client_response.as_ref())
                .save(receiver_persister.clone())
                .expect("persist initialized transition");
            match outcome {
                InitializedTransitionOutcome::Progress { inner } => break inner,
                InitializedTransitionOutcome::Stasis { inner } => {
                    initialized = Arc::unwrap_or_clone(inner);
                    sleep(Duration::from_millis(20)).await;
                }
            }
        };

        let error = unchecked
            .check_broadcast_suitability(None, Arc::new(RejectBroadcast))
            .expect("validation inputs")
            .save(receiver_persister);
        let error = match error {
            Ok(_) => panic!("non-broadcastable original should produce replyable error state"),
            Err(error) => error,
        };

        match error {
            ReceiverPersistedError::FatalWithState { state, .. } => {
                state.create_error_request(services.ohttp_relay_url()).expect("state preserved");
            }
            other => panic!("unexpected receiver persisted error: {other:?}"),
        }
    }

    #[test]
    fn test_receiver_replay_error_exposes_no_events_kind() {
        let error =
            match crate::receive::replay_receiver_event_log(Arc::new(EmptyReceiverPersister)) {
                Ok(_) => panic!("empty event log should fail"),
                Err(error) => error,
            };
        assert_eq!(error.kind(), ReplayErrorKind::NoEvents);
        assert!(error.persistence_failure().is_none());
        assert!(error.expired_at_unix_seconds().is_none());
    }
}

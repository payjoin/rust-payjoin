use std::sync::Arc;

use payjoin::receive;

use crate::error::{FfiValidationError, ImplementationError};
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
            receive::Error::Protocol(e) => Protocol(Arc::new(e.into())),
            receive::Error::Implementation(e) =>
                Implementation(Arc::new(ImplementationError::from(e))),
            _ => Unexpected,
        }
    }
}

/// Error that may occur during state machine transitions
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[error(transparent)]
pub enum ReceiverPersistedError {
    /// rust-payjoin receiver error
    #[error(transparent)]
    Receiver(ReceiverError),
    /// Storage error that could occur at application storage layer
    #[error(transparent)]
    Storage(Arc<ImplementationError>),
}

impl From<ImplementationError> for ReceiverPersistedError {
    fn from(value: ImplementationError) -> Self { ReceiverPersistedError::Storage(Arc::new(value)) }
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
                if err.storage_error_ref().is_some() {
                    if let Some(storage_err) = err.storage_error() {
                        return ReceiverPersistedError::from(ImplementationError::new(storage_err));
                    }
                    return ReceiverPersistedError::Receiver(ReceiverError::Unexpected);
                }
                if let Some(api_err) = err.api_error() {
                    return ReceiverPersistedError::Receiver($receiver_arm(api_err));
                }
                ReceiverPersistedError::Receiver(ReceiverError::Unexpected)
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ProtocolErrorKind {
    OriginalPayload,
    V1Request,
    V2Session,
    Other,
}

impl From<receive::ProtocolErrorKind> for ProtocolErrorKind {
    fn from(value: receive::ProtocolErrorKind) -> Self {
        match value {
            receive::ProtocolErrorKind::OriginalPayload => Self::OriginalPayload,
            receive::ProtocolErrorKind::V1Request => Self::V1Request,
            receive::ProtocolErrorKind::V2Session => Self::V2Session,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PayloadErrorKind {
    InvalidUtf8,
    InvalidPsbt,
    UnsupportedVersion,
    InvalidSenderFeeRate,
    InconsistentPsbt,
    PrevTxOut,
    MissingPayment,
    OriginalPsbtNotBroadcastable,
    InputOwned,
    InputSeen,
    PsbtBelowFeeRate,
    FeeTooHigh,
    Other,
}

impl From<receive::PayloadErrorKind> for PayloadErrorKind {
    fn from(value: receive::PayloadErrorKind) -> Self {
        match value {
            receive::PayloadErrorKind::InvalidUtf8 => Self::InvalidUtf8,
            receive::PayloadErrorKind::InvalidPsbt => Self::InvalidPsbt,
            receive::PayloadErrorKind::UnsupportedVersion => Self::UnsupportedVersion,
            receive::PayloadErrorKind::InvalidSenderFeeRate => Self::InvalidSenderFeeRate,
            receive::PayloadErrorKind::InconsistentPsbt => Self::InconsistentPsbt,
            receive::PayloadErrorKind::PrevTxOut => Self::PrevTxOut,
            receive::PayloadErrorKind::MissingPayment => Self::MissingPayment,
            receive::PayloadErrorKind::OriginalPsbtNotBroadcastable =>
                Self::OriginalPsbtNotBroadcastable,
            receive::PayloadErrorKind::InputOwned => Self::InputOwned,
            receive::PayloadErrorKind::InputSeen => Self::InputSeen,
            receive::PayloadErrorKind::PsbtBelowFeeRate => Self::PsbtBelowFeeRate,
            receive::PayloadErrorKind::FeeTooHigh => Self::FeeTooHigh,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RequestErrorKind {
    MissingHeader,
    InvalidContentType,
    InvalidContentLength,
    ContentLengthMismatch,
    Other,
}

impl From<receive::v1::RequestErrorKind> for RequestErrorKind {
    fn from(value: receive::v1::RequestErrorKind) -> Self {
        match value {
            receive::v1::RequestErrorKind::MissingHeader => Self::MissingHeader,
            receive::v1::RequestErrorKind::InvalidContentType => Self::InvalidContentType,
            receive::v1::RequestErrorKind::InvalidContentLength => Self::InvalidContentLength,
            receive::v1::RequestErrorKind::ContentLengthMismatch => Self::ContentLengthMismatch,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SessionErrorKind {
    ParseUrl,
    Expired,
    OhttpEncapsulation,
    Hpke,
    DirectoryResponse,
    Other,
}

impl From<receive::v2::SessionErrorKind> for SessionErrorKind {
    fn from(value: receive::v2::SessionErrorKind) -> Self {
        match value {
            receive::v2::SessionErrorKind::ParseUrl => Self::ParseUrl,
            receive::v2::SessionErrorKind::Expired => Self::Expired,
            receive::v2::SessionErrorKind::OhttpEncapsulation => Self::OhttpEncapsulation,
            receive::v2::SessionErrorKind::Hpke => Self::Hpke,
            receive::v2::SessionErrorKind::DirectoryResponse => Self::DirectoryResponse,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("{message}")]
pub struct ProtocolError {
    kind: ProtocolErrorKind,
    message: String,
    reply: receive::JsonReply,
    payload_error: Option<Arc<PayloadError>>,
    request_error: Option<Arc<RequestError>>,
    session_error: Option<Arc<SessionError>>,
}

impl From<receive::ProtocolError> for ProtocolError {
    fn from(value: receive::ProtocolError) -> Self {
        let kind = value.kind().into();
        let message = value.to_string();
        let reply = receive::JsonReply::from(&value);

        match value {
            receive::ProtocolError::OriginalPayload(error) => Self {
                kind,
                message,
                reply,
                payload_error: Some(Arc::new(error.into())),
                request_error: None,
                session_error: None,
            },
            receive::ProtocolError::V1(error) => Self {
                kind,
                message,
                reply,
                payload_error: None,
                request_error: Some(Arc::new(error.into())),
                session_error: None,
            },
            receive::ProtocolError::V2(error) => Self {
                kind,
                message,
                reply,
                payload_error: None,
                request_error: None,
                session_error: Some(Arc::new(error.into())),
            },
        }
    }
}

#[uniffi::export]
impl ProtocolError {
    pub fn kind(&self) -> ProtocolErrorKind { self.kind }

    pub fn message(&self) -> String { self.message.clone() }

    pub fn payload_error(&self) -> Option<Arc<PayloadError>> { self.payload_error.clone() }

    pub fn request_error(&self) -> Option<Arc<RequestError>> { self.request_error.clone() }

    pub fn session_error(&self) -> Option<Arc<SessionError>> { self.session_error.clone() }
}

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
    fn from(value: ProtocolError) -> Self { Self(value.reply) }
}

/// Error that may occur during a v2 session typestate change
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("{message}")]
pub struct SessionError {
    kind: SessionErrorKind,
    message: String,
}

impl From<receive::v2::SessionError> for SessionError {
    fn from(value: receive::v2::SessionError) -> Self {
        Self { kind: value.kind().into(), message: value.to_string() }
    }
}

#[uniffi::export]
impl SessionError {
    pub fn kind(&self) -> SessionErrorKind { self.kind }

    pub fn message(&self) -> String { self.message.clone() }
}

/// Receiver original payload validation error exposed over FFI.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("{message}")]
pub struct PayloadError {
    kind: PayloadErrorKind,
    message: String,
    supported_versions: Option<Vec<u64>>,
}

impl From<receive::PayloadError> for PayloadError {
    fn from(value: receive::PayloadError) -> Self {
        Self {
            kind: value.kind().into(),
            message: value.to_string(),
            supported_versions: value.supported_versions(),
        }
    }
}

#[uniffi::export]
impl PayloadError {
    pub fn kind(&self) -> PayloadErrorKind { self.kind }

    pub fn message(&self) -> String { self.message.clone() }

    pub fn supported_versions(&self) -> Option<Vec<u64>> { self.supported_versions.clone() }
}

/// Receiver v1 request validation error exposed over FFI.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("{message}")]
pub struct RequestError {
    kind: RequestErrorKind,
    message: String,
    header_name: Option<String>,
    invalid_content_type: Option<String>,
    expected_content_length: Option<u64>,
    actual_content_length: Option<u64>,
}

impl From<receive::v1::RequestError> for RequestError {
    fn from(value: receive::v1::RequestError) -> Self {
        Self {
            kind: value.kind().into(),
            message: value.to_string(),
            header_name: value.header_name().map(str::to_owned),
            invalid_content_type: value.invalid_content_type().map(str::to_owned),
            expected_content_length: value.expected_content_length().map(|value| value as u64),
            actual_content_length: value.actual_content_length().map(|value| value as u64),
        }
    }
}

#[uniffi::export]
impl RequestError {
    pub fn kind(&self) -> RequestErrorKind { self.kind }

    pub fn message(&self) -> String { self.message.clone() }

    pub fn header_name(&self) -> Option<String> { self.header_name.clone() }

    pub fn invalid_content_type(&self) -> Option<String> { self.invalid_content_type.clone() }

    pub fn expected_content_length(&self) -> Option<u64> { self.expected_content_length }

    pub fn actual_content_length(&self) -> Option<u64> { self.actual_content_length }
}

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

/// Error that may occur when a receiver event log is replayed
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct ReceiverReplayError(
    #[from] payjoin::error::ReplayError<receive::v2::ReceiveSession, receive::v2::SessionEvent>,
);

#[cfg(test)]
mod tests {
    use super::*;

    struct TestHeaders {
        content_type: Option<&'static str>,
        content_length: Option<String>,
    }

    impl receive::v1::Headers for TestHeaders {
        fn get_header(&self, key: &str) -> Option<&str> {
            match key {
                "content-type" => self.content_type,
                "content-length" => self.content_length.as_deref(),
                _ => None,
            }
        }
    }

    #[test]
    fn test_receiver_error_exposes_payload_kind() {
        let body = b"not-a-psbt";
        let headers = TestHeaders {
            content_type: Some("text/plain"),
            content_length: Some(body.len().to_string()),
        };
        let error = receive::v1::UncheckedOriginalPayload::from_request(body, "", headers)
            .expect_err("invalid PSBT should fail");

        let ReceiverError::Protocol(protocol) = ReceiverError::from(error) else {
            panic!("expected protocol error");
        };

        assert_eq!(protocol.kind(), ProtocolErrorKind::OriginalPayload);
        assert_eq!(
            protocol.payload_error().expect("payload error should be present").kind(),
            PayloadErrorKind::InvalidPsbt
        );
        assert!(protocol.request_error().is_none());
        assert!(protocol.session_error().is_none());
    }

    #[test]
    fn test_receiver_error_exposes_request_details() {
        let body = b"abc";
        let headers = TestHeaders {
            content_type: Some("text/plain"),
            content_length: Some((body.len() + 1).to_string()),
        };
        let error = receive::v1::UncheckedOriginalPayload::from_request(body, "", headers)
            .expect_err("content length mismatch should fail");

        let ReceiverError::Protocol(protocol) = ReceiverError::from(error) else {
            panic!("expected protocol error");
        };

        assert_eq!(protocol.kind(), ProtocolErrorKind::V1Request);
        let request = protocol.request_error().expect("request error should be present");
        assert_eq!(request.kind(), RequestErrorKind::ContentLengthMismatch);
        assert_eq!(request.expected_content_length(), Some((body.len() + 1) as u64));
        assert_eq!(request.actual_content_length(), Some(body.len() as u64));
        assert!(protocol.payload_error().is_none());
    }
}

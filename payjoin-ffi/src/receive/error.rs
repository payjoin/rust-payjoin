use std::sync::Arc;

use payjoin::receive;

use crate::error::{ImplementationError, PrimitiveError};
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
    Primitive(PrimitiveError),
}

impl From<receive::OutputSubstitutionError> for OutputSubstitutionError {
    fn from(value: receive::OutputSubstitutionError) -> Self {
        OutputSubstitutionError::Protocol(Arc::new(value.into()))
    }
}

impl From<PrimitiveError> for OutputSubstitutionError {
    fn from(value: PrimitiveError) -> Self { OutputSubstitutionError::Primitive(value) }
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
    /// Amount exceeds allowed maximum.
    #[error("Amount out of range: {amount_sat} sats (max {max_sat})")]
    AmountOutOfRange { amount_sat: u64, max_sat: u64 },
    /// Weight must be positive and no more than a block.
    #[error("Weight out of range: {weight_units} wu (max {max_wu})")]
    WeightOutOfRange { weight_units: u64, max_wu: u64 },
    /// PSBT input failed validation in the core library.
    #[error("Invalid PSBT input: {0}")]
    InvalidPsbtInput(Arc<PsbtInputError>),
    /// Primitive input failed validation in the FFI layer.
    #[error("Invalid primitive input: {0}")]
    InvalidPrimitive(PrimitiveError),
}

impl InputPairError {
    pub fn invalid_outpoint(txid: String, vout: u32) -> Self {
        InputPairError::InvalidOutPoint { txid, vout }
    }
}

impl From<PrimitiveError> for InputPairError {
    fn from(value: PrimitiveError) -> Self {
        match value {
            PrimitiveError::AmountOutOfRange { amount_sat, max_sat } =>
                InputPairError::AmountOutOfRange { amount_sat, max_sat },
            PrimitiveError::WeightOutOfRange { weight_units, max_wu } =>
                InputPairError::WeightOutOfRange { weight_units, max_wu },
            other => InputPairError::InvalidPrimitive(other),
        }
    }
}

/// Error that may occur when a receiver event log is replayed
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct ReceiverReplayError(
    #[from] payjoin::error::ReplayError<receive::v2::ReceiveSession, receive::v2::SessionEvent>,
);

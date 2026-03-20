use std::sync::Arc;

use payjoin::bitcoin::psbt::PsbtParseError as CorePsbtParseError;
use payjoin::send;

use crate::error::{FfiValidationError, ImplementationError};

/// Error building a Sender from a SenderBuilder.
///
/// This error is unrecoverable.
#[derive(Debug, PartialEq, Eq, thiserror::Error, uniffi::Object)]
#[error("Error initializing the sender: {msg}")]
pub struct BuildSenderError {
    msg: String,
    invalid_original_input_index: Option<u64>,
    invalid_original_input_message: Option<String>,
}

impl From<PsbtParseError> for BuildSenderError {
    fn from(value: PsbtParseError) -> Self {
        BuildSenderError {
            msg: value.to_string(),
            invalid_original_input_index: None,
            invalid_original_input_message: None,
        }
    }
}

impl From<send::BuildSenderError> for BuildSenderError {
    fn from(value: send::BuildSenderError) -> Self {
        BuildSenderError {
            msg: value.to_string(),
            invalid_original_input_index: value
                .invalid_original_input_index()
                .map(|index| index as u64),
            invalid_original_input_message: value.invalid_original_input_message(),
        }
    }
}

#[uniffi::export]
impl BuildSenderError {
    pub fn message(&self) -> String { self.msg.clone() }

    pub fn invalid_original_input_index(&self) -> Option<u64> { self.invalid_original_input_index }

    pub fn invalid_original_input_message(&self) -> Option<String> {
        self.invalid_original_input_message.clone()
    }
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

/// Error that may occur when the sender session event log is replayed
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct SenderReplayError(
    #[from] payjoin::error::ReplayError<send::v2::SendSession, send::v2::SessionEvent>,
);

/// Error that may occur during state machine transitions
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[error(transparent)]
pub enum SenderPersistedError {
    /// rust-payjoin sender Encapsulation error
    #[error(transparent)]
    EncapsulationError(Arc<EncapsulationError>),
    /// rust-payjoin sender response error
    #[error(transparent)]
    ResponseError(ResponseError),
    /// Sender Build error
    #[error(transparent)]
    BuildSenderError(Arc<BuildSenderError>),
    /// Storage error that could occur at application storage layer
    #[error(transparent)]
    Storage(Arc<ImplementationError>),
    /// Unexpected error
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
        if err.storage_error_ref().is_some() {
            if let Some(storage_err) = err.storage_error() {
                return SenderPersistedError::from(ImplementationError::new(storage_err));
            }
            return SenderPersistedError::Unexpected;
        }
        if let Some(api_err) = err.api_error() {
            return SenderPersistedError::EncapsulationError(Arc::new(api_err.into()));
        }
        SenderPersistedError::Unexpected
    }
}

impl<S> From<payjoin::persist::PersistedError<send::ResponseError, S>> for SenderPersistedError
where
    S: std::error::Error + Send + Sync + 'static,
{
    fn from(err: payjoin::persist::PersistedError<send::ResponseError, S>) -> Self {
        if err.storage_error_ref().is_some() {
            if let Some(storage_err) = err.storage_error() {
                return SenderPersistedError::from(ImplementationError::new(storage_err));
            }
            return SenderPersistedError::Unexpected;
        }
        if let Some(api_err) = err.api_error() {
            return SenderPersistedError::ResponseError(api_err.into());
        }
        SenderPersistedError::Unexpected
    }
}

impl<S> From<payjoin::persist::PersistedError<send::BuildSenderError, S>> for SenderPersistedError
where
    S: std::error::Error + Send + Sync + 'static,
{
    fn from(err: payjoin::persist::PersistedError<send::BuildSenderError, S>) -> Self {
        if err.storage_error_ref().is_some() {
            if let Some(storage_err) = err.storage_error() {
                return SenderPersistedError::from(ImplementationError::new(storage_err));
            }
            return SenderPersistedError::Unexpected;
        }
        if let Some(api_err) = err.api_error() {
            return SenderPersistedError::BuildSenderError(Arc::new(api_err.into()));
        }
        SenderPersistedError::Unexpected
    }
}

#[cfg(all(test, feature = "_test-utils"))]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;

    use payjoin::bitcoin::hex::FromHex;

    use crate::send::{SenderBuilder, SenderInputError};
    use crate::test_utils::invalid_original_input_psbt;
    use crate::uri::PjUri;

    #[test]
    fn test_build_sender_error_exposes_invalid_input_index() {
        let address =
            payjoin::bitcoin::Address::from_str("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4")
                .expect("address should parse")
                .assume_checked();
        let ohttp_keys = payjoin::OhttpKeys::decode(
            &<Vec<u8> as FromHex>::from_hex(
                "01001604ba48c49c3d4a92a3ad00ecc63a024da10ced02180c73ec12d8a7ad2cc91bb483824fe2bee8d28bfe2eb2fc6453bc4d31cd851e8a6540e86c5382af588d370957000400010003",
            )
            .expect("hex fixture should decode"),
        )
        .expect("OHTTP keys should decode");
        let receiver = payjoin::receive::v2::ReceiverBuilder::new(
            address,
            "https://example.com".to_string(),
            ohttp_keys,
        )
        .expect("receiver builder should succeed")
        .build()
        .save(&payjoin::persist::NoopSessionPersister::default())
        .expect("no-op persister should not fail");
        let uri = Arc::new(PjUri::from(receiver.pj_uri()));

        let error = SenderBuilder::new(invalid_original_input_psbt(), uri)
            .expect("PSBT should parse")
            .build_non_incentivizing(1000);

        let Err(SenderInputError::Build(error)) = error else {
            panic!("expected sender build error");
        };

        assert_eq!(error.invalid_original_input_index(), Some(0));
        assert_eq!(
            error.invalid_original_input_message(),
            Some("invalid previous transaction output".to_string())
        );
    }
}

use std::{error, fmt};

use crate::receive::v1;
#[cfg(feature = "v2")]
use crate::receive::v2;

/// The top-level error type for the payjoin receiver, representing all possible failures that can occur
/// during the processing of a payjoin request.
///
/// The error handling is designed to:
/// 1. Provide structured error responses for protocol-level failures
/// 2. Hide implementation details of external errors for security
/// 3. Support proper error propagation through the receiver stack
/// 4. Provide errors according to BIP-78 JSON error specifications for return using [`Error::to_json`]
#[derive(Debug)]
pub enum Error {
    /// Error arising from the payjoin state machine
    ///
    /// e.g. PSBT validation, HTTP request validation, protocol version checks
    Validation(ValidationError),
    /// Error arising due to the specific receiver implementation
    ///
    /// e.g. database errors, network failures, wallet errors
    Implementation(Box<dyn error::Error + Send + Sync>),
}

impl Error {
    pub fn to_json(&self) -> String {
        match self {
            Self::Validation(e) => e.to_string(),
            Self::Implementation(_) =>
                "{{ \"errorCode\": \"unavailable\", \"message\": \"Receiver error\" }}".to_string(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            Self::Validation(e) => e.fmt(f),
            Self::Implementation(e) => write!(f, "Internal Server Error: {}", e),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Self::Validation(e) => e.source(),
            Self::Implementation(e) => Some(e.as_ref()),
        }
    }
}

impl From<InternalPayloadError> for Error {
    fn from(e: InternalPayloadError) -> Self {
        Error::Validation(ValidationError::Payload(e.into()))
    }
}

impl From<v1::InternalRequestError> for Error {
    fn from(e: v1::InternalRequestError) -> Self { Error::Validation(e.into()) }
}

/// An error that occurs during validation of a payjoin request, encompassing all possible validation
/// failures across different protocol versions and stages.
///
/// This abstraction serves as the primary error type for the validation phase of request processing,
/// allowing uniform error handling while maintaining protocol version specifics internally.
#[derive(Debug)]
pub enum ValidationError {
    /// Error arising from validation of the original PSBT payload
    Payload(PayloadError),
    /// Protocol-specific errors for BIP-78 v1 requests (e.g. HTTP request validation, parameter checks)
    V1(v1::RequestError),
    /// Protocol-specific errors for BIP-77 v2 sessions (e.g. session management, OHTTP, HPKE encryption)
    #[cfg(feature = "v2")]
    V2(v2::SessionError),
}

impl From<InternalPayloadError> for ValidationError {
    fn from(e: InternalPayloadError) -> Self { ValidationError::Payload(e.into()) }
}

impl From<v1::InternalRequestError> for ValidationError {
    fn from(e: v1::InternalRequestError) -> Self { ValidationError::V1(e.into()) }
}

#[cfg(feature = "v2")]
impl From<v2::InternalSessionError> for ValidationError {
    fn from(e: v2::InternalSessionError) -> Self { ValidationError::V2(e.into()) }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ValidationError::Payload(e) => write!(f, "{}", e),
            ValidationError::V1(e) => write!(f, "{}", e),
            #[cfg(feature = "v2")]
            ValidationError::V2(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ValidationError::Payload(e) => Some(e),
            ValidationError::V1(e) => Some(e),
            #[cfg(feature = "v2")]
            ValidationError::V2(e) => Some(e),
        }
    }
}

/// An error that occurs during validation of the original PSBT payload sent by the sender.
///
/// This type provides a public abstraction over internal validation errors while maintaining a stable public API.
/// It handles various failure modes like:
/// - Invalid UTF-8 encoding
/// - PSBT parsing errors
/// - BIP-78 specific PSBT validation failures
/// - Fee rate validation
/// - Input ownership validation
/// - Previous transaction output validation
///
/// The error messages are formatted as JSON strings suitable for HTTP responses according to the BIP-78 spec,
/// with appropriate error codes and human-readable messages.
#[derive(Debug)]
pub struct PayloadError(pub(crate) InternalPayloadError);

impl From<InternalPayloadError> for PayloadError {
    fn from(value: InternalPayloadError) -> Self { PayloadError(value) }
}

#[derive(Debug)]
pub(crate) enum InternalPayloadError {
    /// The payload is not valid utf-8
    Utf8(std::string::FromUtf8Error),
    /// The payload is not a valid PSBT
    ParsePsbt(bitcoin::psbt::PsbtParseError),
    /// Invalid sender parameters
    SenderParams(super::optional_parameters::Error),
    /// The raw PSBT fails bip78-specific validation.
    InconsistentPsbt(crate::psbt::InconsistentPsbt),
    /// The prevtxout is missing
    PrevTxOut(crate::psbt::PrevTxOutError),
    /// The Original PSBT has no output for the receiver.
    MissingPayment,
    /// The original PSBT transaction fails the broadcast check
    OriginalPsbtNotBroadcastable,
    #[allow(dead_code)]
    /// The sender is trying to spend the receiver input
    InputOwned(bitcoin::ScriptBuf),
    /// The expected input weight cannot be determined
    InputWeight(crate::psbt::InputWeightError),
    #[allow(dead_code)]
    /// Original PSBT input has been seen before. Only automatic receivers, aka "interactive" in the spec
    /// look out for these to prevent probing attacks.
    InputSeen(bitcoin::OutPoint),
    /// Original PSBT fee rate is below minimum fee rate set by the receiver.
    ///
    /// First argument is the calculated fee rate of the original PSBT.
    ///
    /// Second argument is the minimum fee rate optionaly set by the receiver.
    PsbtBelowFeeRate(bitcoin::FeeRate, bitcoin::FeeRate),
    /// Effective receiver feerate exceeds maximum allowed feerate
    FeeTooHigh(bitcoin::FeeRate, bitcoin::FeeRate),
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalPayloadError::*;

        fn write_error(
            f: &mut fmt::Formatter,
            code: &str,
            message: impl fmt::Display,
        ) -> fmt::Result {
            write!(f, r#"{{ "errorCode": "{}", "message": "{}" }}"#, code, message)
        }

        match &self.0 {
            Utf8(e) => write_error(f, "original-psbt-rejected", e),
            ParsePsbt(e) => write_error(f, "original-psbt-rejected", e),
            SenderParams(e) => match e {
                super::optional_parameters::Error::UnknownVersion { supported_versions } => {
                    write!(
                        f,
                        r#"{{
                            "errorCode": "version-unsupported",
                            "supported": "{}",
                            "message": "This version of payjoin is not supported."
                        }}"#,
                        serde_json::to_string(supported_versions).map_err(|_| fmt::Error)?
                    )
                }
                _ => write_error(f, "sender-params-error", e),
            },
            InconsistentPsbt(e) => write_error(f, "original-psbt-rejected", e),
            PrevTxOut(e) =>
                write_error(f, "original-psbt-rejected", format!("PrevTxOut Error: {}", e)),
            MissingPayment => write_error(f, "original-psbt-rejected", "Missing payment."),
            OriginalPsbtNotBroadcastable => write_error(
                f,
                "original-psbt-rejected",
                "Can't broadcast. PSBT rejected by mempool.",
            ),
            InputOwned(_) =>
                write_error(f, "original-psbt-rejected", "The receiver rejected the original PSBT."),
            InputWeight(e) =>
                write_error(f, "original-psbt-rejected", format!("InputWeight Error: {}", e)),
            InputSeen(_) =>
                write_error(f, "original-psbt-rejected", "The receiver rejected the original PSBT."),
            PsbtBelowFeeRate(original_psbt_fee_rate, receiver_min_fee_rate) => write_error(
                f,
                "original-psbt-rejected",
                format!(
                    "Original PSBT fee rate too low: {} < {}.",
                    original_psbt_fee_rate, receiver_min_fee_rate
                ),
            ),
            FeeTooHigh(proposed_feerate, max_feerate) => write_error(
                f,
                "original-psbt-rejected",
                format!(
                    "Effective receiver feerate exceeds maximum allowed feerate: {} > {}",
                    proposed_feerate, max_feerate
                ),
            ),
        }
    }
}

impl std::error::Error for PayloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalPayloadError::*;
        match &self.0 {
            Utf8(e) => Some(e),
            ParsePsbt(e) => Some(e),
            SenderParams(e) => Some(e),
            InconsistentPsbt(e) => Some(e),
            PrevTxOut(e) => Some(e),
            InputWeight(e) => Some(e),
            PsbtBelowFeeRate(_, _) => None,
            FeeTooHigh(_, _) => None,
            _ => None,
        }
    }
}

/// Error that may occur when output substitution fails.
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug)]
pub struct OutputSubstitutionError(InternalOutputSubstitutionError);

#[derive(Debug)]
pub(crate) enum InternalOutputSubstitutionError {
    /// Output substitution is disabled
    OutputSubstitutionDisabled(&'static str),
    /// Current output substitution implementation doesn't support reducing the number of outputs
    NotEnoughOutputs,
    /// The provided drain script could not be identified in the provided replacement outputs
    InvalidDrainScript,
}

impl fmt::Display for OutputSubstitutionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            InternalOutputSubstitutionError::OutputSubstitutionDisabled(reason) => write!(f, "{}", &format!("Output substitution is disabled: {}", reason)),
            InternalOutputSubstitutionError::NotEnoughOutputs => write!(
                f,
                "Current output substitution implementation doesn't support reducing the number of outputs"
            ),
            InternalOutputSubstitutionError::InvalidDrainScript =>
                write!(f, "The provided drain script could not be identified in the provided replacement outputs"),
        }
    }
}

impl From<InternalOutputSubstitutionError> for OutputSubstitutionError {
    fn from(value: InternalOutputSubstitutionError) -> Self { OutputSubstitutionError(value) }
}

impl std::error::Error for OutputSubstitutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            InternalOutputSubstitutionError::OutputSubstitutionDisabled(_) => None,
            InternalOutputSubstitutionError::NotEnoughOutputs => None,
            InternalOutputSubstitutionError::InvalidDrainScript => None,
        }
    }
}

/// Error that may occur when coin selection fails.
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug)]
pub struct SelectionError(InternalSelectionError);

#[derive(Debug)]
pub(crate) enum InternalSelectionError {
    /// No candidates available for selection
    Empty,
    /// Current privacy selection implementation only supports 2-output transactions
    TooManyOutputs,
    /// No selection candidates improve privacy
    NotFound,
}

impl fmt::Display for SelectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            InternalSelectionError::Empty => write!(f, "No candidates available for selection"),
            InternalSelectionError::TooManyOutputs => write!(
                f,
                "Current privacy selection implementation only supports 2-output transactions"
            ),
            InternalSelectionError::NotFound =>
                write!(f, "No selection candidates improve privacy"),
        }
    }
}

impl From<InternalSelectionError> for SelectionError {
    fn from(value: InternalSelectionError) -> Self { SelectionError(value) }
}

/// Error that may occur when input contribution fails.
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug)]
pub struct InputContributionError(InternalInputContributionError);

#[derive(Debug)]
pub(crate) enum InternalInputContributionError {
    /// The address type could not be determined
    AddressType(crate::psbt::AddressTypeError),
    /// The original PSBT has no inputs
    NoSenderInputs,
    /// The proposed receiver inputs would introduce mixed input script types
    MixedInputScripts(bitcoin::AddressType, bitcoin::AddressType),
    /// Total input value is not enough to cover additional output value
    ValueTooLow,
}

impl fmt::Display for InputContributionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            InternalInputContributionError::AddressType(e) =>
                write!(f, "The address type could not be determined: {}", e),
            InternalInputContributionError::NoSenderInputs =>
                write!(f, "The original PSBT has no inputs"),
            InternalInputContributionError::MixedInputScripts(type_a, type_b) => write!(
                f,
                "The proposed receiver inputs would introduce mixed input script types: {}; {}.",
                type_a, type_b
            ),
            InternalInputContributionError::ValueTooLow =>
                write!(f, "Total input value is not enough to cover additional output value"),
        }
    }
}

impl From<InternalInputContributionError> for InputContributionError {
    fn from(value: InternalInputContributionError) -> Self { InputContributionError(value) }
}

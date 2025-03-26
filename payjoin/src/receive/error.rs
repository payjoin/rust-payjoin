use std::{error, fmt};

use crate::error_codes::ErrorCode::{
    self, NotEnoughMoney, OriginalPsbtRejected, Unavailable, VersionUnsupported,
};

pub type ImplementationError = Box<dyn error::Error + Send + Sync>;

/// The top-level error type for the payjoin receiver
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Errors that can be replied to the sender
    ReplyToSender(ReplyableError),
    #[cfg(feature = "v2")]
    /// V2-specific errors that are infeasable to reply to the sender
    V2(crate::receive::v2::SessionError),
}

impl From<ReplyableError> for Error {
    fn from(e: ReplyableError) -> Self { Error::ReplyToSender(e) }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::ReplyToSender(e) => write!(f, "replyable error: {}", e),
            #[cfg(feature = "v2")]
            Error::V2(e) => write!(f, "unreplyable error: {}", e),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::ReplyToSender(e) => e.source(),
            #[cfg(feature = "v2")]
            Error::V2(e) => e.source(),
        }
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
#[derive(Debug)]
pub enum ReplyableError {
    /// Error arising from validation of the original PSBT payload
    Payload(PayloadError),
    /// Protocol-specific errors for BIP-78 v1 requests (e.g. HTTP request validation, parameter checks)
    #[cfg(feature = "v1")]
    V1(crate::receive::v1::RequestError),
    /// Error arising due to the specific receiver implementation
    ///
    /// e.g. database errors, network failures, wallet errors
    Implementation(ImplementationError),
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
pub struct JsonReply {
    /// The error code
    error_code: ErrorCode,
    /// The error message to be displayed only in debug logs
    message: String,
    /// Additional fields to be added to the JSON
    additional_fields: Vec<String>,
}

impl JsonReply {
    /// Create a new Reply
    pub fn new(error_code: ErrorCode, message: impl fmt::Display) -> Self {
        Self { error_code, message: message.to_string(), additional_fields: vec![] }
    }

    /// Serialize the Reply to a JSON string
    pub fn to_json(&self) -> String {
        if self.additional_fields.is_empty() {
            format!(r#"{{ "errorCode": "{}", "message": "{}" }}"#, self.error_code, self.message)
        } else {
            format!(
                r#"{{ "errorCode": "{}", "message": "{}", {} }}"#,
                self.error_code,
                self.message,
                self.additional_fields.join(", ")
            )
        }
    }
}

impl From<&ReplyableError> for JsonReply {
    fn from(e: &ReplyableError) -> Self {
        match e {
            ReplyableError::Payload(e) => e.into(),
            #[cfg(feature = "v1")]
            ReplyableError::V1(e) => e.into(),
            ReplyableError::Implementation(_) => JsonReply::new(Unavailable, "Receiver error"),
        }
    }
}

impl fmt::Display for ReplyableError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            Self::Payload(e) => e.fmt(f),
            #[cfg(feature = "v1")]
            Self::V1(e) => e.fmt(f),
            Self::Implementation(e) => write!(f, "Internal Server Error: {}", e),
        }
    }
}

impl error::Error for ReplyableError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Self::Payload(e) => e.source(),
            #[cfg(feature = "v1")]
            Self::V1(e) => e.source(),
            Self::Implementation(e) => Some(e.as_ref()),
        }
    }
}

impl From<InternalPayloadError> for ReplyableError {
    fn from(e: InternalPayloadError) -> Self { ReplyableError::Payload(e.into()) }
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
    /// Second argument is the minimum fee rate optionally set by the receiver.
    PsbtBelowFeeRate(bitcoin::FeeRate, bitcoin::FeeRate),
    /// Effective receiver feerate exceeds maximum allowed feerate
    FeeTooHigh(bitcoin::FeeRate, bitcoin::FeeRate),
}

impl From<&PayloadError> for JsonReply {
    fn from(e: &PayloadError) -> Self {
        use InternalPayloadError::*;

        match &e.0 {
            Utf8(_) => JsonReply::new(OriginalPsbtRejected, e),
            ParsePsbt(_) => JsonReply::new(OriginalPsbtRejected, e),
            SenderParams(e) => match e {
                super::optional_parameters::Error::UnknownVersion { supported_versions } => {
                    let supported_versions_json =
                        serde_json::to_string(supported_versions).unwrap_or_default();
                    JsonReply {
                        error_code: VersionUnsupported,
                        message: "This version of payjoin is not supported.".to_string(),
                        additional_fields: vec![format!(
                            r#""supported": {}"#,
                            supported_versions_json
                        )],
                    }
                }
                _ => JsonReply::new(OriginalPsbtRejected, e),
            },
            InconsistentPsbt(_) => JsonReply::new(OriginalPsbtRejected, e),
            PrevTxOut(_) => JsonReply::new(OriginalPsbtRejected, e),
            MissingPayment => JsonReply::new(OriginalPsbtRejected, e),
            OriginalPsbtNotBroadcastable => JsonReply::new(OriginalPsbtRejected, e),
            InputOwned(_) => JsonReply::new(OriginalPsbtRejected, e),
            InputWeight(_) => JsonReply::new(OriginalPsbtRejected, e),
            InputSeen(_) => JsonReply::new(OriginalPsbtRejected, e),
            PsbtBelowFeeRate(_, _) => JsonReply::new(OriginalPsbtRejected, e),
            FeeTooHigh(_, _) => JsonReply::new(NotEnoughMoney, e),
        }
    }
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalPayloadError::*;

        match &self.0 {
            Utf8(e) => write!(f, "{}", e),
            ParsePsbt(e) => write!(f, "{}", e),
            SenderParams(e) => write!(f, "{}", e),
            InconsistentPsbt(e) => write!(f, "{}", e),
            PrevTxOut(e) => write!(f, "PrevTxOut Error: {}", e),
            MissingPayment => write!(f, "Missing payment."),
            OriginalPsbtNotBroadcastable => write!(f, "Can't broadcast. PSBT rejected by mempool."),
            InputOwned(_) => write!(f, "The receiver rejected the original PSBT."),
            InputWeight(e) => write!(f, "InputWeight Error: {}", e),
            InputSeen(_) => write!(f, "The receiver rejected the original PSBT."),
            PsbtBelowFeeRate(original_psbt_fee_rate, receiver_min_fee_rate) => write!(
                f,
                "Original PSBT fee rate too low: {} < {}.",
                original_psbt_fee_rate, receiver_min_fee_rate
            ),
            FeeTooHigh(proposed_fee_rate, max_fee_rate) => write!(
                f,
                "Effective receiver feerate exceeds maximum allowed feerate: {} > {}",
                proposed_fee_rate, max_fee_rate
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
            MissingPayment => None,
            OriginalPsbtNotBroadcastable => None,
            InputOwned(_) => None,
            InputSeen(_) => None,
        }
    }
}

/// Error that may occur when output substitution fails.
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug, PartialEq)]
pub struct OutputSubstitutionError(InternalOutputSubstitutionError);

#[derive(Debug, PartialEq)]
pub(crate) enum InternalOutputSubstitutionError {
    /// Output substitution is disabled and output value was decreased
    DecreasedValueWhenDisabled,
    /// Output substitution is disabled and script pubkey was changed
    ScriptPubKeyChangedWhenDisabled,
    /// Current output substitution implementation doesn't support reducing the number of outputs
    NotEnoughOutputs,
    /// The provided drain script could not be identified in the provided replacement outputs
    InvalidDrainScript,
}

impl fmt::Display for OutputSubstitutionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            InternalOutputSubstitutionError::DecreasedValueWhenDisabled => write!(f, "Decreasing the receiver output value is not allowed when output substitution is disabled"),
            InternalOutputSubstitutionError::ScriptPubKeyChangedWhenDisabled => write!(f, "Changing the receiver output script pubkey is not allowed when output substitution is disabled"),
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
            InternalOutputSubstitutionError::DecreasedValueWhenDisabled => None,
            InternalOutputSubstitutionError::ScriptPubKeyChangedWhenDisabled => None,
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
    UnsupportedOutputLength,
    /// No selection candidates improve privacy
    NotFound,
}

impl fmt::Display for SelectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            InternalSelectionError::Empty => write!(f, "No candidates available for selection"),
            InternalSelectionError::UnsupportedOutputLength => write!(
                f,
                "Current privacy selection implementation only supports 2-output transactions"
            ),
            InternalSelectionError::NotFound =>
                write!(f, "No selection candidates improve privacy"),
        }
    }
}

impl error::Error for SelectionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use InternalSelectionError::*;

        match &self.0 {
            Empty => None,
            UnsupportedOutputLength => None,
            NotFound => None,
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
    /// Total input value is not enough to cover additional output value
    ValueTooLow,
}

impl fmt::Display for InputContributionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            InternalInputContributionError::ValueTooLow =>
                write!(f, "Total input value is not enough to cover additional output value"),
        }
    }
}

impl error::Error for InputContributionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.0 {
            InternalInputContributionError::ValueTooLow => None,
        }
    }
}

impl From<InternalInputContributionError> for InputContributionError {
    fn from(value: InternalInputContributionError) -> Self { InputContributionError(value) }
}

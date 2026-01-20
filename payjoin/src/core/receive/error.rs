use std::{error, fmt};

use crate::error_codes::ErrorCode::{
    self, NotEnoughMoney, OriginalPsbtRejected, Unavailable, VersionUnsupported,
};

/// The top-level error type for the payjoin receiver
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Error in underlying protocol function
    Protocol(ProtocolError),
    /// Error arising due to the specific receiver implementation
    ///
    /// e.g. database errors, network failures, wallet errors
    Implementation(crate::ImplementationError),
}

impl From<&Error> for JsonReply {
    fn from(e: &Error) -> Self {
        match e {
            Error::Protocol(e) => e.into(),
            Error::Implementation(_) => JsonReply::new(Unavailable, "Receiver error"),
        }
    }
}

impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self { Error::Protocol(e) }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Protocol(e) => write!(f, "Protocol error: {e}"),
            Error::Implementation(e) => write!(f, "Implementation error: {e}"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Protocol(e) => e.source(),
            Error::Implementation(e) => e.source(),
        }
    }
}

/// The protocol error type for the payjoin receiver, representing failures in
/// the internal protocol operation.
///
/// The error handling is designed to:
/// 1. Provide structured error responses for protocol-level failures
/// 2. Hide implementation details of external errors for security
/// 3. Support proper error propagation through the receiver stack
/// 4. Provide errors according to BIP-78 JSON error specifications for return
///    after conversion into [`JsonReply`]
#[derive(Debug)]
pub enum ProtocolError {
    /// Error arising from validation of the original PSBT payload
    OriginalPayload(PayloadError),
    /// Protocol-specific errors for BIP-78 v1 requests (e.g. HTTP request validation, parameter checks)
    #[cfg(feature = "v1")]
    V1(crate::receive::v1::RequestError),
    #[cfg(feature = "v2")]
    /// V2-specific errors that are infeasable to reply to the sender
    V2(crate::receive::v2::SessionError),
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JsonReply {
    /// The error code
    error_code: ErrorCode,
    /// The error message to be displayed only in debug logs
    message: String,
    /// Additional fields to be included in the JSON response
    extra: serde_json::Map<String, serde_json::Value>,
}

impl JsonReply {
    /// Create a new Reply
    pub(crate) fn new(error_code: ErrorCode, message: impl fmt::Display) -> Self {
        Self { error_code, message: message.to_string(), extra: serde_json::Map::new() }
    }

    /// Add an additional field to the JSON response
    pub fn with_extra(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.extra.insert(key.to_string(), value.into());
        self
    }

    /// Serialize the Reply to a JSON string
    pub fn to_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("errorCode".to_string(), self.error_code.to_string().into());
        map.insert("message".to_string(), self.message.clone().into());
        map.extend(self.extra.clone());

        serde_json::Value::Object(map)
    }

    /// Get the HTTP status code for the error
    pub fn status_code(&self) -> u16 {
        match self.error_code {
            ErrorCode::Unavailable => http::StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::NotEnoughMoney
            | ErrorCode::VersionUnsupported
            | ErrorCode::OriginalPsbtRejected => http::StatusCode::BAD_REQUEST,
        }
        .as_u16()
    }
}

impl From<&ProtocolError> for JsonReply {
    fn from(e: &ProtocolError) -> Self {
        use ProtocolError::*;
        match e {
            OriginalPayload(e) => e.into(),
            #[cfg(feature = "v1")]
            V1(e) => JsonReply::new(OriginalPsbtRejected, e),
            #[cfg(feature = "v2")]
            V2(_) => JsonReply::new(Unavailable, "Receiver error"),
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            Self::OriginalPayload(e) => e.fmt(f),
            #[cfg(feature = "v1")]
            Self::V1(e) => e.fmt(f),
            #[cfg(feature = "v2")]
            Self::V2(e) => e.fmt(f),
        }
    }
}

impl error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Self::OriginalPayload(e) => e.source(),
            #[cfg(feature = "v1")]
            Self::V1(e) => e.source(),
            #[cfg(feature = "v2")]
            Self::V2(e) => e.source(),
        }
    }
}

impl From<InternalPayloadError> for Error {
    fn from(e: InternalPayloadError) -> Self {
        Error::Protocol(ProtocolError::OriginalPayload(e.into()))
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
    Utf8(std::str::Utf8Error),
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
            Utf8(_)
            | ParsePsbt(_)
            | InconsistentPsbt(_)
            | PrevTxOut(_)
            | MissingPayment
            | OriginalPsbtNotBroadcastable
            | InputOwned(_)
            | InputSeen(_)
            | PsbtBelowFeeRate(_, _) => JsonReply::new(OriginalPsbtRejected, e),

            FeeTooHigh(_, _) => JsonReply::new(NotEnoughMoney, e),

            SenderParams(e) => match e {
                super::optional_parameters::Error::UnknownVersion { supported_versions } => {
                    let supported_versions_json =
                        serde_json::to_string(supported_versions).unwrap_or_default();
                    JsonReply::new(VersionUnsupported, "This version of payjoin is not supported.")
                        .with_extra("supported", supported_versions_json)
                }
                super::optional_parameters::Error::FeeRate =>
                    JsonReply::new(OriginalPsbtRejected, e),
            },
        }
    }
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { self.0.fmt(f) }
}

impl fmt::Display for InternalPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalPayloadError::*;

        match &self {
            Utf8(e) => write!(f, "{e}"),
            ParsePsbt(e) => write!(f, "{e}"),
            SenderParams(e) => write!(f, "{e}"),
            InconsistentPsbt(e) => write!(f, "{e}"),
            PrevTxOut(e) => write!(f, "PrevTxOut Error: {e}"),
            MissingPayment => write!(f, "Missing payment."),
            OriginalPsbtNotBroadcastable => write!(f, "Can't broadcast. PSBT rejected by mempool."),
            InputOwned(_) => write!(f, "The receiver rejected the original PSBT."),
            InputSeen(_) => write!(f, "The receiver rejected the original PSBT."),
            PsbtBelowFeeRate(original_psbt_fee_rate, receiver_min_fee_rate) => write!(
                f,
                "Original PSBT fee rate too low: {original_psbt_fee_rate} < {receiver_min_fee_rate}."
            ),
            FeeTooHigh(proposed_fee_rate, max_fee_rate) => write!(
                f,
                "Effective receiver feerate exceeds maximum allowed feerate: {proposed_fee_rate} > {max_fee_rate}"
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

#[derive(Debug, PartialEq, Eq)]
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
#[derive(Debug, PartialEq, Eq)]
pub struct SelectionError(InternalSelectionError);

#[derive(Debug, PartialEq, Eq)]
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
#[derive(Debug, PartialEq, Eq)]
pub struct InputContributionError(InternalInputContributionError);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InternalInputContributionError {
    /// Total input value is not enough to cover additional output value
    ValueTooLow,
    /// Duplicate input detected. The same outpoint is already present in the transaction
    DuplicateInput(bitcoin::OutPoint),
}

impl fmt::Display for InputContributionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            InternalInputContributionError::ValueTooLow =>
                write!(f, "Total input value is not enough to cover additional output value"),
            InternalInputContributionError::DuplicateInput(outpoint) =>
                write!(f, "Duplicate input detected: {outpoint}"),
        }
    }
}

impl error::Error for InputContributionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.0 {
            InternalInputContributionError::ValueTooLow => None,
            InternalInputContributionError::DuplicateInput(_) => None,
        }
    }
}

impl From<InternalInputContributionError> for InputContributionError {
    fn from(value: InternalInputContributionError) -> Self { InputContributionError(value) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ImplementationError;

    #[test]
    fn test_json_reply_from_implementation_error() {
        struct AlwaysPanics;

        impl fmt::Display for AlwaysPanics {
            fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
                panic!("internal error should never display when converting to JsonReply");
            }
        }

        impl fmt::Debug for AlwaysPanics {
            fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
                panic!("internal error should never debug when converting to JsonReply");
            }
        }

        impl error::Error for AlwaysPanics {
            fn source(&self) -> Option<&(dyn error::Error + 'static)> {
                panic!("internal error should never be examined when converting to JsonReply");
            }
        }
        // Use a panicking error to ensure conversion does not touch internal formatting
        let internal = AlwaysPanics;
        let error = Error::Implementation(ImplementationError::new(internal));
        let reply = JsonReply::from(&error);
        let expected = JsonReply {
            error_code: ErrorCode::Unavailable,
            message: "Receiver error".to_string(),
            extra: serde_json::Map::new(),
        };
        assert_eq!(reply, expected);

        let json = reply.to_json();
        assert_eq!(
            json,
            serde_json::json!({
                "errorCode": ErrorCode::Unavailable.to_string(),
                "message": "Receiver error",
            })
        );
    }

    #[test]
    /// Create an implementation error that returns INTERNAL_SERVER_ERROR
    fn test_json_reply_with_500_status_code() {
        let error = Error::Implementation(ImplementationError::from("test error"));
        let reply = JsonReply::from(&error);

        assert_eq!(reply.status_code(), http::StatusCode::INTERNAL_SERVER_ERROR.as_u16());

        let json = reply.to_json();
        assert_eq!(json["errorCode"], "unavailable");
        assert_eq!(json["message"], "Receiver error");
    }

    #[test]
    /// Create a payload error that returns BAD_REQUEST
    fn test_json_reply_with_400_status_code() {
        let payload_error = PayloadError(InternalPayloadError::MissingPayment);
        let error = Error::Protocol(ProtocolError::OriginalPayload(payload_error));
        let reply = JsonReply::from(&error);

        assert_eq!(reply.status_code(), http::StatusCode::BAD_REQUEST.as_u16());

        let json = reply.to_json();
        assert_eq!(json["errorCode"], "original-psbt-rejected");
        assert_eq!(json["message"], "Missing payment.");
    }
}

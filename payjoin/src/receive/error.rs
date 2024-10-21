use std::error;
use std::fmt::{self, Display};

#[derive(Debug)]
pub enum Error {
    /// To be returned as HTTP 400
    BadRequest(RequestError),
    // To be returned as HTTP 500
    Server(Box<dyn error::Error>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            Self::BadRequest(e) => e.fmt(f),
            Self::Server(e) => write!(f, "Internal Server Error: {}", e),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Self::BadRequest(_) => None,
            Self::Server(e) => Some(e.as_ref()),
        }
    }
}

impl From<RequestError> for Error {
    fn from(e: RequestError) -> Self { Error::BadRequest(e) }
}

impl From<InternalRequestError> for Error {
    fn from(e: InternalRequestError) -> Self { Error::BadRequest(e.into()) }
}

#[cfg(feature = "v2")]
impl From<crate::v2::HpkeError> for Error {
    fn from(e: crate::v2::HpkeError) -> Self { Error::Server(Box::new(e)) }
}

#[cfg(feature = "v2")]
impl From<crate::v2::OhttpEncapsulationError> for Error {
    fn from(e: crate::v2::OhttpEncapsulationError) -> Self { Error::Server(Box::new(e)) }
}

/// Error that may occur when the request from sender is malformed.
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug)]
pub struct RequestError(InternalRequestError);

#[derive(Debug)]
pub(crate) enum InternalRequestError {
    Psbt(bitcoin::psbt::Error),
    Base64(bitcoin::base64::DecodeError),
    Io(std::io::Error),
    MissingHeader(&'static str),
    InvalidContentType(String),
    InvalidContentLength(std::num::ParseIntError),
    ContentLengthTooLarge(u64),
    SenderParams(super::optional_parameters::Error),
    /// The raw PSBT fails bip78-specific validation.
    InconsistentPsbt(crate::psbt::InconsistentPsbt),
    /// The prevtxout is missing
    PrevTxOut(crate::psbt::PrevTxOutError),
    /// The Original PSBT has no output for the receiver.
    MissingPayment,
    /// The original PSBT transaction fails the broadcast check
    OriginalPsbtNotBroadcastable,
    /// The sender is trying to spend the receiver input
    InputOwned(bitcoin::ScriptBuf),
    /// The expected input weight cannot be determined
    InputWeight(crate::psbt::InputWeightError),
    /// Original PSBT input has been seen before. Only automatic receivers, aka "interactive" in the spec
    /// look out for these to prevent probing attacks.
    InputSeen(bitcoin::OutPoint),
    /// Serde deserialization failed
    #[cfg(feature = "v2")]
    ParsePsbt(bitcoin::psbt::PsbtParseError),
    #[cfg(feature = "v2")]
    Utf8(std::string::FromUtf8Error),
    /// Original PSBT fee rate is below minimum fee rate set by the receiver.
    ///
    /// First argument is the calculated fee rate of the original PSBT.
    ///
    /// Second argument is the minimum fee rate optionaly set by the receiver.
    PsbtBelowFeeRate(bitcoin::FeeRate, bitcoin::FeeRate),
    /// Effective receiver feerate exceeds maximum allowed feerate
    FeeTooHigh(bitcoin::FeeRate, bitcoin::FeeRate),
}

impl From<InternalRequestError> for RequestError {
    fn from(value: InternalRequestError) -> Self { RequestError(value) }
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fn write_error(f: &mut fmt::Formatter, code: &str, message: impl Display) -> fmt::Result {
            write!(f, r#"{{ "errorCode": "{}", "message": "{}" }}"#, code, message)
        }

        match &self.0 {
            InternalRequestError::Psbt(e) => write_error(f, "psbt-error", e),
            InternalRequestError::Base64(e) => write_error(f, "base64-decode-error", e),
            InternalRequestError::Io(e) => write_error(f, "io-error", e),
            InternalRequestError::MissingHeader(header) =>
                write_error(f, "missing-header", &format!("Missing header: {}", header)),
            InternalRequestError::InvalidContentType(content_type) => write_error(
                f,
                "invalid-content-type",
                &format!("Invalid content type: {}", content_type),
            ),
            InternalRequestError::InvalidContentLength(e) =>
                write_error(f, "invalid-content-length", e),
            InternalRequestError::ContentLengthTooLarge(length) => write_error(
                f,
                "content-length-too-large",
                &format!("Content length too large: {}.", length),
            ),
            InternalRequestError::SenderParams(e) => match e {
                super::optional_parameters::Error::UnknownVersion => {
                    write!(
                        f,
                        r#"{{
                            "errorCode": "version-unsupported",
                            "supported": "{}",
                            "message": "This version of payjoin is not supported."
                        }}"#,
                        serde_json::to_string(&super::optional_parameters::SUPPORTED_VERSIONS)
                            .map_err(|_| fmt::Error)?
                    )
                }
                _ => write_error(f, "sender-params-error", e),
            },
            InternalRequestError::InconsistentPsbt(e) =>
                write_error(f, "original-psbt-rejected", e),
            InternalRequestError::PrevTxOut(e) =>
                write_error(f, "original-psbt-rejected", &format!("PrevTxOut Error: {}", e)),
            InternalRequestError::MissingPayment =>
                write_error(f, "original-psbt-rejected", "Missing payment."),
            InternalRequestError::OriginalPsbtNotBroadcastable => write_error(
                f,
                "original-psbt-rejected",
                "Can't broadcast. PSBT rejected by mempool.",
            ),
            InternalRequestError::InputOwned(_) =>
                write_error(f, "original-psbt-rejected", "The receiver rejected the original PSBT."),
            InternalRequestError::InputWeight(e) =>
                write_error(f, "original-psbt-rejected", &format!("InputWeight Error: {}", e)),
            InternalRequestError::InputSeen(_) =>
                write_error(f, "original-psbt-rejected", "The receiver rejected the original PSBT."),
            #[cfg(feature = "v2")]
            InternalRequestError::ParsePsbt(e) => write_error(f, "Error parsing PSBT:", e),
            #[cfg(feature = "v2")]
            InternalRequestError::Utf8(e) => write_error(f, "Error parsing PSBT:", e),
            InternalRequestError::PsbtBelowFeeRate(
                original_psbt_fee_rate,
                receiver_min_fee_rate,
            ) => write_error(
                f,
                "original-psbt-rejected",
                &format!(
                    "Original PSBT fee rate too low: {} < {}.",
                    original_psbt_fee_rate, receiver_min_fee_rate
                ),
            ),
            InternalRequestError::FeeTooHigh(proposed_feerate, max_feerate) => write_error(
                f,
                "original-psbt-rejected",
                &format!(
                    "Effective receiver feerate exceeds maximum allowed feerate: {} > {}",
                    proposed_feerate, max_feerate
                ),
            ),
        }
    }
}

impl std::error::Error for RequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            InternalRequestError::Psbt(e) => Some(e),
            InternalRequestError::Base64(e) => Some(e),
            InternalRequestError::Io(e) => Some(e),
            InternalRequestError::InvalidContentLength(e) => Some(e),
            InternalRequestError::SenderParams(e) => Some(e),
            InternalRequestError::InconsistentPsbt(e) => Some(e),
            InternalRequestError::PrevTxOut(e) => Some(e),
            InternalRequestError::InputWeight(e) => Some(e),
            #[cfg(feature = "v2")]
            InternalRequestError::ParsePsbt(e) => Some(e),
            #[cfg(feature = "v2")]
            InternalRequestError::Utf8(e) => Some(e),
            InternalRequestError::PsbtBelowFeeRate(_, _) => None,
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
    /// Missing previous txout information
    PrevTxOut(crate::psbt::PrevTxOutError),
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
            InternalInputContributionError::PrevTxOut(e) =>
                write!(f, "Missing previous txout information: {}", e),
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

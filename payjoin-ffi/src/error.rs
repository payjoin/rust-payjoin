use std::error;
use std::sync::Arc;

/// Error arising due to the specific receiver implementation
///
/// e.g. database errors, network failures, wallet errors
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct ImplementationError(#[from] payjoin::ImplementationError);

impl ImplementationError {
    pub fn new(e: impl error::Error + Send + Sync + 'static) -> Self {
        ImplementationError(payjoin::ImplementationError::new(e))
    }
}

impl From<ImplementationError> for payjoin::ImplementationError {
    fn from(value: ImplementationError) -> Self { value.0 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum HpkeErrorKind {
    InvalidPublicKey,
    Hpke,
    InvalidKeyLength,
    PayloadTooLarge,
    PayloadTooShort,
    UnexpectedSecp256k1Error,
    Other,
}

impl From<payjoin::HpkeErrorKind> for HpkeErrorKind {
    fn from(value: payjoin::HpkeErrorKind) -> Self {
        match value {
            payjoin::HpkeErrorKind::InvalidPublicKey => Self::InvalidPublicKey,
            payjoin::HpkeErrorKind::Hpke => Self::Hpke,
            payjoin::HpkeErrorKind::InvalidKeyLength => Self::InvalidKeyLength,
            payjoin::HpkeErrorKind::PayloadTooLarge => Self::PayloadTooLarge,
            payjoin::HpkeErrorKind::PayloadTooShort => Self::PayloadTooShort,
            payjoin::HpkeErrorKind::UnexpectedSecp256k1Error => Self::UnexpectedSecp256k1Error,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("{message}")]
pub struct HpkeError {
    kind: HpkeErrorKind,
    message: String,
    payload_too_large_actual: Option<u64>,
    payload_too_large_max: Option<u64>,
}

impl From<payjoin::HpkeErrorDetails> for HpkeError {
    fn from(value: payjoin::HpkeErrorDetails) -> Self {
        Self {
            kind: value.kind().into(),
            message: value.message().to_owned(),
            payload_too_large_actual: value.payload_too_large_actual().map(|value| value as u64),
            payload_too_large_max: value.payload_too_large_max().map(|value| value as u64),
        }
    }
}

#[uniffi::export]
impl HpkeError {
    pub fn kind(&self) -> HpkeErrorKind { self.kind }

    pub fn message(&self) -> String { self.message.clone() }

    pub fn payload_too_large_actual(&self) -> Option<u64> { self.payload_too_large_actual }

    pub fn payload_too_large_max(&self) -> Option<u64> { self.payload_too_large_max }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OhttpEncapsulationErrorKind {
    Http,
    Ohttp,
    Bhttp,
    ParseUrl,
    Other,
}

impl From<payjoin::OhttpEncapsulationErrorKind> for OhttpEncapsulationErrorKind {
    fn from(value: payjoin::OhttpEncapsulationErrorKind) -> Self {
        match value {
            payjoin::OhttpEncapsulationErrorKind::Http => Self::Http,
            payjoin::OhttpEncapsulationErrorKind::Ohttp => Self::Ohttp,
            payjoin::OhttpEncapsulationErrorKind::Bhttp => Self::Bhttp,
            payjoin::OhttpEncapsulationErrorKind::ParseUrl => Self::ParseUrl,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("{message}")]
pub struct OhttpEncapsulationError {
    kind: OhttpEncapsulationErrorKind,
    message: String,
}

impl From<payjoin::OhttpEncapsulationErrorDetails> for OhttpEncapsulationError {
    fn from(value: payjoin::OhttpEncapsulationErrorDetails) -> Self {
        Self { kind: value.kind().into(), message: value.message().to_owned() }
    }
}

#[uniffi::export]
impl OhttpEncapsulationError {
    pub fn kind(&self) -> OhttpEncapsulationErrorKind { self.kind }

    pub fn message(&self) -> String { self.message.clone() }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DirectoryResponseErrorKind {
    InvalidSize,
    OhttpDecapsulation,
    UnexpectedStatusCode,
    Other,
}

impl From<payjoin::DirectoryResponseErrorKind> for DirectoryResponseErrorKind {
    fn from(value: payjoin::DirectoryResponseErrorKind) -> Self {
        match value {
            payjoin::DirectoryResponseErrorKind::InvalidSize => Self::InvalidSize,
            payjoin::DirectoryResponseErrorKind::OhttpDecapsulation => Self::OhttpDecapsulation,
            payjoin::DirectoryResponseErrorKind::UnexpectedStatusCode => Self::UnexpectedStatusCode,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("{message}")]
pub struct DirectoryResponseError {
    kind: DirectoryResponseErrorKind,
    message: String,
    invalid_size: Option<u64>,
    unexpected_status_code: Option<u16>,
    ohttp_error: Option<Arc<OhttpEncapsulationError>>,
}

impl From<payjoin::DirectoryResponseErrorDetails> for DirectoryResponseError {
    fn from(value: payjoin::DirectoryResponseErrorDetails) -> Self {
        Self {
            kind: value.kind().into(),
            message: value.message().to_owned(),
            invalid_size: value.invalid_size().map(|value| value as u64),
            unexpected_status_code: value.unexpected_status_code(),
            ohttp_error: value.ohttp_error().cloned().map(|details| Arc::new(details.into())),
        }
    }
}

#[uniffi::export]
impl DirectoryResponseError {
    pub fn kind(&self) -> DirectoryResponseErrorKind { self.kind }

    pub fn message(&self) -> String { self.message.clone() }

    pub fn invalid_size(&self) -> Option<u64> { self.invalid_size }

    pub fn unexpected_status_code(&self) -> Option<u16> { self.unexpected_status_code }

    pub fn ohttp_error(&self) -> Option<Arc<OhttpEncapsulationError>> { self.ohttp_error.clone() }
}

#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("Error de/serializing JSON object: {0}")]
pub struct SerdeJsonError(#[from] serde_json::Error);

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiValidationError {
    #[error("Amount out of range: {amount_sat} sats (max {max_sat})")]
    AmountOutOfRange { amount_sat: u64, max_sat: u64 },
    #[error("{field} script is empty")]
    ScriptEmpty { field: String },
    #[error("{field} script too large: {len} bytes (max {max})")]
    ScriptTooLarge { field: String, len: u64, max: u64 },
    #[error("Witness stack has {count} items (max {max})")]
    WitnessItemsTooMany { count: u64, max: u64 },
    #[error("Witness item {index} too large: {len} bytes (max {max})")]
    WitnessItemTooLarge { index: u64, len: u64, max: u64 },
    #[error("Witness stack too large: {len} bytes (max {max})")]
    WitnessTooLarge { len: u64, max: u64 },
    #[error("Weight out of range: {weight_units} wu (max {max_wu})")]
    WeightOutOfRange { weight_units: u64, max_wu: u64 },
    #[error("Fee rate out of range: {value} {unit}")]
    FeeRateOutOfRange { value: u64, unit: String },
    #[error("Expiration out of range: {seconds} seconds (max {max})")]
    ExpirationOutOfRange { seconds: u64, max: u64 },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, uniffi::Error)]
pub enum ForeignError {
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<uniffi::UnexpectedUniFFICallbackError> for ForeignError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::InternalError("Unexpected Uniffi callback error".to_string())
    }
}

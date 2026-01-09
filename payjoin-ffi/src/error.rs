use std::error;

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

#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("Error de/serializing JSON object: {0}")]
pub struct SerdeJsonError(#[from] serde_json::Error);

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PrimitiveError {
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

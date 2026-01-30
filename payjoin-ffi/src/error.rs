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

#[derive(Debug, Clone, thiserror::Error, uniffi::Object)]
#[error("PSBT input #{index} validation failed: {message}")]
pub struct PsbtInputsError {
    index: usize,
    message: String,
}

impl PsbtInputsError {
    /// Create a new PsbtInputsError
    pub fn new(index: usize, message: String) -> Self { Self { index, message } }
}

#[uniffi::export]
impl PsbtInputsError {
    pub fn input_index(&self) -> u64 { self.index as u64 }

    pub fn error_message(&self) -> String { self.message.clone() }
}

impl From<payjoin::psbt::PsbtInputsError> for PsbtInputsError {
    fn from(value: payjoin::psbt::PsbtInputsError) -> Self {
        let index = value.index();
        let message = if let Some(source) = std::error::Error::source(&value) {
            source.to_string()
        } else {
            value.to_string()
        };

        PsbtInputsError { index, message }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psbt_inputs_error_preserves_index() {
        let error = PsbtInputsError::new(5, "Missing UTXO information".to_string());

        assert_eq!(error.input_index(), 5);
        assert_eq!(error.error_message(), "Missing UTXO information");

        let error_string = error.to_string();
        assert!(error_string.contains("input #5"));
        assert!(error_string.contains("Missing UTXO"));
    }

    #[test]
    fn test_psbt_inputs_error_index_zero() {
        let error = PsbtInputsError::new(0, "Invalid previous transaction output".to_string());

        assert_eq!(error.input_index(), 0);
        assert!(error.error_message().contains("Invalid previous transaction output"));
    }

    #[test]
    fn test_psbt_inputs_error_large_index() {
        let error = PsbtInputsError::new(999, "Test error".to_string());

        assert_eq!(error.input_index(), 999);
        assert_eq!(error.error_message(), "Test error");
    }

    #[test]
    fn test_error_display_format() {
        let error = PsbtInputsError::new(7, "missing UTXO information".to_string());
        let display = format!("{}", error);

        assert!(display.contains("#7"));
        assert!(display.contains("missing UTXO information"));
    }

    #[test]
    fn test_error_clone() {
        let error = PsbtInputsError::new(2, "Test message".to_string());
        let cloned = error.clone();

        assert_eq!(error.input_index(), cloned.input_index());
        assert_eq!(error.error_message(), cloned.error_message());
    }

    #[test]
    fn test_multiple_errors_different_indices() {
        let errors = [
            PsbtInputsError::new(0, "Error at input 0".to_string()),
            PsbtInputsError::new(1, "Error at input 1".to_string()),
            PsbtInputsError::new(2, "Error at input 2".to_string()),
        ];

        for (expected_index, error) in errors.iter().enumerate() {
            assert_eq!(error.input_index(), expected_index as u64);
        }
    }
}

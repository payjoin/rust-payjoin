use std::sync::Arc;

use payjoin::receive;

use super::PlainOutPoint;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OutputSubstitutionErrorKind {
    DecreasedValueWhenDisabled,
    ScriptPubKeyChangedWhenDisabled,
    NotEnoughOutputs,
    InvalidDrainScript,
    Other,
}

impl From<receive::OutputSubstitutionErrorKind> for OutputSubstitutionErrorKind {
    fn from(value: receive::OutputSubstitutionErrorKind) -> Self {
        match value {
            receive::OutputSubstitutionErrorKind::DecreasedValueWhenDisabled =>
                Self::DecreasedValueWhenDisabled,
            receive::OutputSubstitutionErrorKind::ScriptPubKeyChangedWhenDisabled =>
                Self::ScriptPubKeyChangedWhenDisabled,
            receive::OutputSubstitutionErrorKind::NotEnoughOutputs => Self::NotEnoughOutputs,
            receive::OutputSubstitutionErrorKind::InvalidDrainScript => Self::InvalidDrainScript,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum InputContributionErrorKind {
    ValueTooLow,
    DuplicateInput,
    Other,
}

impl From<receive::InputContributionErrorKind> for InputContributionErrorKind {
    fn from(value: receive::InputContributionErrorKind) -> Self {
        match value {
            receive::InputContributionErrorKind::ValueTooLow => Self::ValueTooLow,
            receive::InputContributionErrorKind::DuplicateInput => Self::DuplicateInput,
            _ => Self::Other,
        }
    }
}

/// Protocol error raised during output substitution.
#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error("{message}")]
pub struct OutputSubstitutionProtocolError {
    kind: OutputSubstitutionErrorKind,
    message: String,
}

impl From<receive::OutputSubstitutionError> for OutputSubstitutionProtocolError {
    fn from(value: receive::OutputSubstitutionError) -> Self {
        Self { kind: value.kind().into(), message: value.to_string() }
    }
}

#[uniffi::export]
impl OutputSubstitutionProtocolError {
    pub fn kind(&self) -> OutputSubstitutionErrorKind { self.kind }

    pub fn message(&self) -> String { self.message.clone() }
}

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
#[error("{message}")]
pub struct InputContributionError {
    kind: InputContributionErrorKind,
    message: String,
    duplicate_input_outpoint: Option<PlainOutPoint>,
}

impl From<receive::InputContributionError> for InputContributionError {
    fn from(value: receive::InputContributionError) -> Self {
        Self {
            kind: value.kind().into(),
            message: value.to_string(),
            duplicate_input_outpoint: value.duplicate_input_outpoint().map(Into::into),
        }
    }
}

#[uniffi::export]
impl InputContributionError {
    pub fn kind(&self) -> InputContributionErrorKind { self.kind }

    pub fn message(&self) -> String { self.message.clone() }

    pub fn duplicate_input_outpoint(&self) -> Option<PlainOutPoint> {
        self.duplicate_input_outpoint.clone()
    }
}

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

#[cfg(all(test, feature = "_test-utils"))]
mod tests {
    use std::str::FromStr;

    use payjoin::bitcoin::{Address, Amount, Network, Psbt, ScriptBuf, TxOut};
    use payjoin::receive::v1::{Headers, UncheckedOriginalPayload};
    use payjoin_test_utils::{ORIGINAL_PSBT, QUERY_PARAMS, RECEIVER_INPUT_CONTRIBUTION};

    use super::*;

    struct TestHeaders {
        content_type: Option<&'static str>,
        content_length: String,
    }

    impl Headers for TestHeaders {
        fn get_header(&self, key: &str) -> Option<&str> {
            match key {
                "content-type" => self.content_type,
                "content-length" => Some(self.content_length.as_str()),
                _ => None,
            }
        }
    }

    fn wants_outputs_from_test_vector() -> payjoin::receive::v1::WantsOutputs {
        let body = ORIGINAL_PSBT.as_bytes();
        let headers = TestHeaders {
            content_type: Some("text/plain"),
            content_length: body.len().to_string(),
        };
        let receiver_address = Address::from_str("3CZZi7aWFugaCdUCS15dgrUUViupmB8bVM")
            .expect("known address should parse")
            .require_network(Network::Bitcoin)
            .expect("known address should match network");

        UncheckedOriginalPayload::from_request(body, QUERY_PARAMS, headers)
            .expect("test vector should parse")
            .assume_interactive_receiver()
            .check_inputs_not_owned(&mut |_| Ok(false))
            .expect("proposal should not spend receiver inputs")
            .check_no_inputs_seen_before(&mut |_| Ok(false))
            .expect("proposal should not contain seen inputs")
            .identify_receiver_outputs(&mut |script| {
                Ok(Address::from_script(script, Network::Bitcoin)
                    .expect("known script should decode")
                    == receiver_address)
            })
            .expect("receiver output should be identified")
    }

    fn wants_inputs_from_test_vector() -> payjoin::receive::v1::WantsInputs {
        wants_outputs_from_test_vector().commit_outputs()
    }

    fn receiver_output_from_test_vector() -> TxOut {
        let receiver_script = Address::from_str("3CZZi7aWFugaCdUCS15dgrUUViupmB8bVM")
            .expect("known address should parse")
            .require_network(Network::Bitcoin)
            .expect("known address should match network")
            .script_pubkey();
        let original = Psbt::from_str(ORIGINAL_PSBT).expect("known PSBT should parse");

        original
            .unsigned_tx
            .output
            .iter()
            .find(|output| output.script_pubkey == receiver_script)
            .cloned()
            .expect("test vector should pay the receiver")
    }

    fn receiver_input_pair() -> payjoin::receive::InputPair {
        let proposal_psbt =
            Psbt::from_str(RECEIVER_INPUT_CONTRIBUTION).expect("known PSBT should parse");
        payjoin::receive::InputPair::new(
            proposal_psbt.unsigned_tx.input[1].clone(),
            proposal_psbt.inputs[1].clone(),
            None,
        )
        .expect("test vector input should be valid")
    }

    fn receiver_input_outpoint() -> PlainOutPoint {
        let proposal_psbt =
            Psbt::from_str(RECEIVER_INPUT_CONTRIBUTION).expect("known PSBT should parse");
        PlainOutPoint::from(proposal_psbt.unsigned_tx.input[1].previous_output)
    }

    fn wants_inputs_with_minimum_contribution(
        required_delta: Amount,
    ) -> payjoin::receive::v1::WantsInputs {
        let mut receiver_output = receiver_output_from_test_vector();
        let drain_script = receiver_output.script_pubkey.clone();
        receiver_output.value += required_delta;

        wants_outputs_from_test_vector()
            .replace_receiver_outputs(vec![receiver_output], &drain_script)
            .expect("higher receiver output should be accepted")
            .commit_outputs()
    }

    fn low_value_input_pair() -> payjoin::receive::InputPair {
        let proposal_psbt =
            Psbt::from_str(RECEIVER_INPUT_CONTRIBUTION).expect("known PSBT should parse");
        let mut psbt_input = proposal_psbt.inputs[1].clone();
        let mut witness_utxo =
            psbt_input.witness_utxo.clone().expect("test vector input should include witness UTXO");
        witness_utxo.value = Amount::from_sat(123);
        psbt_input.witness_utxo = Some(witness_utxo);

        payjoin::receive::InputPair::new(
            proposal_psbt.unsigned_tx.input[1].clone(),
            psbt_input,
            None,
        )
        .expect("low-value test input should remain structurally valid")
    }

    #[test]
    fn test_output_substitution_error_exposes_kind() {
        let receiver_output = receiver_output_from_test_vector();
        let missing_drain_script = ScriptBuf::new();
        let error = wants_outputs_from_test_vector()
            .replace_receiver_outputs(vec![receiver_output], &missing_drain_script)
            .expect_err("missing drain script should fail");
        let OutputSubstitutionError::Protocol(protocol) = OutputSubstitutionError::from(error)
        else {
            panic!("expected protocol substitution error");
        };

        assert_eq!(protocol.kind(), OutputSubstitutionErrorKind::InvalidDrainScript);
        assert_eq!(
            protocol.message(),
            "The provided drain script could not be identified in the provided replacement outputs"
        );
    }

    #[test]
    fn test_input_contribution_error_exposes_duplicate_outpoint() {
        let input = receiver_input_pair();
        let contributed = wants_inputs_from_test_vector()
            .contribute_inputs(vec![input.clone()])
            .expect("first contribution should succeed");
        let error = contributed
            .contribute_inputs(vec![input])
            .expect_err("duplicate contribution should fail");
        let error = InputContributionError::from(error);
        let expected_outpoint = receiver_input_outpoint();

        assert_eq!(error.kind(), InputContributionErrorKind::DuplicateInput);
        let outpoint =
            error.duplicate_input_outpoint().expect("duplicate outpoint should be present");
        assert_eq!(outpoint.txid, expected_outpoint.txid);
        assert_eq!(outpoint.vout, expected_outpoint.vout);
        assert_eq!(
            error.message(),
            format!("Duplicate input detected: {}:{}", outpoint.txid, outpoint.vout)
        );
    }

    #[test]
    fn test_input_contribution_error_exposes_value_too_low_kind() {
        let error = wants_inputs_with_minimum_contribution(Amount::from_sat(1_000))
            .contribute_inputs(vec![low_value_input_pair()])
            .expect_err("low value contribution should fail");
        let error = InputContributionError::from(error);

        assert_eq!(error.kind(), InputContributionErrorKind::ValueTooLow);
        assert!(error.duplicate_input_outpoint().is_none());
        assert_eq!(
            error.message(),
            "Total input value is not enough to cover additional output value"
        );
    }
}

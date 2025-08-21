use std::fmt;

use bitcoin::locktime::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::Sequence;

use crate::error_codes::ErrorCode;

/// Error building a Sender from a SenderBuilder.
///
/// This error is unrecoverable.
#[derive(Debug)]
pub struct BuildSenderError(InternalBuildSenderError);

#[derive(Debug, PartialEq)]
pub(crate) enum InternalBuildSenderError {
    InvalidOriginalInput(crate::psbt::PsbtInputsError),
    InconsistentOriginalPsbt(crate::psbt::InconsistentPsbt),
    NoInputs,
    PayeeValueNotEqual,
    NoOutputs,
    MultiplePayeeOutputs,
    MissingPayeeOutput,
    FeeOutputValueLowerThanFeeContribution,
    AmbiguousChangeOutput,
    ChangeIndexOutOfBounds,
    ChangeIndexPointsAtPayee,
    InputWeight(crate::psbt::InputWeightError),
    AddressType(crate::psbt::AddressTypeError),
}

impl From<InternalBuildSenderError> for BuildSenderError {
    fn from(value: InternalBuildSenderError) -> Self { BuildSenderError(value) }
}

impl From<crate::psbt::AddressTypeError> for BuildSenderError {
    fn from(value: crate::psbt::AddressTypeError) -> Self {
        BuildSenderError(InternalBuildSenderError::AddressType(value))
    }
}

impl fmt::Display for BuildSenderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalBuildSenderError::*;

        match &self.0 {
            InvalidOriginalInput(e) => write!(f, "an input in the original transaction is invalid: {e:#?}"),
            InconsistentOriginalPsbt(e) => write!(f, "the original transaction is inconsistent: {e:#?}"),
            NoInputs => write!(f, "the original transaction has no inputs"),
            PayeeValueNotEqual => write!(f, "the value in original transaction doesn't equal value requested in the payment link"),
            NoOutputs => write!(f, "the original transaction has no outputs"),
            MultiplePayeeOutputs => write!(f, "the original transaction has more than one output belonging to the payee"),
            MissingPayeeOutput => write!(f, "the output belonging to payee is missing from the original transaction"),
            FeeOutputValueLowerThanFeeContribution => write!(f, "the value of fee output is lower than maximum allowed contribution"),
            AmbiguousChangeOutput => write!(f, "can not determine which output is change because there's more than two outputs"),
            ChangeIndexOutOfBounds => write!(f, "fee output index is points out of bounds"),
            ChangeIndexPointsAtPayee => write!(f, "fee output index is points at output belonging to the payee"),
            AddressType(e) => write!(f, "can not determine input address type: {e}"),
            InputWeight(e) => write!(f, "can not determine expected input weight: {e}"),
        }
    }
}

impl std::error::Error for BuildSenderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalBuildSenderError::*;

        match &self.0 {
            InvalidOriginalInput(error) => Some(error),
            InconsistentOriginalPsbt(error) => Some(error),
            NoInputs => None,
            PayeeValueNotEqual => None,
            NoOutputs => None,
            MultiplePayeeOutputs => None,
            MissingPayeeOutput => None,
            FeeOutputValueLowerThanFeeContribution => None,
            AmbiguousChangeOutput => None,
            ChangeIndexOutOfBounds => None,
            ChangeIndexPointsAtPayee => None,
            AddressType(error) => Some(error),
            InputWeight(error) => Some(error),
        }
    }
}

/// Error that may occur when the response from receiver is malformed.
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug)]
pub struct ValidationError(InternalValidationError);

#[derive(Debug)]
pub(crate) enum InternalValidationError {
    #[cfg(feature = "v1")]
    Parse,
    #[cfg(feature = "v1")]
    ContentTooLarge,
    Proposal(InternalProposalError),
    #[cfg(feature = "v2")]
    V2Encapsulation(crate::send::v2::EncapsulationError),
}

impl From<InternalValidationError> for ValidationError {
    fn from(value: InternalValidationError) -> Self { ValidationError(value) }
}

impl From<crate::psbt::AddressTypeError> for ValidationError {
    fn from(value: crate::psbt::AddressTypeError) -> Self {
        ValidationError(InternalValidationError::Proposal(
            InternalProposalError::InvalidAddressType(value),
        ))
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalValidationError::*;

        match &self.0 {
            #[cfg(feature = "v1")]
            Parse => write!(f, "couldn't decode as PSBT or JSON",),
            #[cfg(feature = "v1")]
            ContentTooLarge => {
                use crate::MAX_CONTENT_LENGTH;
                write!(f, "content is larger than {MAX_CONTENT_LENGTH} bytes")
            }
            Proposal(e) => write!(f, "proposal PSBT error: {e}"),
            #[cfg(feature = "v2")]
            V2Encapsulation(e) => write!(f, "v2 encapsulation error: {e}"),
        }
    }
}

impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalValidationError::*;

        match &self.0 {
            #[cfg(feature = "v1")]
            Parse => None,
            #[cfg(feature = "v1")]
            ContentTooLarge => None,
            Proposal(e) => Some(e),
            #[cfg(feature = "v2")]
            V2Encapsulation(e) => Some(e),
        }
    }
}

/// Error that may occur when the proposal PSBT from receiver is malformed.
#[derive(Debug)]
pub(crate) enum InternalProposalError {
    InvalidAddressType(crate::psbt::AddressTypeError),
    NoInputs,
    PrevTxOut(crate::psbt::PrevTxOutError),
    InputWeight(crate::psbt::InputWeightError),
    VersionsDontMatch { proposed: Version, original: Version },
    LockTimesDontMatch { proposed: LockTime, original: LockTime },
    SenderTxinSequenceChanged { proposed: Sequence, original: Sequence },
    SenderTxinContainsFinalScriptSig,
    SenderTxinContainsFinalScriptWitness,
    TxInContainsKeyPaths,
    ContainsPartialSigs,
    ReceiverTxinNotFinalized,
    ReceiverTxinMissingUtxoInfo,
    MixedSequence,
    MissingOrShuffledInputs,
    TxOutContainsKeyPaths,
    FeeContributionExceedsMaximum,
    DisallowedOutputSubstitution,
    OutputValueDecreased,
    MissingOrShuffledOutputs,
    AbsoluteFeeDecreased,
    PayeeTookContributedFee,
    FeeContributionPaysOutputSizeIncrease,
    FeeRateBelowMinimum,
    Psbt(bitcoin::psbt::Error),
}

impl From<crate::psbt::AddressTypeError> for InternalProposalError {
    fn from(value: crate::psbt::AddressTypeError) -> Self {
        InternalProposalError::InvalidAddressType(value)
    }
}

impl fmt::Display for InternalProposalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalProposalError::*;

        match &self {
            InvalidAddressType(e) => write!(f, "invalid input address type: {e}"),
            NoInputs => write!(f, "PSBT doesn't have any inputs"),
            PrevTxOut(e) => write!(f, "missing previous txout information: {e}"),
            InputWeight(e) => write!(f, "can not determine expected input weight: {e}"),
            VersionsDontMatch { proposed, original, } => write!(f, "proposed transaction version {proposed} doesn't match the original {original}"),
            LockTimesDontMatch { proposed, original, } => write!(f, "proposed transaction lock time {proposed} doesn't match the original {original}"),
            SenderTxinSequenceChanged { proposed, original, } => write!(f, "proposed transaction sequence number {proposed} doesn't match the original {original}"),
            SenderTxinContainsFinalScriptSig => write!(f, "an input in proposed transaction belonging to the sender contains finalized non-witness signature"),
            SenderTxinContainsFinalScriptWitness => write!(f, "an input in proposed transaction belonging to the sender contains finalized witness signature"),
            TxInContainsKeyPaths => write!(f, "proposed transaction inputs contain key paths"),
            ContainsPartialSigs => write!(f, "an input in proposed transaction belonging to the sender contains partial signatures"),
            ReceiverTxinNotFinalized => write!(f, "an input in proposed transaction belonging to the receiver is not finalized"),
            ReceiverTxinMissingUtxoInfo => write!(f, "an input in proposed transaction belonging to the receiver is missing UTXO information"),
            MixedSequence => write!(f, "inputs of proposed transaction contain mixed sequence numbers"),
            MissingOrShuffledInputs => write!(f, "proposed transaction is missing inputs of the sender or they are shuffled"),
            TxOutContainsKeyPaths => write!(f, "proposed transaction outputs contain key paths"),
            FeeContributionExceedsMaximum => write!(f, "fee contribution exceeds allowed maximum"),
            DisallowedOutputSubstitution => write!(f, "the receiver change output despite it being disallowed"),
            OutputValueDecreased => write!(f, "the amount in our non-fee output was decreased"),
            MissingOrShuffledOutputs => write!(f, "proposed transaction is missing outputs of the sender or they are shuffled"),
            AbsoluteFeeDecreased => write!(f, "abslute fee of proposed transaction is lower than original"),
            PayeeTookContributedFee => write!(f, "payee tried to take fee contribution for himself"),
            FeeContributionPaysOutputSizeIncrease => write!(f, "fee contribution pays for additional outputs"),
            FeeRateBelowMinimum =>  write!(f, "the fee rate of proposed transaction is below minimum"),
            Psbt(e) => write!(f, "psbt error: {e}"),
        }
    }
}

impl std::error::Error for InternalProposalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalProposalError::*;

        match self {
            InvalidAddressType(error) => Some(error),
            NoInputs => None,
            PrevTxOut(error) => Some(error),
            InputWeight(error) => Some(error),
            VersionsDontMatch { proposed: _, original: _ } => None,
            LockTimesDontMatch { proposed: _, original: _ } => None,
            SenderTxinSequenceChanged { proposed: _, original: _ } => None,
            SenderTxinContainsFinalScriptSig => None,
            SenderTxinContainsFinalScriptWitness => None,
            TxInContainsKeyPaths => None,
            ContainsPartialSigs => None,
            ReceiverTxinNotFinalized => None,
            ReceiverTxinMissingUtxoInfo => None,
            MixedSequence => None,
            MissingOrShuffledInputs => None,
            TxOutContainsKeyPaths => None,
            FeeContributionExceedsMaximum => None,
            DisallowedOutputSubstitution => None,
            OutputValueDecreased => None,
            MissingOrShuffledOutputs => None,
            AbsoluteFeeDecreased => None,
            PayeeTookContributedFee => None,
            FeeContributionPaysOutputSizeIncrease => None,
            FeeRateBelowMinimum => None,
            Psbt(error) => Some(error),
        }
    }
}

/// Represent an error returned by Payjoin receiver.
pub enum ResponseError {
    /// `WellKnown` Errors are defined in the [`BIP78::ReceiverWellKnownError`] spec.
    ///
    /// It is safe to display `WellKnown` errors to end users.
    ///
    /// [`BIP78::ReceiverWellKnownError`]: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#user-content-Receivers_well_known_errors
    WellKnown(WellKnownError),

    /// Errors caused by malformed responses.
    Validation(ValidationError),

    /// `Unrecognized` Errors are NOT defined in the [`BIP78::ReceiverWellKnownError`] spec.
    ///
    /// It is NOT safe to display `Unrecognized` errors to end users as they could be used
    /// maliciously to phish a non technical user. Only display them in debug logs.
    ///
    /// [`BIP78::ReceiverWellKnownError`]: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#user-content-Receivers_well_known_errors
    Unrecognized { error_code: String, message: String },
}

impl std::error::Error for ResponseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ResponseError::*;

        match self {
            WellKnown(error) => Some(error),
            Validation(error) => Some(error),
            Unrecognized { .. } => None,
        }
    }
}

impl From<InternalValidationError> for ResponseError {
    fn from(value: InternalValidationError) -> Self { Self::Validation(ValidationError(value)) }
}

impl From<InternalProposalError> for ResponseError {
    fn from(value: InternalProposalError) -> Self {
        ResponseError::Validation(ValidationError(InternalValidationError::Proposal(value)))
    }
}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::WellKnown(e) => e.fmt(f),
            Self::Validation(e) => write!(f, "The receiver sent an invalid response: {e}"),

            // Do NOT display unrecognized errors to end users, only debug logs
            Self::Unrecognized { .. } => write!(f, "The receiver sent an unrecognized error."),
        }
    }
}

impl fmt::Debug for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::WellKnown(e) => {
                let json = serde_json::json!({
                    "errorCode": e.code.to_string(),
                    "message": e.message
                });
                write!(f, "Well known error: {json}")
            }
            Self::Validation(e) => write!(f, "Validation({e:?})"),

            Self::Unrecognized { error_code, message } => {
                let json = serde_json::json!({
                    "errorCode": error_code,
                    "message": message
                });
                write!(f, "Unrecognized error: {json}")
            }
        }
    }
}

/// A well-known error that can be safely displayed to end users.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WellKnownError {
    pub(crate) code: ErrorCode,
    pub(crate) message: String,
    pub(crate) supported_versions: Option<Vec<u64>>,
}

impl std::error::Error for WellKnownError {}

impl core::fmt::Display for WellKnownError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.code {
            ErrorCode::Unavailable => write!(f, "The payjoin endpoint is not available for now."),
            ErrorCode::NotEnoughMoney => write!(f, "The receiver added some inputs but could not bump the fee of the payjoin proposal."),
            ErrorCode::VersionUnsupported => {
                if let Some(supported) = &self.supported_versions {
                    write!(f, "This version of payjoin is not supported. Use version {supported:?}.")
                } else {
                    write!(f, "This version of payjoin is not supported.")
                }
            }
            ErrorCode::OriginalPsbtRejected => write!(f, "The receiver rejected the original PSBT."),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_parse_json() {
        let known_str_error = r#"{"errorCode":"version-unsupported", "message":"custom message here", "supported": [1, 2]}"#;
        match ResponseError::parse(known_str_error) {
            ResponseError::WellKnown(e) => {
                assert_eq!(e.code, ErrorCode::VersionUnsupported);
                assert_eq!(e.message, "custom message here");
                assert_eq!(
                    e.to_string(),
                    "This version of payjoin is not supported. Use version [1, 2]."
                );
            }
            _ => panic!("Expected WellKnown error"),
        };
        let unrecognized_error = r#"{"errorCode":"random", "message":"random"}"#;
        assert!(matches!(
            ResponseError::parse(unrecognized_error),
            ResponseError::Unrecognized { .. }
        ));
        let invalid_json_error = json!({
            "err": "random",
            "message": "This version of payjoin is not supported."
        });
        assert!(matches!(
            ResponseError::from_json(invalid_json_error),
            ResponseError::Validation(_)
        ));
    }
}

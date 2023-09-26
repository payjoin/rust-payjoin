use std::fmt;

use bitcoin::locktime::absolute::LockTime;
use bitcoin::Sequence;

use crate::input_type::{InputType, InputTypeError};

/// Error that may occur when the response from receiver is malformed.
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug)]
pub struct ValidationError {
    internal: InternalValidationError,
}

#[derive(Debug)]
pub(crate) enum InternalValidationError {
    Psbt(bitcoin::psbt::PsbtParseError),
    Io(std::io::Error),
    InvalidInputType(InputTypeError),
    InvalidProposedInput(crate::psbt::PrevTxOutError),
    VersionsDontMatch { proposed: i32, original: i32 },
    LockTimesDontMatch { proposed: LockTime, original: LockTime },
    SenderTxinSequenceChanged { proposed: Sequence, original: Sequence },
    SenderTxinContainsNonWitnessUtxo,
    SenderTxinContainsWitnessUtxo,
    SenderTxinContainsFinalScriptSig,
    SenderTxinContainsFinalScriptWitness,
    TxInContainsKeyPaths,
    ContainsPartialSigs,
    ReceiverTxinNotFinalized,
    ReceiverTxinMissingUtxoInfo,
    MixedSequence,
    MixedInputTypes { proposed: InputType, original: InputType },
    MissingOrShuffledInputs,
    TxOutContainsKeyPaths,
    FeeContributionExceedsMaximum,
    DisallowedOutputSubstitution,
    OutputValueDecreased,
    MissingOrShuffledOutputs,
    Inflation,
    AbsoluteFeeDecreased,
    PayeeTookContributedFee,
    FeeContributionPaysOutputSizeIncrease,
    FeeRateBelowMinimum,
}

impl From<InternalValidationError> for ValidationError {
    fn from(value: InternalValidationError) -> Self { ValidationError { internal: value } }
}
impl From<InputTypeError> for InternalValidationError {
    fn from(value: InputTypeError) -> Self { InternalValidationError::InvalidInputType(value) }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalValidationError::*;

        match &self.internal {
            Psbt(e) => write!(f, "couldn't decode PSBT: {}", e),
            Io(e) => write!(f, "couldn't read PSBT: {}", e),
            InvalidInputType(e) => write!(f, "invalid transaction input type: {}", e),
            InvalidProposedInput(e) => write!(f, "invalid proposed transaction input: {}", e),
            VersionsDontMatch { proposed, original, } => write!(f, "proposed transaction version {} doesn't match the original {}", proposed, original),
            LockTimesDontMatch { proposed, original, } => write!(f, "proposed transaction lock time {} doesn't match the original {}", proposed, original),
            SenderTxinSequenceChanged { proposed, original, } => write!(f, "proposed transaction sequence number {} doesn't match the original {}", proposed, original),
            SenderTxinContainsNonWitnessUtxo => write!(f, "an input in proposed transaction belonging to the sender contains non-witness UTXO information"),
            SenderTxinContainsWitnessUtxo => write!(f, "an input in proposed transaction belonging to the sender contains witness UTXO information"),
            SenderTxinContainsFinalScriptSig => write!(f, "an input in proposed transaction belonging to the sender contains finalized non-witness signature"),
            SenderTxinContainsFinalScriptWitness => write!(f, "an input in proposed transaction belonging to the sender contains finalized witness signature"),
            TxInContainsKeyPaths => write!(f, "proposed transaction inputs contain key paths"),
            ContainsPartialSigs => write!(f, "an input in proposed transaction belonging to the sender contains partial signatures"),
            ReceiverTxinNotFinalized => write!(f, "an input in proposed transaction belonging to the receiver is not finalized"),
            ReceiverTxinMissingUtxoInfo => write!(f, "an input in proposed transaction belonging to the receiver is missing UTXO information"),
            MixedSequence => write!(f, "inputs of proposed transaction contain mixed sequence numbers"),
            MixedInputTypes { proposed, original, } => write!(f, "proposed transaction contains input of type {:?} while original contains inputs of type {:?}", proposed, original),
            MissingOrShuffledInputs => write!(f, "proposed transaction is missing inputs of the sender or they are shuffled"),
            TxOutContainsKeyPaths => write!(f, "proposed transaction outputs contain key paths"),
            FeeContributionExceedsMaximum => write!(f, "fee contribution exceeds allowed maximum"),
            DisallowedOutputSubstitution => write!(f, "the receiver change output despite it being disallowed"),
            OutputValueDecreased => write!(f, "the amount in our non-fee output was decreased"),
            MissingOrShuffledOutputs => write!(f, "proposed transaction is missing outputs of the sender or they are shuffled"),
            Inflation => write!(f, "proposed transaction is attempting inflation"),
            AbsoluteFeeDecreased => write!(f, "abslute fee of proposed transaction is lower than original"),
            PayeeTookContributedFee => write!(f, "payee tried to take fee contribution for himself"),
            FeeContributionPaysOutputSizeIncrease => write!(f, "fee contribution pays for additional outputs"),
            FeeRateBelowMinimum =>  write!(f, "the fee rate of proposed transaction is below minimum"),
        }
    }
}

impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalValidationError::*;

        match &self.internal {
            Psbt(error) => Some(error),
            Io(error) => Some(error),
            InvalidInputType(error) => Some(error),
            InvalidProposedInput(error) => Some(error),
            VersionsDontMatch { proposed: _, original: _ } => None,
            LockTimesDontMatch { proposed: _, original: _ } => None,
            SenderTxinSequenceChanged { proposed: _, original: _ } => None,
            SenderTxinContainsNonWitnessUtxo => None,
            SenderTxinContainsWitnessUtxo => None,
            SenderTxinContainsFinalScriptSig => None,
            SenderTxinContainsFinalScriptWitness => None,
            TxInContainsKeyPaths => None,
            ContainsPartialSigs => None,
            ReceiverTxinNotFinalized => None,
            ReceiverTxinMissingUtxoInfo => None,
            MixedSequence => None,
            MixedInputTypes { .. } => None,
            MissingOrShuffledInputs => None,
            TxOutContainsKeyPaths => None,
            FeeContributionExceedsMaximum => None,
            DisallowedOutputSubstitution => None,
            OutputValueDecreased => None,
            MissingOrShuffledOutputs => None,
            Inflation => None,
            AbsoluteFeeDecreased => None,
            PayeeTookContributedFee => None,
            FeeContributionPaysOutputSizeIncrease => None,
            FeeRateBelowMinimum => None,
        }
    }
}

#[derive(Debug)]
pub struct ConfigurationError(InternalConfigurationError);

#[derive(Debug)]
pub(crate) enum InternalConfigurationError {
    PrevTxOut(crate::psbt::PrevTxOutError),
    InputType(crate::input_type::InputTypeError),
    NoInputs,
}

impl From<InternalConfigurationError> for ConfigurationError {
    fn from(value: InternalConfigurationError) -> Self { ConfigurationError(value) }
}

impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalConfigurationError::*;

        match &self.0 {
            PrevTxOut(e) => write!(f, "invalid previous transaction output: {}", e),
            InputType(e) => write!(f, "invalid input type: {}", e),
            NoInputs => write!(f, "no inputs"),
        }
    }
}

impl std::error::Error for ConfigurationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalConfigurationError::*;

        match &self.0 {
            PrevTxOut(error) => Some(error),
            InputType(error) => Some(error),
            NoInputs => None,
        }
    }
}

/// Error returned when request could not be created.
///
/// This error can currently only happen due to programmer mistake.
/// `unwrap()`ing it is thus considered OK in Rust but you may achieve nicer message by displaying
/// it.
#[derive(Debug)]
pub struct CreateRequestError(InternalCreateRequestError);

#[derive(Debug)]
pub(crate) enum InternalCreateRequestError {
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
    Url(url::ParseError),
    UriDoesNotSupportPayjoin,
}

impl fmt::Display for CreateRequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalCreateRequestError::*;

        match &self.0 {
            InvalidOriginalInput(e) => write!(f, "an input in the original transaction is invalid: {:#?}", e),
            InconsistentOriginalPsbt(e) => write!(f, "the original transaction is inconsistent: {:#?}", e),
            NoInputs => write!(f, "the original transaction has no inputs"),
            PayeeValueNotEqual => write!(f, "the value in original transaction doesn't equal value requested in the payment link"),
            NoOutputs => write!(f, "the original transaction has no outputs"),
            MultiplePayeeOutputs => write!(f, "the original transaction has more than one output belonging to the payee"),
            MissingPayeeOutput => write!(f, "the output belonging to payee is missing from the original transaction"),
            FeeOutputValueLowerThanFeeContribution => write!(f, "the value of fee output is lower than maximum allowed contribution"),
            AmbiguousChangeOutput => write!(f, "can not determine which output is change because there's more than two outputs"),
            ChangeIndexOutOfBounds => write!(f, "fee output index is points out of bounds"),
            ChangeIndexPointsAtPayee => write!(f, "fee output index is points at output belonging to the payee"),
            Url(e) => write!(f, "cannot parse endpoint url: {:#?}", e),
            UriDoesNotSupportPayjoin => write!(f, "the URI does not support payjoin"),
        }
    }
}

impl std::error::Error for CreateRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalCreateRequestError::*;

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
            Url(error) => Some(error),
            UriDoesNotSupportPayjoin => None,
        }
    }
}

impl From<InternalCreateRequestError> for CreateRequestError {
    fn from(value: InternalCreateRequestError) -> Self { CreateRequestError(value) }
}

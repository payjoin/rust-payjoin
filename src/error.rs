#[derive(Debug)]
pub struct ValidationError {
    internal: InternalValidationError,
}

impl From<InternalValidationError> for ValidationError {
    fn from(value: InternalValidationError) -> Self {
        ValidationError { internal: value }
    }
}
impl From<InputTypeError> for InternalValidationError {
    fn from(value: InputTypeError) -> Self {
        InternalValidationError::InvalidInputType(value)
    }
}
#[derive(Debug)]
pub(crate) enum InternalValidationError {
    Psbt(bitcoin::psbt::PsbtParseError),
    Io(std::io::Error),
    InvalidInput,
    Type(InputTypeError),
    InvalidProposedInput(crate::psbt::PrevTxOutError),
    VersionsDontMatch {
        proposed: i32,
        original: i32,
    },
    LockTimesDontMatch {
        proposed: LockTime,
        original: LockTime,
    },
    SenderTxinSequenceChanged {
        proposed: Sequence,
        original: Sequence,
    },
    SenderTxinContainsNonWitnessUtxo,
    SenderTxinContainsWitnessUtxo,
    SenderTxinContainsFinalScriptSig,
    SenderTxinContainsFinalScriptWitness,
    TxInContainsKeyPaths,
    ContainsPartialSigs,
    ReceiverTxinNotFinalized,
    ReceiverTxinMissingUtxoInfo,
    MixedSequence,
    MixedInputTypes {
        proposed: InputType,
        original: InputType,
    },
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

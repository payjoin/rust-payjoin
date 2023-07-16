use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Psbt(String),
    Io(String),
    InvalidInput,
    Type(String),
    InvalidProposedInput(String),
    VersionsDontMatch {
        proposed: i32,
        original: i32,
    },
    LockTimesDontMatch {
        proposed: usize,
        original: usize,
    },
    SenderTxinSequenceChanged {
        proposed: usize,
        original: usize,
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
        proposed: String,
        original: String,
    },
    MissingOrShuffledInputs,
    TxOutContainsKeyPaths,
    FeeContributionExceedsMaximum,
    DisallowedOutputSubstitution,
    OutputValueDecreased,
    MissingOrShuffledOutputs,
    AbsoluteFeeDecreased,
    PayeeTookContributedFee,
    FeeRateBelowMinimum,
    ReceiveError(String),
    PjParseError(String),
    ///Error that may occur when the request from sender is malformed.
    ///This is currently opaque type because we aren’t sure which variants will stay. You can only display it.
    RequestError(String),
    ///Error that may occur when coin selection fails.
    SelectionError(String),
    ///Error returned when request could not be created.
    ///This error can currently only happen due to programmer mistake.
    CreateRequestError(String),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Psbt(e) => write!(f, "Psbt error:{}", e),
            Error::Io(e) => write!(f, "Io error:{}", e),
            Error::InvalidInput => write!(f, "Invalid input"),
            Error::Type(e) => write!(f, "Type error:{}", e),
            Error::InvalidProposedInput(e) => write!(f, "Invalid proposed input:{}", e),
            Error::VersionsDontMatch { proposed, original } =>
                write!(f, "Version mismatch: proposed: {proposed}, original: {original} "),
            Error::LockTimesDontMatch { proposed, original } =>
                write!(f, "LockTimes mismatch: proposed: {proposed}, original: {original} "),
            Error::SenderTxinSequenceChanged { proposed, original } =>
                write!(
                    f,
                    "SenderTxinSequence changed: proposed: {proposed}, original: {original} "
                ),
            Error::SenderTxinContainsNonWitnessUtxo =>
                write!(f, "Sender txin contains non-witness utxo"),
            Error::SenderTxinContainsWitnessUtxo => write!(f, "Sender txin contains witness utxo"),
            Error::SenderTxinContainsFinalScriptSig =>
                write!(f, "Sender txin contains final script sig"),
            Error::SenderTxinContainsFinalScriptWitness =>
                write!(f, "Sender txin contains final script witness"),
            Error::TxInContainsKeyPaths => write!(f, "Txin contains keyP paths"),
            Error::ContainsPartialSigs => write!(f, "Contains partial sigs"),
            Error::ReceiverTxinNotFinalized => write!(f, "Receiver txin not finalized"),
            Error::ReceiverTxinMissingUtxoInfo => write!(f, "Receiver txin missing utxo info"),
            Error::MixedSequence => write!(f, "Missed sequence"),
            Error::MixedInputTypes { proposed, original } =>
                write!(f, "Mixed input types: proposed: {proposed}, original: {original} "),
            Error::MissingOrShuffledInputs => write!(f, "Missing or shuffled inputs"),
            Error::TxOutContainsKeyPaths => write!(f, "Tx out contains key paths"),
            Error::FeeContributionExceedsMaximum => write!(f, "Fee contribution exceeds maximum"),
            Error::DisallowedOutputSubstitution => write!(f, "Output substited is not allowed"),
            Error::OutputValueDecreased => write!(f, "Output value decreased"),
            Error::MissingOrShuffledOutputs => write!(f, "Missing or shuffled outputs"),
            Error::AbsoluteFeeDecreased => write!(f, "Absolute fee decreased"),
            Error::PayeeTookContributedFee => write!(f, "The payee took the contribution fees"),
            Error::FeeRateBelowMinimum => write!(f, "Fee rate is below minimum"),
            Error::ReceiveError(e) => write!(f, "ReceiveError: {}", e),
            Error::RequestError(e) => write!(f, "RequestError: {}", e),
            Error::SelectionError(e) => write!(f, "SelectionError: {}", e),
            Error::CreateRequestError(e) => write!(f, "CreateRequestError: {}", e),
            Error::PjParseError(e) => write!(f, "PjParseError: {}", e),
        }
    }
}
impl std::error::Error for Error {}

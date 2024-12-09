use core::fmt;
use std::error;

#[derive(Debug)]
pub struct MultipartyError(InternalMultipartyError);

#[derive(Debug)]
pub(crate) enum InternalMultipartyError {
    /// Not enough proposals
    NotEnoughProposals,
    /// Proposal version not supported
    ProposalVersionNotSupported(usize),
    /// Optimistic merge not supported
    OptimisticMergeNotSupported,
    /// Bitcoin Internal Error
    BitcoinExtractTxError(Box<bitcoin::psbt::ExtractTxError>),
    /// Input in Finalized Proposal is missing witness or script_sig
    InputMissingWitnessOrScriptSig,
    /// Failed to combine psbts
    FailedToCombinePsbts(bitcoin::psbt::Error),
}

impl From<InternalMultipartyError> for MultipartyError {
    fn from(e: InternalMultipartyError) -> Self { MultipartyError(e) }
}

impl fmt::Display for MultipartyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            InternalMultipartyError::NotEnoughProposals => write!(f, "Not enough proposals"),
            InternalMultipartyError::ProposalVersionNotSupported(v) =>
                write!(f, "Proposal version not supported: {}", v),
            InternalMultipartyError::OptimisticMergeNotSupported =>
                write!(f, "Optimistic merge not supported"),
            InternalMultipartyError::BitcoinExtractTxError(e) =>
                write!(f, "Bitcoin extract tx error: {:?}", e),
            InternalMultipartyError::InputMissingWitnessOrScriptSig =>
                write!(f, "Input in Finalized Proposal is missing witness or script_sig"),
            InternalMultipartyError::FailedToCombinePsbts(e) =>
                write!(f, "Failed to combine psbts: {:?}", e),
        }
    }
}

impl error::Error for MultipartyError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.0 {
            InternalMultipartyError::NotEnoughProposals => None,
            InternalMultipartyError::ProposalVersionNotSupported(_) => None,
            InternalMultipartyError::OptimisticMergeNotSupported => None,
            InternalMultipartyError::BitcoinExtractTxError(e) => Some(e),
            InternalMultipartyError::InputMissingWitnessOrScriptSig => None,
            InternalMultipartyError::FailedToCombinePsbts(e) => Some(e),
        }
    }
}

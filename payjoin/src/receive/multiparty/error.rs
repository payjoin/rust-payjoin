use core::fmt;
use std::error;

use crate::uri::ShortId;

#[derive(Debug)]
pub struct MultipartyError(InternalMultipartyError);

#[derive(Debug)]
pub(crate) enum InternalMultipartyError {
    /// Not enough proposals
    NotEnoughProposals,
    /// Duplicate proposals
    IdenticalProposals(IdenticalProposalError),
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

#[derive(Debug)]
pub enum IdenticalProposalError {
    IdenticalPsbts(Box<bitcoin::Psbt>, Box<bitcoin::Psbt>),
    IdenticalContexts(Box<ShortId>, Box<ShortId>),
}

impl std::fmt::Display for IdenticalProposalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdenticalProposalError::IdenticalPsbts(current_psbt, incoming_psbt) => write!(
                f,
                "Two sender psbts are identical\n left psbt: {current_psbt}\n right psbt: {incoming_psbt}"
            ),
            IdenticalProposalError::IdenticalContexts(current_context, incoming_context) => write!(
                f,
                "Two sender contexts are identical\n left id: {current_context}\n right id: {incoming_context}"
            ),
        }
    }
}

impl From<InternalMultipartyError> for MultipartyError {
    fn from(e: InternalMultipartyError) -> Self { MultipartyError(e) }
}

impl fmt::Display for MultipartyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            InternalMultipartyError::NotEnoughProposals => write!(f, "Not enough proposals"),
            InternalMultipartyError::IdenticalProposals(e) =>
                write!(f, "More than one identical participant: {e}"),
            InternalMultipartyError::ProposalVersionNotSupported(v) =>
                write!(f, "Proposal version not supported: {v}"),
            InternalMultipartyError::OptimisticMergeNotSupported =>
                write!(f, "Optimistic merge not supported"),
            InternalMultipartyError::BitcoinExtractTxError(e) =>
                write!(f, "Bitcoin extract tx error: {e:?}"),
            InternalMultipartyError::InputMissingWitnessOrScriptSig =>
                write!(f, "Input in Finalized Proposal is missing witness or script_sig"),
            InternalMultipartyError::FailedToCombinePsbts(e) =>
                write!(f, "Failed to combine psbts: {e:?}"),
        }
    }
}

impl error::Error for MultipartyError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.0 {
            InternalMultipartyError::NotEnoughProposals => None,
            InternalMultipartyError::IdenticalProposals(_) => None,
            InternalMultipartyError::ProposalVersionNotSupported(_) => None,
            InternalMultipartyError::OptimisticMergeNotSupported => None,
            InternalMultipartyError::BitcoinExtractTxError(e) => Some(e),
            InternalMultipartyError::InputMissingWitnessOrScriptSig => None,
            InternalMultipartyError::FailedToCombinePsbts(e) => Some(e),
        }
    }
}

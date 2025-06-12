use std::fmt::{self, Display};

use bitcoin::psbt::Error as PsbtError;

use crate::hpke::HpkeError;
use crate::ohttp::DirectoryResponseError;
use crate::send::InternalProposalError;
use crate::uri::url_ext::ParseReceiverPubkeyParamError;
use crate::ImplementationError;

#[derive(Debug)]
pub struct CreateRequestError(InternalCreateRequestError);

#[derive(Debug)]
pub(crate) enum InternalCreateRequestError {
    #[allow(dead_code)]
    Expired(std::time::SystemTime),
    MissingOhttpConfig,
    ParseReceiverPubkeyParam(ParseReceiverPubkeyParamError),
    V2CreateRequest(crate::send::v2::CreateRequestError),
}

impl From<InternalCreateRequestError> for CreateRequestError {
    fn from(value: InternalCreateRequestError) -> Self { CreateRequestError(value) }
}

impl Display for CreateRequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{:?}", self.0) }
}

impl std::error::Error for CreateRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            InternalCreateRequestError::Expired(_) => None,
            InternalCreateRequestError::MissingOhttpConfig => None,
            InternalCreateRequestError::ParseReceiverPubkeyParam(e) => Some(e),
            InternalCreateRequestError::V2CreateRequest(e) => Some(e),
        }
    }
}

#[derive(Debug)]
pub struct FinalizedError(InternalFinalizedError);

#[derive(Debug)]
pub(crate) enum InternalFinalizedError {
    Hpke(HpkeError),
    #[allow(dead_code)]
    FinalizePsbt(ImplementationError),
    MissingResponse,
    Psbt(PsbtError),
    DirectoryResponse(DirectoryResponseError),
    Proposal(InternalProposalError),
}

impl From<InternalFinalizedError> for FinalizedError {
    fn from(value: InternalFinalizedError) -> Self { FinalizedError(value) }
}

impl From<DirectoryResponseError> for FinalizedError {
    fn from(err: DirectoryResponseError) -> Self {
        FinalizedError(InternalFinalizedError::DirectoryResponse(err))
    }
}

impl Display for FinalizedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{:?}", self.0) }
}

impl std::error::Error for FinalizedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            InternalFinalizedError::Hpke(e) => Some(e),
            InternalFinalizedError::FinalizePsbt(_) => None,
            InternalFinalizedError::MissingResponse => None,
            InternalFinalizedError::Psbt(e) => Some(e),
            InternalFinalizedError::Proposal(e) => Some(e),
            InternalFinalizedError::DirectoryResponse(e) => Some(e),
        }
    }
}

#[derive(Debug)]
pub struct FinalizeResponseError(InternalFinalizeResponseError);

#[derive(Debug)]
pub(crate) enum InternalFinalizeResponseError {
    DirectoryResponse(DirectoryResponseError),
}

impl From<InternalFinalizeResponseError> for FinalizeResponseError {
    fn from(value: InternalFinalizeResponseError) -> Self { FinalizeResponseError(value) }
}

impl From<DirectoryResponseError> for FinalizeResponseError {
    fn from(err: DirectoryResponseError) -> Self {
        FinalizeResponseError(InternalFinalizeResponseError::DirectoryResponse(err))
    }
}

impl Display for FinalizeResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{:?}", self.0) }
}

impl std::error::Error for FinalizeResponseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            InternalFinalizeResponseError::DirectoryResponse(e) => Some(e),
        }
    }
}

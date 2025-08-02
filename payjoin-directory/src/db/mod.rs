use std::future::Future;
use std::result::Result;

use payjoin::directory::ShortId;

pub(crate) mod mem;
pub(crate) mod redis;

pub trait SendableError:
    std::error::Error + std::marker::Send + std::marker::Sync + std::convert::Into<anyhow::Error>
{
}

#[derive(Debug)]
pub enum Error<OperationalError: SendableError> {
    Operational(OperationalError),
    Timeout(tokio::time::error::Elapsed),
}

impl SendableError for tokio::time::error::Elapsed {}

impl<E: SendableError> From<E> for Error<E> {
    fn from(value: E) -> Self { Error::Operational(value) }
}

impl<E: SendableError> std::fmt::Display for Error<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;

        match &self {
            Operational(error) => write!(f, "Db error: {error}"),
            Timeout(timeout) => write!(f, "Timeout: {timeout}"),
        }
    }
}

impl<E: SendableError + 'static> std::error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Operational(e) => Some(e),
            Error::Timeout(e) => Some(e),
        }
    }
}

// TODO split into v1 and v2 traits
pub trait Db: Clone + Send + Sync + 'static {
    type OperationalError: SendableError + 'static;

    /// Store a v2 payload.
    fn post_v2_payload(
        &self,
        mailbox_id: &ShortId,
        data: Vec<u8>,
    ) -> impl Future<Output = Result<(), Error<Self::OperationalError>>> + Send;

    /// Read a stored v1 request or v2 payload, waiting if not yet posted.
    fn wait_for_v2_payload(
        &self,
        mailbox_id: &ShortId,
    ) -> impl Future<Output = Result<Vec<u8>, Error<Self::OperationalError>>> + Send;

    /// Write a v1 response payload.
    fn post_v1_response(
        &self,
        mailbox_id: &ShortId,
        data: Vec<u8>,
    ) -> impl Future<Output = Result<(), Error<Self::OperationalError>>> + Send;

    /// Store a v1 request payload, waiting for any response.
    fn post_v1_request_and_wait_for_response(
        &self,
        mailbox_id: &ShortId,
        data: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, Error<Self::OperationalError>>> + Send;
}
